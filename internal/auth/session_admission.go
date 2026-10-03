package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

func (m *SessionManager) stage(ctx context.Context, claims *UOAClaims) (string, error) {
	if m.db == nil || m.db.Pool == nil {
		return "", errSessionUnavailable
	}
	if claims.RefreshToken == "" || claims.RefreshExpiresIn <= 0 {
		return "", errors.New("missing UOA refresh capability")
	}
	sealed, err := m.seal(claims.RefreshToken)
	if err != nil {
		return "", err
	}
	var id string
	err = m.db.Pool.QueryRow(ctx, `INSERT INTO uoa_sessions(subject,organization_id,team_id,sealed_capability,expires_at,closing,cleanup_after) VALUES($1,NULLIF($2,''),NULLIF($3,''),$4,$5,true,now()+interval '30 seconds') RETURNING id`, claims.Subject, claims.ActiveOrgID, claims.ActiveTeamID, sealed, time.Now().Add(time.Duration(claims.RefreshExpiresIn)*time.Second)).Scan(&id)
	return id, err
}

// admitFreshFamily persists cleanup authority before profile or local admission.
func (h *CallbackHandler) admitFreshFamily(ctx context.Context, claims *UOAClaims) (string, bool, string, error) {
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	id, err := h.sessions.stage(persist, claims)
	cancel()
	if err != nil {
		h.discardFamily(ctx, claims.RefreshToken)
		return "", false, "", errSessionUnavailable
	}
	admission, cancelAdmission := context.WithTimeout(ctx, 20*time.Second)
	defer cancelAdmission()
	ctx = admission
	admitted := false
	defer func(cleanupContext context.Context) {
		if !admitted {
			h.cleanupStaged(cleanupContext, id)
		}
	}(ctx)
	profile, err := currentUOAProfile(ctx, h.cfg, claims.Subject)
	if err != nil {
		return "", false, "", errSessionUnavailable
	}
	claims.Email = profile.Email
	claims.DisplayName = profile.DisplayName
	claims.Picture = profile.Picture
	userID, isSuper, err := h.upsertUserFn(ctx, claims)
	if err != nil {
		return "", false, "", errSessionUnavailable
	}
	result, err := h.db.Pool.Exec(ctx, `UPDATE uoa_sessions s SET user_id=$2::uuid,closing=false WHERE s.id::text=$1 AND s.user_id IS NULL AND s.closing AND s.subject=$3 AND s.expires_at>now() AND EXISTS(SELECT 1 FROM users u WHERE u.id=$2::uuid AND u.external_id=$3 AND u.status='active')`, id, userID, claims.Subject)
	if err != nil || result.RowsAffected() != 1 {
		return "", false, "", errSessionUnavailable
	}
	admitted = true
	return userID, isSuper, id, nil
}

func (h *CallbackHandler) cleanupStaged(ctx context.Context, id string) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
	defer cancel()
	if _, err := h.db.Pool.Exec(cleanup, `UPDATE uoa_sessions SET cleanup_after=now() WHERE id::text=$1 AND closing`, id); err != nil {
		return
	}
	if err := h.sessions.cleanupOne(cleanup, id); err != nil && h.logger != nil {
		h.logger.Warn("session cleanup retained for retry")
	}
}

// cleanupOne holds the row lock so only one process revokes a staged family.
func (m *SessionManager) cleanupOne(ctx context.Context, id string) error {
	tx, err := m.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort after commit
	var sealed []byte
	var kind string
	if err = tx.QueryRow(ctx, `SELECT sealed_capability,capability_kind FROM uoa_sessions WHERE id::text=$1 AND closing AND cleanup_after<=now() FOR UPDATE`, id).Scan(&sealed, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	capability, err := m.open(sealed)
	if err != nil {
		return err
	}
	if kind == capabilityRefresh {
		if err = uoaRequest(ctx, m.cfg, http.MethodPost, "/auth/revoke", map[string]string{fieldRefreshToken: capability, fieldScope: revokeScopeFamily}, nil); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM uoa_sessions WHERE id::text=$1 AND closing`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
