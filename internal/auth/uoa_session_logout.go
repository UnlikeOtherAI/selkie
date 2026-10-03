package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

func (m *SessionManager) logout(ctx context.Context, id, userID string) error {
	// Persist closing before contacting UOA; requests cannot resurrect the session.
	tx, err := m.db.Pool.Begin(ctx)
	if err != nil {
		return errSessionUnavailable
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort after commit
	var sealed []byte
	var kind string
	if err = tx.QueryRow(ctx, `SELECT sealed_capability,capability_kind FROM uoa_sessions WHERE id::text=$1 AND user_id::text=$2 FOR UPDATE`, id, userID).Scan(&sealed, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return errSessionUnavailable
	}
	refresh, err := m.open(sealed)
	if err != nil {
		return errSessionUnavailable
	}
	if _, err = tx.Exec(ctx, `UPDATE uoa_sessions SET closing=true,cleanup_after=now() WHERE id::text=$1`, id); err != nil {
		return errSessionUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return errSessionUnavailable
	}
	if kind == capabilityRefresh {
		if err = uoaRequest(ctx, m.cfg, http.MethodPost, "/auth/revoke", map[string]string{fieldRefreshToken: refresh, fieldScope: revokeScopeFamily}, nil); err != nil {
			return errSessionUnavailable
		}
	}
	_, err = m.db.Pool.Exec(ctx, `DELETE FROM uoa_sessions WHERE id::text=$1 AND user_id::text=$2 AND closing`, id, userID)
	return err
}

func (h *CallbackHandler) sessionAuth(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	claims, reason := authenticateBearer(r.Header.Get("Authorization"), []byte(h.cfg.InternalSessionSecret))
	if reason != "" || claims.SessionID == "" {
		writeUnauthorized(w)
		return claims, false
	}
	return claims, true
}

func (h *CallbackHandler) ServeSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claims, ok := h.sessionAuth(w, r)
	if !ok {
		return
	}
	profile, isSuper, err := h.sessions.resolve(r.Context(), claims.SessionID, claims.Sub)
	if errors.Is(err, errSessionClosing) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{fieldError: "logout confirmation pending", "logout_pending": true})
		return
	}
	if errors.Is(err, errSessionExpired) {
		writeUnauthorized(w)
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{fieldSubject: claims.Sub, "session_id": claims.SessionID, fieldEmail: profile.Email, "display_name": profile.DisplayName, "picture": profile.Picture, "is_super": isSuper})
}

func (h *CallbackHandler) ServeLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.allowRateLimit(r.Context(), w, ratelimit.Key("auth", "logout", "ip", audit.RateLimitIP(audit.ClientIP(r, h.cfg.TrustedProxyCIDRs))), 20) {
		return
	}
	claims, ok := h.sessionAuth(w, r)
	if !ok {
		return
	}
	if err := h.sessions.logout(r.Context(), claims.SessionID, claims.Sub); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "logout temporarily unavailable; retry")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
