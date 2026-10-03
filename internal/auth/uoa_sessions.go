package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/store"
)

var (
	errSessionUnavailable = errors.New("session temporarily unavailable")
	errSessionExpired     = errors.New("session expired")
	errSessionClosing     = errors.New("logout confirmation pending")
)

// SessionManager owns scoped UOA capabilities; profiles never enter its database.
type SessionManager struct {
	cache sessionCache
	db    *store.DB
	cfg   config.Config
}

func NewSessionManager(db *store.DB, cfg config.Config) *SessionManager {
	return &SessionManager{db: db, cfg: cfg, cache: sessionCache{entries: map[string]sessionCacheEntry{}, flights: map[string]chan struct{}{}}}
}

func (m *SessionManager) seal(refresh string) ([]byte, error) {
	key := sha256.Sum256([]byte("selkie-uoa-refresh-v1:" + m.cfg.InternalSessionSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(refresh), []byte(m.cfg.UOAConfigURL)), nil
}

func (m *SessionManager) open(sealed []byte) (string, error) {
	key := sha256.Sum256([]byte("selkie-uoa-refresh-v1:" + m.cfg.InternalSessionSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", errSessionExpired
	}
	raw, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(m.cfg.UOAConfigURL))
	return string(raw), err
}

func (m *SessionManager) create(ctx context.Context, userID string, claims *UOAClaims) (string, error) {
	if claims.RefreshToken == "" || claims.RefreshExpiresIn <= 0 {
		return "", errors.New("UOA returned no scoped refresh capability")
	}
	sealed, err := m.seal(claims.RefreshToken)
	if err != nil {
		return "", err
	}
	var id string
	err = m.db.Pool.QueryRow(ctx, `INSERT INTO uoa_sessions (user_id,subject,organization_id,team_id,sealed_capability,expires_at) VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6) RETURNING id`, userID, claims.Subject, claims.ActiveOrgID, claims.ActiveTeamID, sealed, time.Now().Add(time.Duration(claims.RefreshExpiresIn)*time.Second)).Scan(&id)
	return id, err
}

// resolve serializes rotating credentials across processes. Profile reads follow commit.
func (m *SessionManager) resolve(ctx context.Context, id, userID string) (*UOAClaims, bool, error) {
	release, err := m.cache.acquire(ctx, id)
	if err != nil {
		return nil, false, err
	}
	defer release()
	return m.resolveLocked(ctx, id, userID)
}

func (m *SessionManager) resolveLocked(ctx context.Context, id, userID string) (*UOAClaims, bool, error) {
	if id == "" || m.db == nil {
		return nil, false, errSessionExpired
	}
	tx, err := m.db.Pool.Begin(ctx)
	if err != nil {
		return nil, false, errSessionUnavailable
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort after commit
	var sealed []byte
	var subject, kind string
	var closing, isSuper bool
	err = tx.QueryRow(ctx, `SELECT s.sealed_capability,s.subject,s.capability_kind,s.closing,u.is_super FROM uoa_sessions s JOIN users u ON u.id=s.user_id WHERE s.id::text=$1 AND s.user_id::text=$2 AND s.expires_at>now() AND u.status='active' FOR UPDATE OF s`, id, userID).Scan(&sealed, &subject, &kind, &closing, &isSuper)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errSessionExpired
	}
	if err != nil {
		return nil, false, errSessionUnavailable
	}
	if closing {
		return nil, false, errSessionClosing
	}
	if kind == capabilityRefresh {
		if cached, ok := m.cache.get(id, capabilityFingerprint(sealed)); ok {
			return cached, isSuper, nil
		}
	}
	var claims *UOAClaims
	switch kind {
	case "development":
		claims, err = m.resolveDevelopment(ctx, tx, subject)
	case "broker":
		claims, err = m.resolveBroker(ctx, tx, sealed, subject)
	case capabilityRefresh:
		claims, err = m.rotate(ctx, tx, id, sealed, subject)
	default:
		return nil, false, errSessionExpired
	}
	if err != nil {
		return nil, false, err
	}
	profile, err := m.profileForSession(ctx, id, claims)
	if err == nil && kind == capabilityRefresh {
		m.cache.put(id, profile)
	}
	return profile, isSuper, err
}

func (m *SessionManager) resolveDevelopment(ctx context.Context, tx pgx.Tx, subject string) (*UOAClaims, error) {
	if !m.cfg.DevMode || m.cfg.UOAConfigURL != "" {
		return nil, errSessionExpired
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errSessionUnavailable
	}
	claims := &UOAClaims{Email: DevUserEmail, DisplayName: DevUserDisplayName, Picture: DevUserPicture}
	claims.Subject = subject
	return claims, nil
}

func (m *SessionManager) resolveBroker(ctx context.Context, tx pgx.Tx, sealed []byte, subject string) (*UOAClaims, error) {
	capability, err := m.open(sealed)
	if err != nil {
		return nil, errSessionUnavailable
	}
	validation, err := validateBrokerCapability(ctx, m.cfg, capability)
	if err != nil || validation.Sub != subject {
		return nil, errSessionUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, errSessionUnavailable
	}
	claims := &UOAClaims{ActiveOrgID: validation.Active.OrgID, ActiveTeamID: validation.Active.TeamID}
	claims.Subject = subject
	return claims, nil
}

func (m *SessionManager) rotate(ctx context.Context, tx pgx.Tx, id string, sealed []byte, subject string) (*UOAClaims, error) {
	refresh, err := m.open(sealed)
	if err != nil {
		return nil, errSessionUnavailable
	}
	tokens, err := exchangeUOATokens(ctx, m.cfg, map[string]string{fieldRefreshToken: refresh, "grant_type": fieldRefreshToken})
	if err != nil {
		return nil, errSessionUnavailable
	}
	claims, err := decodeUOAToken(tokens.AccessToken)
	if err != nil || claims.Subject != subject || tokens.RefreshToken == "" || tokens.RefreshTokenExpiresIn <= 0 {
		return nil, errSessionUnavailable
	}
	sealed, err = m.seal(tokens.RefreshToken)
	if err != nil {
		return nil, errSessionUnavailable
	}
	if _, err = tx.Exec(ctx, `UPDATE uoa_sessions SET sealed_capability=$2,organization_id=NULLIF($3,''),team_id=NULLIF($4,''),expires_at=$5 WHERE id::text=$1`, id, sealed, claims.ActiveOrgID, claims.ActiveTeamID, time.Now().Add(time.Duration(tokens.RefreshTokenExpiresIn)*time.Second)); err != nil {
		return nil, errSessionUnavailable
	}
	claims.CapabilityFingerprint = capabilityFingerprint(sealed)
	if err = tx.Commit(ctx); err != nil {
		return nil, errSessionUnavailable
	}
	return claims, nil
}

func (m *SessionManager) profileForSession(ctx context.Context, id string, claims *UOAClaims) (*UOAClaims, error) {
	if !m.cfg.DevMode || m.cfg.UOAConfigURL != "" {
		profile, err := currentUOAProfile(ctx, m.cfg, claims.Subject)
		if err != nil {
			return nil, errSessionUnavailable
		}
		claims.Email = profile.Email
		claims.DisplayName = profile.DisplayName
		claims.Picture = profile.Picture
	}
	var sealed []byte
	if err := m.db.Pool.QueryRow(ctx, `SELECT sealed_capability FROM uoa_sessions WHERE id::text=$1 AND NOT closing AND expires_at>now()`, id).Scan(&sealed); err != nil {
		return nil, errSessionUnavailable
	}
	if claims.CapabilityFingerprint != "" && claims.CapabilityFingerprint != capabilityFingerprint(sealed) {
		return nil, errSessionUnavailable
	}
	return claims, nil
}
