package auth

import (
	"context"
	"errors"
	"time"
)

// createDevelopment is confined to explicitly enabled, unbound local installs.
func (m *SessionManager) createDevelopment(ctx context.Context, userID string) (string, error) {
	if !m.cfg.DevMode || m.cfg.UOAConfigURL != "" {
		return "", errors.New("development login disabled")
	}
	sealed, err := m.seal("development-only")
	if err != nil {
		return "", err
	}
	var id string
	err = m.db.Pool.QueryRow(ctx, `INSERT INTO uoa_sessions (user_id,subject,sealed_capability,capability_kind,expires_at) VALUES ($1,$2,$3,'development',$4) RETURNING id`, userID, DevUserExternalID, sealed, time.Now().Add(sessionTokenTTL)).Scan(&id)
	return id, err
}
