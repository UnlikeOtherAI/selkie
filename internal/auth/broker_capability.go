package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/unlikeotherai/selkie/internal/config"
)

type brokerValidation struct {
	Sub       string    `json:"sub"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    struct {
		OrgID  string `json:"orgId"`  //nolint:tagliatelle // Exact UOA contract.
		TeamID string `json:"teamId"` //nolint:tagliatelle // Exact UOA contract.
	} `json:"active"`
}

func validateBrokerCapability(ctx context.Context, cfg config.Config, capability string) (brokerValidation, error) {
	var result brokerValidation
	if len(capability) == 0 || len(capability) > 8192 {
		return result, errors.New("invalid broker capability")
	}
	if err := uoaRequest(ctx, cfg, http.MethodPost, "/auth/session-broker/validate", map[string]string{fieldToken: capability}, &result); err != nil {
		return result, err
	}
	if result.Sub == "" || !result.ExpiresAt.After(time.Now()) || result.ExpiresAt.After(time.Now().Add(5*time.Minute+30*time.Second)) {
		return result, errors.New("invalid broker capability expiry")
	}
	return result, nil
}

func (m *SessionManager) createBroker(ctx context.Context, userID, capability string, validation brokerValidation) (string, error) {
	sealed, err := m.seal(capability)
	if err != nil {
		return "", err
	}
	var id string
	err = m.db.Pool.QueryRow(ctx, `INSERT INTO uoa_sessions (user_id,subject,organization_id,team_id,sealed_capability,capability_kind,expires_at) VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,'broker',$6) RETURNING id`, userID, validation.Sub, validation.Active.OrgID, validation.Active.TeamID, sealed, validation.ExpiresAt).Scan(&id)
	return id, err
}
