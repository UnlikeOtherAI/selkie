package auth

import (
	"context"
	"time"

	"github.com/unlikeotherai/selkie/internal/config"
)

// RafikiDirectCapability is a product-owned machine grant, never a UOA login.
const RafikiDirectCapability = "rafiki_direct_home"

func validRafikiDirect(cfg config.Config, claims Claims, now time.Time) bool {
	return cfg.RafikiServiceKey != "" && cfg.RafikiHomeDeviceID != "" &&
		claims.CapabilityKind == RafikiDirectCapability && claims.SessionID == "" &&
		claims.Sub != "" && !claims.IsSuper && claims.DirectHomeID == cfg.RafikiHomeDeviceID &&
		len(claims.Audience) == 1 && claims.HasAudience(AudienceMobile) &&
		claims.ExpiresAt.After(now) && !claims.ExpiresAt.After(now.Add(5*time.Minute))
}

func (m *SessionManager) validateRafikiDirect(ctx context.Context, claims Claims) (Claims, error) {
	if !validRafikiDirect(m.cfg, claims, time.Now()) {
		return Claims{}, errSessionExpired
	}
	if m.db == nil || m.db.Pool == nil {
		return Claims{}, errSessionUnavailable
	}
	var active bool
	err := m.db.Pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM users u, devices d WHERE u.id::text=$1 AND u.status='active'
		AND d.id::text=$2 AND d.status='active' AND d.direct_home_port IS NOT NULL
	)`, claims.Sub, claims.DirectHomeID).Scan(&active)
	if err != nil {
		return Claims{}, errSessionUnavailable
	}
	if !active {
		return Claims{}, errSessionExpired
	}
	return claims, nil
}
