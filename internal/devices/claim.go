package devices

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type pairClaimRequest struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
}

type pairClaimResponse struct {
	DeviceID   string  `json:"device_id"`
	OverlayIP  *string `json:"overlay_ip"`
	Credential string  `json:"credential"`
}

type pairCodeRecord struct {
	ID                    string
	FailCount             int
	RequestedWGPublicKey  string
	RequestedHostname     string
	RequestedOSPlatform   string
	RequestedOSArch       string
	RequestedAgentVersion string
}

type pairClaimTracker interface {
	Peek(ctx context.Context, key string) (ratelimit.Decision, error)
	Hit(ctx context.Context, key string, window time.Duration) (ratelimit.Decision, error)
}

//nolint:gocyclo,gocognit // linear multi-step claim process is clearer as one function
func (h *Handler) pairClaim(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req pairClaimRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	code := strings.ToUpper(strings.TrimSpace(req.Code))
	if code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	sourceIP := audit.ClientIP(r, h.cfg.TrustedProxyCIDRs)
	if !h.allowPairClaim(ctx, w, sourceIP, code) {
		return
	}

	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	var pc pairCodeRecord
	err = tx.QueryRow(ctx, `
SELECT id,
       fail_count,
       requested_wg_public_key,
       requested_hostname,
       requested_os_platform,
       requested_os_arch,
       requested_agent_version
FROM pair_codes
WHERE code_hash = sha256($1::bytea)
  AND status = 'pending'
  AND expires_at > now()
  AND locked_until IS NULL
`, code).Scan(
		&pc.ID,
		&pc.FailCount,
		&pc.RequestedWGPublicKey,
		&pc.RequestedHostname,
		&pc.RequestedOSPlatform,
		&pc.RequestedOSArch,
		&pc.RequestedAgentVersion,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.handleInvalidPairClaim(ctx, w, sourceIP, code)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load pair code")
		return
	}

	if pc.FailCount >= pairClaimFailureLimit {
		writeRateLimitError(w, pairClaimCodeLockWindow)
		return
	}

	credBytes := make([]byte, 32)
	if _, randErr := rand.Read(credBytes); randErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate credential")
		return
	}
	credential := base64.URLEncoding.EncodeToString(credBytes)

	credHash, hashErr := bcrypt.GenerateFromPassword([]byte(credential), bcrypt.DefaultCost)
	if hashErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash credential")
		return
	}

	hostname := strings.TrimSpace(req.DeviceName)
	if hostname == "" {
		hostname = pc.RequestedHostname
	}

	var deviceID string
	err = tx.QueryRow(ctx, `
INSERT INTO devices (
    owner_user_id,
    hostname,
    status,
    credential_hash,
    agent_version,
    os_platform,
    os_arch,
    os_version,
    kernel_version,
    cpu_model,
    cpu_cores,
    total_memory_bytes,
    disk_total_bytes,
    disk_free_bytes
) VALUES ($1, $2, 'active', $3, $4, $5, $6, '', '', '', 1, 0, 0, 0)
RETURNING id
`, claims.Sub, hostname, string(credHash), pc.RequestedAgentVersion, pc.RequestedOSPlatform, pc.RequestedOSArch).Scan(&deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create device")
		return
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO device_keys (device_id, key_version, wg_public_key, state)
VALUES ($1, 1, $2, 'active')
`, deviceID, pc.RequestedWGPublicKey); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create device key")
		return
	}

	var overlayIP *string
	if h.overlay != nil {
		ip, allocErr := h.overlay.AllocateTx(ctx, tx, deviceID)
		if allocErr != nil {
			h.logger.Error("allocate overlay ip", zap.Error(allocErr), zap.String("device_id", deviceID))
			writeError(w, http.StatusInternalServerError, "failed to allocate overlay ip")
			return
		}
		s := ip.String()
		overlayIP = &s
	}

	if _, err := tx.Exec(ctx, `
UPDATE pair_codes
SET status = 'claimed',
    claimed_device_id = $1,
    claimant_user_id = $2,
    claimed_at = now()
WHERE id = $3
`, deviceID, claims.Sub, pc.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to claim pair code")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit claim")
		return
	}

	if h.hub != nil {
		if syncErr := h.hub.SyncDevice(ctx, deviceID); syncErr != nil {
			h.logger.Error("sync wireguard peer after device claim", zap.Error(syncErr), zap.String("device_id", deviceID))
		}
	}

	if h.audit != nil {
		if auditErr := h.audit.Log(ctx, audit.Event{
			ActorUserID: &claims.Sub,
			Action:      "device.create",
			Outcome:     "success",
			TargetTable: "devices",
			TargetID:    &deviceID,
			RemoteIP:    sourceIP,
			UserAgent:   audit.TruncateUserAgent(r.UserAgent()),
		}); auditErr != nil {
			h.logger.Error("audit device.create", zap.Error(auditErr))
		}
	}

	writeJSON(w, http.StatusOK, pairClaimResponse{
		DeviceID:   deviceID,
		OverlayIP:  overlayIP,
		Credential: credential,
	})
}

func (h *Handler) allowPairClaim(ctx context.Context, w http.ResponseWriter, sourceIP, code string) bool {
	tracker, ok := h.pairClaimTracker()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return false
	}

	keys := []string{
		ratelimit.Key("devices", "pair", "claim", "failure", "ip", audit.RateLimitIP(sourceIP)),
		ratelimit.Key("devices", "pair", "claim", "failure", "code", ratelimit.HashToken(code)),
	}
	for _, key := range keys {
		decision, err := tracker.Peek(ctx, key)
		if err != nil {
			h.logger.Error("pair claim lock check failed", zap.Error(err), zap.String("key", key))
			writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
			return false
		}
		if decision.Count >= pairClaimFailureLimit {
			writeRateLimitError(w, decision.RetryAfter)
			return false
		}
	}
	return true
}

func (h *Handler) handleInvalidPairClaim(ctx context.Context, w http.ResponseWriter, sourceIP, code string) {
	allowed, retryAfter, err := h.recordPairClaimFailure(ctx, sourceIP, code)
	if err != nil {
		h.logger.Error("record pair claim failure", zap.Error(err), zap.String("source_ip", sourceIP))
		writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return
	}
	if !allowed {
		writeRateLimitError(w, retryAfter)
		return
	}
	writeError(w, http.StatusNotFound, "invalid or expired code")
}

func (h *Handler) recordPairClaimFailure(ctx context.Context, sourceIP, code string) (bool, time.Duration, error) {
	tracker, ok := h.pairClaimTracker()
	if !ok {
		return false, 0, errors.New("rate limiter unavailable")
	}

	checks := []struct {
		key    string
		window time.Duration
	}{
		{key: ratelimit.Key("devices", "pair", "claim", "failure", "ip", audit.RateLimitIP(sourceIP)), window: pairClaimSourceLockWindow},
		{key: ratelimit.Key("devices", "pair", "claim", "failure", "code", ratelimit.HashToken(code)), window: pairClaimCodeLockWindow},
	}

	var retryAfter time.Duration
	for _, check := range checks {
		decision, err := tracker.Hit(ctx, check.key, check.window)
		if err != nil {
			return false, 0, err
		}
		if decision.RetryAfter > retryAfter {
			retryAfter = decision.RetryAfter
		}
		if decision.Count >= pairClaimFailureLimit {
			return false, decision.RetryAfter, nil
		}
	}

	return true, retryAfter, nil
}

func (h *Handler) pairClaimTracker() (pairClaimTracker, bool) {
	tracker, ok := h.limiter.(pairClaimTracker)
	return tracker, ok
}
