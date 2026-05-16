package mobile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxHostnameLen    = 253
	maxOSArchLen      = 64
	maxAppVersionLen  = 64
	wgPublicKeyRawLen = 32
)

// enrollValidationError indicates a specific field of the enrollment request
// failed validation. The bad value is intentionally not exposed.
type enrollValidationError struct {
	Field  string
	Reason string
}

func (e *enrollValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason)
}

func parseEnrollRequest(w http.ResponseWriter, r *http.Request) (enrollRequest, bool) {
	var req enrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return enrollRequest{}, false
	}
	if err := validateEnrollRequest(req); err != nil {
		writeEnrollValidationError(w, err)
		return enrollRequest{}, false
	}
	return req, true
}

func writeEnrollValidationError(w http.ResponseWriter, err error) {
	var verr *enrollValidationError
	if errors.As(err, &verr) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid request",
			"field":  verr.Field,
			"reason": verr.Reason,
		})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func validateEnrollRequest(req enrollRequest) error {
	hostname := strings.TrimSpace(req.Hostname)
	switch {
	case hostname == "":
		return &enrollValidationError{Field: "hostname", Reason: "required"}
	case len(hostname) > maxHostnameLen:
		return &enrollValidationError{Field: "hostname", Reason: "too long"}
	case !isDNSSafe(hostname):
		return &enrollValidationError{Field: "hostname", Reason: "must contain only letters, digits, '.' or '-'"}
	}

	platform := strings.TrimSpace(req.OSPlatform)
	if platform != "ios" && platform != "android" {
		return &enrollValidationError{Field: "os_platform", Reason: "must be 'ios' or 'android'"}
	}

	osArch := strings.TrimSpace(req.OSArch)
	switch {
	case osArch == "":
		return &enrollValidationError{Field: "os_arch", Reason: "required"}
	case len(osArch) > maxOSArchLen:
		return &enrollValidationError{Field: "os_arch", Reason: "too long"}
	}

	appVersion := strings.TrimSpace(req.AppVersion)
	switch {
	case appVersion == "":
		return &enrollValidationError{Field: "app_version", Reason: "required"}
	case len(appVersion) > maxAppVersionLen:
		return &enrollValidationError{Field: "app_version", Reason: "too long"}
	}

	wgKey := strings.TrimSpace(req.WGPublicKey)
	if wgKey == "" {
		return &enrollValidationError{Field: "wg_public_key", Reason: "required"}
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(wgKey)
	if decodeErr != nil || len(raw) != wgPublicKeyRawLen {
		return &enrollValidationError{Field: "wg_public_key", Reason: "must be base64-encoded 32 bytes"}
	}

	return nil
}

func isDNSSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func (h *Handler) ensureEnrollReady(ctx context.Context, w http.ResponseWriter, userID string) bool {
	if !h.allowRateLimit(ctx, w, ratelimit.Key("mobile", "enroll", "user", userID), mobileEnrollLimit, mobileEnrollWindow) {
		return false
	}
	if h.db == nil || h.db.Pool == nil {
		writeError(w, http.StatusInternalServerError, "database unavailable")
		return false
	}
	if h.cfg.WGServerPublicKey == "" || h.cfg.WGServerEndpoint == "" || h.cfg.WGOverlayCIDR == "" {
		writeError(w, http.StatusServiceUnavailable, "wireguard server not configured")
		return false
	}
	return true
}

func (h *Handler) enrollMobileDevice(ctx context.Context, userID string, req enrollRequest) (string, *string, error) {
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	deviceID, overlayIP, err := upsertMobileDevice(ctx, tx, userID, req)
	if err != nil {
		return "", nil, err
	}
	if keyErr := upsertMobileDeviceKey(ctx, tx, deviceID, req.WGPublicKey); keyErr != nil {
		return "", nil, keyErr
	}
	if overlayIP == nil && h.overlay != nil {
		ip, allocErr := h.overlay.AllocateTx(ctx, tx, deviceID)
		if allocErr != nil {
			return "", nil, allocErr
		}
		value := ip.String()
		overlayIP = &value
	}
	if commitErr := tx.Commit(ctx); commitErr != nil {
		return "", nil, commitErr
	}
	if h.hub != nil {
		if syncErr := h.hub.SyncDevice(ctx, deviceID); syncErr != nil {
			h.logger.Error("sync mobile wireguard peer", zap.Error(syncErr), zap.String("device_id", deviceID))
		}
	}
	return deviceID, overlayIP, nil
}

func (h *Handler) auditMobileEnroll(ctx context.Context, r *http.Request, userID, deviceID string) {
	if h.audit == nil {
		return
	}
	if auditErr := h.audit.Log(ctx, audit.Event{
		ActorUserID: &userID,
		Action:      "device.mobile_enroll",
		Outcome:     "success",
		TargetTable: "devices",
		TargetID:    &deviceID,
		RemoteIP:    audit.RemoteAddr(r),
		UserAgent:   r.UserAgent(),
	}); auditErr != nil {
		h.logger.Error("audit mobile enroll", zap.Error(auditErr))
	}
}

func upsertMobileDevice(ctx context.Context, tx pgx.Tx, userID string, req enrollRequest) (string, *string, error) {
	var deviceID string
	var overlayIP *string
	err := tx.QueryRow(ctx, `
SELECT id, host(overlay_ip)
FROM devices
WHERE owner_user_id = $1 AND hostname = $2
LIMIT 1
`, userID, req.Hostname).Scan(&deviceID, &overlayIP)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		credential, credErr := randomCredential()
		if credErr != nil {
			return "", nil, credErr
		}
		credentialHash, hashErr := bcrypt.GenerateFromPassword([]byte(credential), bcrypt.DefaultCost)
		if hashErr != nil {
			return "", nil, hashErr
		}

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
    disk_free_bytes,
    last_seen_at,
    updated_at
) VALUES ($1, $2, 'active', $3, $4, $5, $6, '', '', '', 1, 0, 0, 0, now(), now())
RETURNING id, host(overlay_ip)
`, userID, req.Hostname, string(credentialHash), req.AppVersion, req.OSPlatform, req.OSArch).Scan(&deviceID, &overlayIP)
		return deviceID, overlayIP, err
	}

	err = tx.QueryRow(ctx, `
UPDATE devices
SET status = 'active',
    hostname = $2,
    agent_version = $3,
    os_platform = $4,
    os_arch = $5,
    last_seen_at = now(),
    updated_at = now(),
    revoked_at = NULL,
    overlay_ip_reclaim_after = NULL
WHERE id = $1
RETURNING host(overlay_ip)
`, deviceID, req.Hostname, req.AppVersion, req.OSPlatform, req.OSArch).Scan(&overlayIP)
	return deviceID, overlayIP, err
}

func upsertMobileDeviceKey(ctx context.Context, tx pgx.Tx, deviceID, publicKey string) error {
	var keyID string
	var currentKey string
	var version int
	err := tx.QueryRow(ctx, `
SELECT id, wg_public_key, key_version
FROM device_keys
WHERE device_id = $1 AND state = 'active'
LIMIT 1
`, deviceID).Scan(&keyID, &currentKey, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_, insertErr := tx.Exec(ctx, `
INSERT INTO device_keys (device_id, key_version, wg_public_key, state)
VALUES ($1, 1, $2, 'active')
`, deviceID, publicKey)
			return insertErr
		}
		return err
	}
	if currentKey == publicKey {
		return nil
	}
	if _, execErr := tx.Exec(ctx, `
UPDATE device_keys
SET state = 'retired', retired_at = now()
WHERE id = $1
`, keyID); execErr != nil {
		return execErr
	}
	_, insertErr := tx.Exec(ctx, `
INSERT INTO device_keys (device_id, key_version, wg_public_key, state, rotated_from_key_id)
VALUES ($1, $2, $3, 'active', $4)
`, deviceID, version+1, publicKey, keyID)
	return insertErr
}
