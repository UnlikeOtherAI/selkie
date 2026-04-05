package devices

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/silkie/internal/auth"
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

func (h *Handler) mountPairClaim(r chi.Router) {
	r.Post("/v1/auth/pair/claim", h.pairClaim)
}

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

	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

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
			writeError(w, http.StatusNotFound, "invalid or expired code")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load pair code")
		return
	}

	if pc.FailCount >= 5 {
		writeError(w, http.StatusLocked, "code locked")
		return
	}

	credBytes := make([]byte, 32)
	if _, err := rand.Read(credBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate credential")
		return
	}
	credential := base64.URLEncoding.EncodeToString(credBytes)

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
`, claims.Sub, hostname, credential, pc.RequestedAgentVersion, pc.RequestedOSPlatform, pc.RequestedOSArch).Scan(&deviceID)
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

	writeJSON(w, http.StatusOK, pairClaimResponse{
		DeviceID:   deviceID,
		OverlayIP:  nil,
		Credential: credential,
	})
}

// ensureUser looks up a user by their JWT subject (internal UUID).
// The subject in silkie JWTs is already the internal user UUID.
func ensureUser(ctx context.Context, tx pgx.Tx, userID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1`, userID).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}
