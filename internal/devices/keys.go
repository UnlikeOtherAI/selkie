package devices

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/silkie/internal/audit"
	"github.com/unlikeotherai/silkie/internal/auth"
	"go.uber.org/zap"
)

type rotateKeyRequest struct {
	NewWGPublicKey string `json:"new_wg_public_key"`
}

type rotateKeyResponse struct {
	KeyVersion int    `json:"key_version"`
	State      string `json:"state"`
}

func (h *Handler) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(chi.URLParam(r, "id"))
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "device id is required")
		return
	}

	var req rotateKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.NewWGPublicKey == "" {
		writeError(w, http.StatusBadRequest, "new_wg_public_key is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	// Verify device ownership.
	var ownerID string
	err = tx.QueryRow(ctx,
		`SELECT owner_user_id FROM devices WHERE id = $1 AND status = 'active'`,
		deviceID,
	).Scan(&ownerID)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if ownerID != claims.Sub {
		writeError(w, http.StatusForbidden, "not device owner")
		return
	}

	// Retire the current active key.
	var oldKeyID string
	var oldVersion int
	err = tx.QueryRow(ctx,
		`UPDATE device_keys
		 SET state = 'retired', retired_at = now()
		 WHERE device_id = $1 AND state = 'active'
		 RETURNING id, key_version`,
		deviceID,
	).Scan(&oldKeyID, &oldVersion)
	if err != nil {
		h.logger.Error("retire old key", zap.Error(err), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to retire old key")
		return
	}

	newVersion := oldVersion + 1

	// Insert the new key.
	_, err = tx.Exec(ctx,
		`INSERT INTO device_keys (device_id, key_version, wg_public_key, state, rotated_from_key_id)
		 VALUES ($1, $2, $3, 'active', $4)`,
		deviceID, newVersion, req.NewWGPublicKey, oldKeyID,
	)
	if err != nil {
		h.logger.Error("insert new key", zap.Error(err), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to insert new key")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit key rotation")
		return
	}

	if h.audit != nil {
		if auditErr := h.audit.Log(ctx, audit.Event{
			ActorUserID: &claims.Sub,
			Action:      "device.key_rotate",
			Outcome:     "success",
			TargetTable: "device_keys",
			TargetID:    &deviceID,
			RemoteIP:    audit.RemoteAddr(r),
			UserAgent:   r.UserAgent(),
		}); auditErr != nil {
			h.logger.Error("audit device.key_rotate", zap.Error(auditErr))
		}
	}

	writeJSON(w, http.StatusOK, rotateKeyResponse{
		KeyVersion: newVersion,
		State:      "active",
	})
}
