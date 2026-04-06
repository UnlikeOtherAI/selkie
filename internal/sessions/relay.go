package sessions

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA1 is required by coturn's use-auth-secret mechanism (RFC 5389)
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/auth"
	"go.uber.org/zap"
)

const relayCredentialTTL = 3600 // 1 hour in seconds

type relayCredentialResponse struct {
	TurnServer string `json:"turn_server"`
	TurnPort   int    `json:"turn_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TTLSeconds int    `json:"ttl_seconds"`
	Transport  string `json:"transport"`
}

func (h *Handler) handleRelayCredentials(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessionID := strings.TrimSpace(chi.URLParam(r, "id"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}

	if h.cfg.CoturnSecret == "" {
		h.logger.Error("relay credentials requested but COTURN_SECRET is not configured")
		writeError(w, http.StatusServiceUnavailable, "relay not configured")
		return
	}

	// Validate the session exists, belongs to the requester, and is in an operable state.
	var targetDeviceID string
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select target_device_id from connect_sessions
		 where id = $1 and requester_user_id = $2
		   and status not in ('denied', 'closing', 'closed', 'expired', 'failed')`,
		sessionID,
		claims.Sub,
	).Scan(&targetDeviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		h.logger.Error("query session for relay", zap.Error(err), zap.String("session_id", sessionID))
		writeError(w, http.StatusInternalServerError, "failed to validate session")
		return
	}

	// Generate ephemeral TURN credentials using coturn's use-auth-secret mechanism.
	now := time.Now().UTC()
	expiresAt := now.Add(relayCredentialTTL * time.Second)
	// Embed session ID in the TURN username so coturn's redis-statsdb events
	// can be correlated back to our connect_sessions rows.
	username := fmt.Sprintf("%d:%s", expiresAt.Unix(), sessionID)

	mac := hmac.New(sha1.New, []byte(h.cfg.CoturnSecret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	transport := "udp"

	// Store the credential in the database.
	_, err = h.db.Pool.Exec(
		r.Context(),
		`insert into relay_credentials (
			connect_session_id,
			turn_username,
			password_hash,
			transport,
			ttl_seconds,
			issued_at,
			expires_at
		) values ($1, $2, $3, $4, $5, $6, $7)`,
		sessionID,
		username,
		password,
		transport,
		relayCredentialTTL,
		now,
		expiresAt,
	)
	if err != nil {
		h.logger.Error("insert relay credential", zap.Error(err), zap.String("session_id", sessionID))
		writeError(w, http.StatusInternalServerError, "failed to issue relay credentials")
		return
	}

	writeJSON(w, http.StatusOK, relayCredentialResponse{
		TurnServer: h.cfg.TurnHost,
		TurnPort:   h.cfg.TurnPort,
		Username:   username,
		Password:   password,
		TTLSeconds: relayCredentialTTL,
		Transport:  transport,
	})
}
