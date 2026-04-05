package devices

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/store"
)

const pairCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type Handler struct {
	db *store.DB
}

func New(db *store.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/v1/auth/pair/start", h.pairStart)
	r.Get("/v1/auth/pair/status", h.pairStatus)
	r.Get("/v1/devices", h.listDevices)
	r.Get("/v1/devices/{id}", h.getDevice)
	r.Post("/v1/devices/{id}/heartbeat", h.heartbeat)
	r.Delete("/v1/devices/{id}", h.revokeDevice)
}

func (h *Handler) pairStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WGPublicKey  string `json:"wg_public_key"`
		Hostname     string `json:"hostname"`
		OSPlatform   string `json:"os_platform"`
		OSArch       string `json:"os_arch"`
		AgentVersion string `json:"agent_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.WGPublicKey == "" || body.Hostname == "" {
		writeErr(w, http.StatusBadRequest, "wg_public_key and hostname required")
		return
	}

	code, err := generatePairCode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate code")
		return
	}

	_, err = h.db.Pool.Exec(r.Context(), `
		INSERT INTO pair_codes
			(code_hash, requested_hostname, requested_wg_public_key,
			 requested_agent_version, requested_os_platform, requested_os_arch,
			 status, expires_at)
		VALUES
			(sha256($1::bytea), $2, $3, $4, $5, $6, 'pending', now() + interval '10 minutes')
	`, code, body.Hostname, body.WGPublicKey,
		coalesce(body.AgentVersion, "unknown"),
		coalesce(body.OSPlatform, "unknown"),
		coalesce(body.OSArch, "unknown"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create pair code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (h *Handler) pairStatus(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
	if len(code) != 6 {
		writeErr(w, http.StatusBadRequest, "invalid code")
		return
	}

	var status string
	var overlayIP *string
	err := h.db.Pool.QueryRow(r.Context(), `
		SELECT pc.status, d.overlay_ip::text
		FROM pair_codes pc
		LEFT JOIN devices d ON d.id = pc.claimed_device_id
		WHERE pc.code_hash = sha256($1::bytea)
		  AND pc.expires_at > now()
	`, code).Scan(&status, &overlayIP)
	if err != nil {
		writeErr(w, http.StatusNotFound, "code not found or expired")
		return
	}

	resp := map[string]any{"status": status}
	if status == "claimed" && overlayIP != nil {
		resp["overlay_ip"] = *overlayIP
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(), `
		SELECT id, hostname, status, overlay_ip::text, os_platform,
		       os_version, os_arch, agent_version, last_seen_at, created_at
		FROM devices
		WHERE owner_user_id = (SELECT id FROM users WHERE external_id = $1)
		  AND status != 'revoked'
		ORDER BY created_at DESC
	`, claims.Sub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type deviceRow struct {
		ID           string     `json:"id"`
		Hostname     string     `json:"hostname"`
		Status       string     `json:"status"`
		OverlayIP    *string    `json:"overlay_ip"`
		OSPlatform   string     `json:"os_platform"`
		OSVersion    string     `json:"os_version"`
		OSArch       string     `json:"os_arch"`
		AgentVersion string     `json:"agent_version"`
		LastSeenAt   *time.Time `json:"last_seen_at"`
		CreatedAt    time.Time  `json:"created_at"`
	}

	devices := []deviceRow{}
	for rows.Next() {
		var d deviceRow
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Status, &d.OverlayIP,
			&d.OSPlatform, &d.OSVersion, &d.OSArch, &d.AgentVersion,
			&d.LastSeenAt, &d.CreatedAt); err != nil {
			continue
		}
		devices = append(devices, d)
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")

	var d struct {
		ID           string     `json:"id"`
		Hostname     string     `json:"hostname"`
		Status       string     `json:"status"`
		OverlayIP    *string    `json:"overlay_ip"`
		OSPlatform   string     `json:"os_platform"`
		OSVersion    string     `json:"os_version"`
		OSArch       string     `json:"os_arch"`
		AgentVersion string     `json:"agent_version"`
		LastSeenAt   *time.Time `json:"last_seen_at"`
		CreatedAt    time.Time  `json:"created_at"`
	}
	err := h.db.Pool.QueryRow(r.Context(), `
		SELECT id, hostname, status, overlay_ip::text, os_platform,
		       os_version, os_arch, agent_version, last_seen_at, created_at
		FROM devices
		WHERE id = $1
		  AND owner_user_id = (SELECT id FROM users WHERE external_id = $2)
	`, id, claims.Sub).Scan(&d.ID, &d.Hostname, &d.Status, &d.OverlayIP,
		&d.OSPlatform, &d.OSVersion, &d.OSArch, &d.AgentVersion,
		&d.LastSeenAt, &d.CreatedAt)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")

	var body struct {
		ExternalEndpointHost string `json:"external_endpoint_host"`
		ExternalEndpointPort int    `json:"external_endpoint_port"`
		AgentVersion         string `json:"agent_version"`
		DiskFreeBytes        int64  `json:"disk_free_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	tag, err := h.db.Pool.Exec(r.Context(), `
		UPDATE devices SET
			last_seen_at = now(),
			external_endpoint_host = NULLIF($3, ''),
			external_endpoint_port = NULLIF($4, 0),
			agent_version = NULLIF($5, ''),
			disk_free_bytes = NULLIF($6, 0),
			updated_at = now()
		WHERE id = $1
		  AND owner_user_id = (SELECT id FROM users WHERE external_id = $2)
		  AND status = 'active'
	`, id, claims.Sub,
		body.ExternalEndpointHost, body.ExternalEndpointPort,
		body.AgentVersion, body.DiskFreeBytes)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "device not found or not active")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")

	tag, err := h.db.Pool.Exec(r.Context(), `
		UPDATE devices SET
			status = 'revoked',
			revoked_at = now(),
			overlay_ip_reclaim_after = now() + interval '24 hours',
			updated_at = now()
		WHERE id = $1
		  AND owner_user_id = (SELECT id FROM users WHERE external_id = $2)
		  AND status != 'revoked'
	`, id, claims.Sub)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func generatePairCode() (string, error) {
	b := make([]byte, 6)
	n := big.NewInt(int64(len(pairCodeChars)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b[i] = pairCodeChars[idx.Int64()]
	}
	return string(b), nil
}

func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
