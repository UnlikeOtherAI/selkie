package sessions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/store"
)

type Handler struct {
	db *store.DB
}

func New(db *store.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/v1/sessions", h.createSession)
	r.Post("/v1/sessions/{id}/candidates", h.submitCandidates)
	r.Get("/v1/sessions", h.listSessions)
	r.Get("/v1/devices/{id}/events", h.deviceEvents)
}

// POST /v1/sessions
func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		RequesterDeviceID string `json:"requester_device_id"`
		TargetDeviceID    string `json:"target_device_id"`
		TargetServiceID   string `json:"target_service_id"`
		RequestedAction   string `json:"requested_action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.TargetDeviceID == "" || body.TargetServiceID == "" {
		writeErr(w, http.StatusBadRequest, "target_device_id and target_service_id required")
		return
	}

	var sessionID string
	err := h.db.Pool.QueryRow(r.Context(), `
		INSERT INTO connect_sessions
			(requester_user_id, requester_device_id, target_device_id,
			 target_service_id, requested_action, status, expires_at)
		SELECT
			u.id,
			NULLIF($2, '')::uuid,
			$3::uuid,
			$4::uuid,
			$5,
			'pending',
			now() + interval '1 hour'
		FROM users u WHERE u.external_id = $1
		RETURNING id
	`, claims.Sub,
		body.RequesterDeviceID, body.TargetDeviceID,
		body.TargetServiceID, coalesce(body.RequestedAction, "connect")).Scan(&sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        sessionID,
		"status":    "pending",
		"expires_at": time.Now().Add(time.Hour),
	})
}

// POST /v1/sessions/{id}/candidates
func (h *Handler) submitCandidates(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sessionID := chi.URLParam(r, "id")

	var body struct {
		Role       string   `json:"role"` // "requester" or "target"
		Candidates []string `json:"candidates"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	candidatesJSON, err := json.Marshal(body.Candidates)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid candidates")
		return
	}

	var col string
	switch body.Role {
	case "requester":
		col = "requester_candidate_set"
	case "target":
		col = "target_candidate_set"
	default:
		writeErr(w, http.StatusBadRequest, "role must be requester or target")
		return
	}

	tag, err := h.db.Pool.Exec(r.Context(),
		fmt.Sprintf(`
			UPDATE connect_sessions SET %s = $1, status = 'candidate_exchange', updated_at = now()
			WHERE id = $2
			  AND requester_user_id = (SELECT id FROM users WHERE external_id = $3)
			  AND status IN ('pending', 'candidate_exchange')
		`, col),
		candidatesJSON, sessionID, claims.Sub)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/sessions
func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(), `
		SELECT id, status, target_device_id, target_service_id,
		       selected_path, created_at, closed_at
		FROM connect_sessions
		WHERE requester_user_id = (SELECT id FROM users WHERE external_id = $1)
		ORDER BY created_at DESC
		LIMIT 50
	`, claims.Sub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type sessionRow struct {
		ID              string     `json:"id"`
		Status          string     `json:"status"`
		TargetDeviceID  string     `json:"target_device_id"`
		TargetServiceID string     `json:"target_service_id"`
		SelectedPath    *string    `json:"selected_path"`
		CreatedAt       time.Time  `json:"created_at"`
		ClosedAt        *time.Time `json:"closed_at"`
	}

	sessions := []sessionRow{}
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.ID, &s.Status, &s.TargetDeviceID, &s.TargetServiceID,
			&s.SelectedPath, &s.CreatedAt, &s.ClosedAt); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}
	writeJSON(w, http.StatusOK, sessions)
}

// GET /v1/devices/{id}/events — SSE stream
func (h *Handler) deviceEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Send initial connected event
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	// Keep connection alive until client disconnects
	// Real Redis pub/sub fan-out is wired in the next pass
	<-r.Context().Done()
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
