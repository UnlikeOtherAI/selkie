package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/store"
	"go.uber.org/zap"
)

type Handler struct {
	db     *store.DB
	logger *zap.Logger
	cfg    config.Config
}

func New(db *store.DB, logger *zap.Logger, cfg config.Config) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Handler{db: db, logger: logger, cfg: cfg}
}

func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
		r.Post("/v1/sessions", h.handleCreateSession)
		r.Post("/v1/sessions/{id}/candidates", h.handleSessionCandidates)
		r.Get("/v1/sessions", h.handleListSessions)
		r.Get("/v1/devices/{id}/events", h.handleDeviceEvents)
	})
}

type createSessionRequest struct {
	RequesterDeviceID string `json:"requester_device_id"`
	TargetDeviceID    string `json:"target_device_id"`
	TargetServiceID   string `json:"target_service_id"`
	RequestedAction   string `json:"requested_action"`
}

type candidatesRequest struct {
	Role       string `json:"role"`
	Candidates []any  `json:"candidates"`
}

func (h *Handler) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req createSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RequesterDeviceID == "" || req.TargetDeviceID == "" || req.TargetServiceID == "" || req.RequestedAction == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`with inserted as (
			insert into connect_sessions (
				requester_user_id,
				requester_device_id,
				target_device_id,
				target_service_id,
				requested_action,
				status,
				expires_at
			) values ($1, $2, $3, $4, $5, 'pending', $6)
			returning *
		)
		select row_to_json(inserted) from inserted`,
		claims.Sub,
		req.RequesterDeviceID,
		req.TargetDeviceID,
		req.TargetServiceID,
		req.RequestedAction,
		time.Now().UTC().Add(time.Hour),
	).Scan(&payload)
	if err != nil {
		h.logger.Error("create session", zap.Error(err), zap.String("requester_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleSessionCandidates(w http.ResponseWriter, r *http.Request) {
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

	var req candidatesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	column := ""
	switch req.Role {
	case "requester":
		column = "requester_candidate_set"
	case "target":
		column = "target_candidate_set"
	default:
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}

	candidateSet, err := json.Marshal(req.Candidates)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid candidates")
		return
	}

	query := fmt.Sprintf(`update connect_sessions
		set %s = $1::jsonb,
			updated_at = now()
		where id = $2 and requester_user_id = $3`, column)
	commandTag, err := h.db.Pool.Exec(r.Context(), query, candidateSet, sessionID, claims.Sub)
	if err != nil {
		h.logger.Error("update session candidates", zap.Error(err), zap.String("session_id", sessionID), zap.String("requester_user_id", claims.Sub), zap.String("role", req.Role))
		writeError(w, http.StatusInternalServerError, "failed to update candidates")
		return
	}

	if commandTag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select coalesce(json_agg(row_to_json(s)), '[]'::json)
		from (
			select *
			from connect_sessions
			where requester_user_id = $1
			order by created_at desc
			limit 50
		) s`,
		claims.Sub,
	).Scan(&payload)
	if err != nil {
		h.logger.Error("list sessions", zap.Error(err), zap.String("requester_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleDeviceEvents(w http.ResponseWriter, r *http.Request) {
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

	var exists int
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select 1 from devices where id = $1 and owner_user_id = $2`,
		deviceID,
		claims.Sub,
	).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}

		h.logger.Error("load device events stream", zap.Error(err), zap.String("device_id", deviceID), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to open events stream")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"device_id\":%q}\n\n", deviceID)
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain a single JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeRawJSON(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
