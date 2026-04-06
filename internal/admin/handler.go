// Package admin serves the web-based admin UI, login pages, and admin API endpoints.
package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/store"
	"go.uber.org/zap"
)

// Handler serves the admin dashboard, login HTML pages, and admin API endpoints.
type Handler struct {
	db     *store.DB
	logger *zap.Logger
	cfg    config.Config
}

// New creates a new admin Handler with the given dependencies.
func New(db *store.DB, logger *zap.Logger, cfg config.Config) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Handler{db: db, logger: logger, cfg: cfg}
}

// Mount registers admin routes on the given router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/admin", h.serveAdmin)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	r.Get("/login", h.serveLogin)

	// Admin API endpoints require auth and super-user status.
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
		r.Get("/api/v1/audit", h.handleListAuditEvents)
	})
}

func (*Handler) serveAdmin(w http.ResponseWriter, _ *http.Request) {
	serveHTMLFile(w, "admin/index.html")
}

func (*Handler) serveLogin(w http.ResponseWriter, _ *http.Request) {
	serveHTMLFile(w, "admin/login.html")
}

func serveHTMLFile(w http.ResponseWriter, path string) {
	body, err := os.ReadFile(path) //nolint:gosec // G304: paths are controlled server-side, not user input
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

func (h *Handler) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if !claims.IsSuper {
		writeError(w, http.StatusForbidden, "super-user access required")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	action := r.URL.Query().Get("action")

	var payload []byte
	var err error

	if action != "" {
		err = h.db.Pool.QueryRow(
			r.Context(),
			`SELECT coalesce(json_agg(row_to_json(e)), '[]'::json)
			 FROM (
				SELECT event_uuid, actor_user_id, actor_device_id, action, outcome,
				       target_table, target_id, remote_ip, user_agent, trace_id,
				       metadata, occurred_at
				FROM audit_events
				WHERE action = $1
				ORDER BY occurred_at DESC
				LIMIT $2
			 ) e`,
			action, limit,
		).Scan(&payload)
	} else {
		err = h.db.Pool.QueryRow(
			r.Context(),
			`SELECT coalesce(json_agg(row_to_json(e)), '[]'::json)
			 FROM (
				SELECT event_uuid, actor_user_id, actor_device_id, action, outcome,
				       target_table, target_id, remote_ip, user_agent, trace_id,
				       metadata, occurred_at
				FROM audit_events
				ORDER BY occurred_at DESC
				LIMIT $1
			 ) e`,
			limit,
		).Scan(&payload)
	}

	if err != nil {
		h.logger.Error("list audit events", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
