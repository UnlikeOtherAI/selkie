// Package admin serves the web-based admin UI, login pages, and admin API endpoints.
package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

// Handler serves the admin dashboard, login HTML pages, and admin API endpoints.
type Handler struct {
	db      *store.DB
	logger  *zap.Logger
	cfg     config.Config
	audit   *audit.Logger
	limiter ratelimit.Limiter
}

// New creates a new admin Handler with the given dependencies.
func New(db *store.DB, logger *zap.Logger, cfg config.Config, auditor *audit.Logger, limiter ratelimit.Limiter) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Handler{db: db, logger: logger, cfg: cfg, audit: auditor, limiter: limiter}
}

// Mount registers admin routes on the given router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})

	// SPA routes — all resolve to the React app's index.html.
	r.Get("/login", h.serveSPA)
	r.Get("/admin", h.serveSPA)
	r.Get("/admin/*", h.serveSPA)

	// Vite-built JS/CSS bundles.
	r.Handle("/static/*", http.StripPrefix("/static",
		http.FileServer(http.Dir("admin-ui/dist/static"))))

	// Image assets (icons).
	r.Handle("/assets/*", http.StripPrefix("/assets",
		http.FileServer(http.Dir("assets"))))

	// Admin API endpoints require auth and super-user status.
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg, h.audit, h.limiter))
		r.Use(auth.RequireAudience(auth.AudienceAdmin))
		r.Get("/api/v1/audit", h.handleListAuditEvents)
		r.Get("/api/v1/system/info", h.handleSystemInfo)
	})
}

func (*Handler) serveSPA(w http.ResponseWriter, _ *http.Request) {
	serveHTMLFile(w, "admin-ui/dist/index.html")
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

func (h *Handler) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if !claims.IsSuper {
		writeError(w, http.StatusForbidden, "super-user access required")
		return
	}

	info := map[string]any{
		"version":          "0.1.0",
		"overlay_cidr":     h.cfg.WGOverlayCIDR,
		"turn_configured":  h.cfg.TurnHost != "",
		"turn_host":        h.cfg.TurnHost,
		"turn_port":        h.cfg.TurnPort,
		"opa_configured":   h.cfg.OPAEndpoint != "",
		"redis_configured": h.cfg.RedisURL != "",
	}

	var deviceCount, sessionCount int
	if scanErr := h.db.Pool.QueryRow(r.Context(),
		`SELECT count(*) FROM devices WHERE status = 'active'`).Scan(&deviceCount); scanErr != nil {
		h.logger.Error("count active devices", zap.Error(scanErr))
	}
	if scanErr := h.db.Pool.QueryRow(r.Context(),
		`SELECT count(*) FROM connect_sessions WHERE status NOT IN ('closed', 'expired', 'denied')`).Scan(&sessionCount); scanErr != nil {
		h.logger.Error("count active sessions", zap.Error(scanErr))
	}
	info["active_devices"] = deviceCount
	info["active_sessions"] = sessionCount

	writeJSON(w, http.StatusOK, info)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
