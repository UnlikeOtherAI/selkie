package mobile

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

type HubSyncer interface {
	SyncAll(ctx context.Context) error
	SyncDevice(ctx context.Context, deviceID string) error
}

const (
	mobileEnrollLimit  = 10
	mobileEnrollWindow = time.Minute
)

type Handler struct {
	db      *store.DB
	logger  *zap.Logger
	cfg     config.Config
	overlay *overlay.Allocator
	audit   *audit.Logger
	hub     HubSyncer
	limiter ratelimit.Limiter
}

type enrollRequest struct {
	Hostname    string `json:"hostname"`
	OSPlatform  string `json:"os_platform"`
	OSArch      string `json:"os_arch"`
	AppVersion  string `json:"app_version"`
	WGPublicKey string `json:"wg_public_key"`
}

type enrollResponse struct {
	DeviceID  string  `json:"device_id"`
	OverlayIP *string `json:"overlay_ip"`
	WGConfig  string  `json:"wg_config"`
}

type mobileServer struct {
	DeviceID   string  `json:"device_id"`
	Hostname   string  `json:"hostname"`
	Status     string  `json:"status"`
	OverlayIP  *string `json:"overlay_ip"`
	OSPlatform string  `json:"os_platform"`
	OSArch     string  `json:"os_arch"`
}

func New(db *store.DB, logger *zap.Logger, cfg config.Config, alloc *overlay.Allocator, auditor *audit.Logger, hub HubSyncer, limiter ratelimit.Limiter) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Handler{db: db, logger: logger, cfg: cfg, overlay: alloc, audit: auditor, hub: hub, limiter: limiter}
}

func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
		r.Use(auth.RequireAudience(auth.AudienceMobile))
		r.Post("/api/v1/mobile/enroll", h.handleEnroll)
		r.Get("/api/v1/mobile/servers", h.handleListServers)
		r.Post("/api/v1/mobile/disconnect", h.handleDisconnect)
	})
}

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	req, ok := parseEnrollRequest(w, r)
	if !ok {
		return
	}
	if !h.ensureEnrollReady(r.Context(), w, claims.Sub) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	deviceID, overlayIP, err := h.enrollMobileDevice(ctx, claims.Sub, req)
	if err != nil {
		h.logger.Error("enroll mobile device", zap.Error(err), zap.String("user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to enroll mobile device")
		return
	}

	h.auditMobileEnroll(ctx, r, claims.Sub, deviceID)

	wgConfig, renderErr := h.renderMobileWGConfig(*overlayIP)
	if renderErr != nil {
		h.logger.Error("render mobile wireguard config", zap.Error(renderErr), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to build wireguard config")
		return
	}

	writeJSON(w, http.StatusOK, enrollResponse{
		DeviceID:  deviceID,
		OverlayIP: overlayIP,
		WGConfig:  wgConfig,
	})
}

func (h *Handler) handleListServers(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(), `
SELECT d.id,
       d.hostname,
       'active' AS status,
       host(d.overlay_ip),
       d.os_platform,
       d.os_arch
FROM devices d
WHERE d.owner_user_id = $1
  AND d.status = 'active'
  AND EXISTS (SELECT 1 FROM services s WHERE s.device_id = d.id)
ORDER BY d.hostname ASC
`, claims.Sub)
	if err != nil {
		h.logger.Error("list mobile servers", zap.Error(err), zap.String("user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to list mobile servers")
		return
	}
	defer rows.Close()

	result := make([]mobileServer, 0)
	for rows.Next() {
		var item mobileServer
		if err := rows.Scan(&item.DeviceID, &item.Hostname, &item.Status, &item.OverlayIP, &item.OSPlatform, &item.OSArch); err != nil {
			h.logger.Error("scan mobile server", zap.Error(err), zap.String("user_id", claims.Sub))
			writeError(w, http.StatusInternalServerError, "failed to list mobile servers")
			return
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("iterate mobile servers", zap.Error(err), zap.String("user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to list mobile servers")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if h.audit != nil {
		if auditErr := h.audit.Log(r.Context(), audit.Event{
			ActorUserID: &claims.Sub,
			Action:      "mobile.disconnect",
			Outcome:     "info",
			TargetTable: "users",
			TargetID:    nil,
			RemoteIP:    audit.RemoteAddr(r),
			UserAgent:   r.UserAgent(),
		}); auditErr != nil {
			h.logger.Error("audit mobile disconnect", zap.Error(auditErr))
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) renderMobileWGConfig(deviceOverlayIP string) (string, error) {
	serverOverlayIP, err := overlay.ServerOverlayIP(h.cfg.WGOverlayCIDR)
	if err != nil {
		return "", err
	}

	peerConfig := overlay.GeneratePeerConfig(
		h.cfg.WGServerPublicKey,
		h.cfg.WGServerEndpoint,
		h.cfg.WGServerPort,
		serverOverlayIP,
		"mobile-device",
		deviceOverlayIP,
	)

	return fmt.Sprintf("[Interface]\nAddress = %s/32\n\n%s", deviceOverlayIP, peerConfig.DeviceSide), nil
}

func randomCredential() (string, error) {
	credBytes := make([]byte, 32)
	if _, err := rand.Read(credBytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(credBytes), nil
}

func (h *Handler) allowRateLimit(ctx context.Context, w http.ResponseWriter, key string, limit int64, window time.Duration) bool {
	if h.limiter == nil {
		writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return false
	}
	decision, err := h.limiter.Allow(ctx, key, limit, window)
	if err != nil {
		h.logger.Error("rate limit check failed", zap.Error(err), zap.String("key", key))
		writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return false
	}
	if decision.Allowed {
		return true
	}
	writeRateLimitError(w, decision.RetryAfter)
	return false
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
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}
