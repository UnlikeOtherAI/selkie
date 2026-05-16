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

// mobileDeviceDisconnector revokes a user's mobile devices and retires their
// active WireGuard key rows. It exists as an interface so the HTTP handler can
// be exercised without a live database.
type mobileDeviceDisconnector interface {
	DisconnectMobileDevices(ctx context.Context, userID string) ([]string, error)
}

const (
	mobileEnrollLimit  = 10
	mobileEnrollWindow = time.Minute
	// mobileDisconnectLimit is intentionally tight: each call retires every
	// active mobile device for the user, so a stolen JWT must not be able to
	// burst-revoke. Future work: take a `device_id` body param and make this
	// endpoint per-device, then this limit can relax.
	mobileDisconnectLimit  = 1
	mobileDisconnectWindow = time.Minute
)

type Handler struct {
	db           *store.DB
	logger       *zap.Logger
	cfg          config.Config
	overlay      *overlay.Allocator
	audit        *audit.Logger
	hub          HubSyncer
	limiter      ratelimit.Limiter
	disconnector mobileDeviceDisconnector
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
	h := &Handler{db: db, logger: logger, cfg: cfg, overlay: alloc, audit: auditor, hub: hub, limiter: limiter}
	h.disconnector = pgDisconnector{db: db}
	return h
}

func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
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

	h.writeMobileEnrollSuccess(w, deviceID, claims.Sub, overlayIP)
}

// writeMobileEnrollSuccess renders the WireGuard config for the freshly
// enrolled device and writes the success response. It returns false (after
// writing an error response) when the overlay IP is missing or the WireGuard
// config cannot be rendered.
func (h *Handler) writeMobileEnrollSuccess(w http.ResponseWriter, deviceID, userID string, overlayIP *string) bool {
	if overlayIP == nil {
		h.logger.Error("mobile enroll missing overlay allocation",
			zap.String("device_id", deviceID),
			zap.String("user_id", userID),
		)
		writeError(w, http.StatusServiceUnavailable, "overlay not allocated")
		return false
	}

	wgConfig, renderErr := h.renderMobileWGConfig(*overlayIP)
	if renderErr != nil {
		h.logger.Error("render mobile wireguard config", zap.Error(renderErr), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to build wireguard config")
		return false
	}

	writeJSON(w, http.StatusOK, enrollResponse{
		DeviceID:  deviceID,
		OverlayIP: overlayIP,
		WGConfig:  wgConfig,
	})
	return true
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

	if !h.allowRateLimit(r.Context(), w, ratelimit.Key("mobile", "disconnect", "user", claims.Sub), mobileDisconnectLimit, mobileDisconnectWindow) {
		return
	}
	if h.disconnector == nil {
		writeError(w, http.StatusInternalServerError, "database unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	deviceIDs, err := h.disconnector.DisconnectMobileDevices(ctx, claims.Sub)
	if err != nil {
		h.logger.Error("disconnect mobile devices", zap.Error(err), zap.String("user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to disconnect mobile devices")
		return
	}

	// A single SyncAll reconciles every retired device in one pass — loading
	// peers per-device fans out to N full reconciliations because retired
	// devices no longer match the `status='active'` filter in loadPeer.
	if h.hub != nil && len(deviceIDs) > 0 {
		if syncErr := h.hub.SyncAll(ctx); syncErr != nil {
			h.logger.Error("sync wireguard hub after mobile disconnect", zap.Error(syncErr), zap.Int("device_count", len(deviceIDs)))
		}
	}

	h.auditMobileDisconnect(ctx, r, claims.Sub, deviceIDs)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) auditMobileDisconnect(ctx context.Context, r *http.Request, userID string, deviceIDs []string) {
	if h.audit == nil {
		return
	}
	outcome := "success"
	if len(deviceIDs) == 0 {
		outcome = "info"
	}
	metadata := map[string]any{"device_ids": deviceIDs, "device_count": len(deviceIDs)}
	if auditErr := h.audit.Log(ctx, audit.Event{
		ActorUserID: &userID,
		Action:      "mobile.disconnect",
		Outcome:     outcome,
		TargetTable: "devices",
		TargetID:    nil,
		RemoteIP:    audit.RemoteAddr(r),
		UserAgent:   r.UserAgent(),
		Metadata:    metadata,
	}); auditErr != nil {
		h.logger.Error("audit mobile disconnect", zap.Error(auditErr))
	}
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
