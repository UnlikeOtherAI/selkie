package devices

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"go.uber.org/zap"
)

func (h *Handler) handleGetPeerConfig(w http.ResponseWriter, r *http.Request) {
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

	if h.cfg.WGServerPublicKey == "" || h.cfg.WGServerEndpoint == "" || h.cfg.WGOverlayCIDR == "" {
		writeError(w, http.StatusServiceUnavailable, "wireguard server not configured")
		return
	}

	serverOverlayIP, err := overlay.ServerOverlayIP(h.cfg.WGOverlayCIDR)
	if err != nil {
		h.logger.Error("resolve server overlay ip", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve wireguard server config")
		return
	}

	var overlayIP, wgPublicKey string
	err = h.db.Pool.QueryRow(
		r.Context(),
		`SELECT host(d.overlay_ip), dk.wg_public_key
		 FROM devices d
		 JOIN device_keys dk ON dk.device_id = d.id AND dk.state = 'active'
		 WHERE d.id = $1 AND d.owner_user_id = $2 AND d.status = 'active'`,
		deviceID,
		claims.Sub,
	).Scan(&overlayIP, &wgPublicKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device not found or has no overlay ip")
			return
		}
		h.logger.Error("get peer config", zap.Error(err), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to load peer config")
		return
	}

	pc := overlay.GeneratePeerConfig(
		h.cfg.WGServerPublicKey,
		h.cfg.WGServerEndpoint,
		h.cfg.WGServerPort,
		serverOverlayIP,
		wgPublicKey,
		overlayIP,
	)

	writeJSON(w, http.StatusOK, pc)
}
