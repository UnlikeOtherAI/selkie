package direct

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db      *store.DB
	cfg     config.Config
	audit   *audit.Logger
	limiter ratelimit.Limiter
	slots   chan struct{}
}

func New(db *store.DB, cfg config.Config, auditor *audit.Logger, limiter ratelimit.Limiter) *Handler {
	return &Handler{db: db, cfg: cfg, audit: auditor, limiter: limiter, slots: make(chan struct{}, 32)}
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/api/v1/direct/home/{id}/peers", h.deviceAuthenticated(h.stream))
	r.Post("/api/v1/direct/home/{id}/register", h.deviceAuthenticated(h.register))
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg, h.audit, h.limiter))
		r.Get("/api/v1/direct/{id}/peers", h.stream)
		r.With(auth.RequireAudience(auth.AudienceAdmin)).Post("/api/v1/direct/{id}/home", h.register)
	})
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var req struct {
		Endpoint    string `json:"endpoint"`
		ServicePort int    `json:"service_port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || ValidateEndpoint(req.Endpoint) != nil || req.ServicePort < 1 || req.ServicePort > 65535 {
		http.Error(w, "invalid direct endpoint or service port", http.StatusBadRequest)
		return
	}
	host, port, _ := net.SplitHostPort(req.Endpoint)
	n, _ := strconv.Atoi(port)
	tag, err := h.db.Pool.Exec(r.Context(), `UPDATE devices SET external_endpoint_host=$1, external_endpoint_port=$2, direct_home_port=$3, updated_at=now(), last_seen_at=now() WHERE id=$4 AND owner_user_id=$5 AND status='active' AND os_platform NOT IN ('ios','android','tvos')`, host, n, req.ServicePort, chi.URLParam(r, "id"), claims.Sub)
	if err != nil {
		http.Error(w, "registration unavailable", 503)
		return
	}
	if tag.RowsAffected() != 1 {
		http.Error(w, "device unavailable", 404)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) snapshot(ctx context.Context, deviceID string, claims auth.Claims) (Snapshot, error) {
	var ip, platform string
	var port *int
	err := h.db.Pool.QueryRow(ctx, `SELECT host(d.overlay_ip),d.os_platform,d.direct_home_port FROM devices d JOIN device_keys k ON k.device_id=d.id AND k.state='active' WHERE d.id=$1 AND d.owner_user_id=$2 AND d.status='active' AND d.overlay_ip IS NOT NULL`, deviceID, claims.Sub).Scan(&ip, &platform, &port)
	if err != nil {
		return Snapshot{}, err
	}
	mobile := platform == "ios" || platform == "android" || platform == "tvos"
	if claims.HasAudience(auth.AudienceMobile) && !claims.HasAudience(auth.AudienceAdmin) && !mobile {
		return Snapshot{}, errors.New("mobile audience requires mobile device")
	}
	if !mobile && port == nil {
		return Snapshot{}, errors.New("home service not registered")
	}
	rows, err := h.db.Pool.Query(ctx, `SELECT d.id,k.wg_public_key,host(d.overlay_ip),coalesce(d.external_endpoint_host,''),coalesce(d.external_endpoint_port,0),coalesce(d.direct_home_port,0),
 CASE WHEN d.owner_user_id=$1 AND NOT d.direct_scoped THEN NULL ELSE
 (SELECT min(g.expires_at) FROM direct_home_grants g WHERE g.expires_at>now() AND (($3 AND g.mobile_device_id=$2 AND g.home_device_id=d.id) OR (NOT $3 AND g.home_device_id=$2 AND g.mobile_device_id=d.id))) END
 FROM devices d JOIN device_keys k ON k.device_id=d.id AND k.state='active'
 WHERE d.status='active' AND d.id<>$2 AND d.overlay_ip IS NOT NULL
 AND ((d.owner_user_id=$1 AND NOT d.direct_scoped) OR EXISTS (SELECT 1 FROM direct_home_grants g WHERE g.expires_at>now() AND (($3 AND g.mobile_device_id=$2 AND g.home_device_id=d.id) OR (NOT $3 AND g.home_device_id=$2 AND g.mobile_device_id=d.id))))
 AND (NOT $3 OR $4='' OR d.id::text=$4)
 AND (($3 AND d.direct_home_port IS NOT NULL) OR (NOT $3 AND d.os_platform IN ('ios','android','tvos')))
 ORDER BY d.id`, claims.Sub, deviceID, mobile, claims.DirectHomeID)
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	result := Snapshot{OverlayIP: ip, Peers: make([]Peer, 0)}
	for rows.Next() {
		var peer Peer
		var host string
		var udpPort int
		var expiresAt *time.Time
		if err := rows.Scan(&peer.DeviceID, &peer.PublicKey, &peer.OverlayIP, &host, &udpPort, &peer.ServicePort, &expiresAt); err != nil {
			return Snapshot{}, err
		}
		// Home peers accept an incoming authenticated mobile handshake; they need
		// no client endpoint. Mobiles must have a concrete direct home endpoint.
		if mobile {
			peer.Endpoint = net.JoinHostPort(host, strconv.Itoa(udpPort))
			if ValidateEndpoint(peer.Endpoint) != nil {
				continue
			}
		}
		if expiresAt != nil && (result.NextExpiry.IsZero() || expiresAt.Before(result.NextExpiry)) {
			result.NextExpiry = *expiresAt
		}
		result.Peers = append(result.Peers, peer)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	result.WGConfig, err = Render(ip, result.Peers, h.cfg.WGServerPublicKey)
	return result, err
}

func (h *Handler) stream(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "too many connections", 503)
		return
	}
	// Expiry is enforced while the socket is open, not only at the handshake.
	ctx, cancel := context.WithDeadline(r.Context(), claims.ExpiresAt)
	defer cancel()
	listener, err := pgx.ConnectConfig(ctx, h.db.Pool.Config().ConnConfig.Copy())
	if err != nil {
		http.Error(w, "events unavailable", 503)
		return
	}
	defer listener.Close(context.Background()) //nolint:errcheck // best effort cleanup
	if _, err := listener.Exec(ctx, "LISTEN selkie_direct_peers"); err != nil {
		http.Error(w, "events unavailable", 503)
		return
	}
	snapshot, err := h.snapshot(ctx, chi.URLParam(r, "id"), claims)
	if err != nil {
		http.Error(w, "device unavailable", 404)
		return
	}
	if claims.DirectHomeID != "" {
		_, err = h.db.Pool.Exec(ctx, `INSERT INTO direct_home_grants (mobile_device_id,home_device_id,expires_at) VALUES ($1,$2,$3) ON CONFLICT (mobile_device_id,home_device_id) DO UPDATE SET expires_at=EXCLUDED.expires_at`, chi.URLParam(r, "id"), claims.DirectHomeID, claims.ExpiresAt)
		if err != nil {
			http.Error(w, "direct grant unavailable", 503)
			return
		}
		snapshot, err = h.snapshot(ctx, chi.URLParam(r, "id"), claims)
		if err != nil {
			http.Error(w, "device unavailable", 404)
			return
		}
	}
	socket, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer socket.CloseNow() //nolint:errcheck // disconnect fails closed
	ctx = socket.CloseRead(ctx)
	last := ""
	for {
		data, _ := json.Marshal(snapshot)
		if string(data) != last {
			writeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			err = wsjson.Write(writeCtx, socket, snapshot)
			stop()
			if err != nil {
				return
			}
			last = string(data)
		}
		waitCtx, stopWait := context.WithCancel(ctx)
		if !snapshot.NextExpiry.IsZero() {
			stopWait()
			waitCtx, stopWait = context.WithDeadline(ctx, snapshot.NextExpiry)
		}
		_, err = listener.WaitForNotification(waitCtx)
		stopWait()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		snapshot, err = h.snapshot(ctx, chi.URLParam(r, "id"), claims)
		if err != nil {
			return
		}
	}
}

// deviceAuthenticated accepts only the opaque credential issued for this home
// device. It cannot enroll a human, mint a session, or access another device.
func (h *Handler) deviceAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sourceIP := audit.ClientIP(r, h.cfg.TrustedProxyCIDRs)
		if h.limiter == nil {
			http.Error(w, "authentication unavailable", 503)
			return
		}
		limit, limitErr := h.limiter.Allow(r.Context(), ratelimit.Key("direct", "device-auth", audit.RateLimitIP(sourceIP)), 20, time.Minute)
		if limitErr != nil || !limit.Allowed {
			http.Error(w, "authentication rate limited", 429)
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if provided == r.Header.Get("Authorization") || len(provided) > 128 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var owner, hash string
		err := h.db.Pool.QueryRow(r.Context(), `SELECT owner_user_id,credential_hash FROM devices WHERE id=$1 AND status='active' AND os_platform NOT IN ('ios','android','tvos')`, chi.URLParam(r, "id")).Scan(&owner, &hash)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(provided)) != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		claims := auth.Claims{Sub: owner, Audience: []string{auth.AudienceAdmin}, ExpiresAt: time.Now().Add(24 * time.Hour)}
		next(w, r.WithContext(auth.ContextWithClaims(r.Context(), claims)))
	}
}
