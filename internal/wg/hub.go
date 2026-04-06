package wg

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

type peerRecord struct {
	DeviceID     string
	PublicKey    string
	OverlayIP    string
	EndpointHost string
	EndpointPort int
}

// Hub owns the server-side WireGuard interface for the hub-and-spoke overlay.
type Hub struct {
	db               *store.DB
	manager          *Manager
	logger           *zap.Logger
	privateKey       string
	interfaceAddress string
}

// NewHub creates a hub when the WireGuard server runtime is configured.
// If WG_PRIVATE_KEY is empty, nil is returned and hub mode stays disabled.
func NewHub(db *store.DB, cfg config.Config, logger *zap.Logger) (*Hub, error) {
	if cfg.WGPrivateKey == "" {
		return nil, nil
	}
	if db == nil || db.Pool == nil {
		return nil, errors.New("wireguard hub: database is required")
	}
	if cfg.WGOverlayCIDR == "" {
		return nil, errors.New("wireguard hub: WG_OVERLAY_CIDR is required")
	}

	interfaceAddress, err := overlay.ServerInterfaceAddress(cfg.WGOverlayCIDR)
	if err != nil {
		return nil, err
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Hub{
		db:               db,
		manager:          New(cfg.WGInterfaceName),
		logger:           logger,
		privateKey:       cfg.WGPrivateKey,
		interfaceAddress: interfaceAddress,
	}, nil
}

// Init ensures the hub interface exists and reconciles all active peers.
func (h *Hub) Init(ctx context.Context, listenPort int) error {
	if h == nil {
		return nil
	}
	if err := h.manager.Init(ctx, h.privateKey, h.interfaceAddress, strconv.Itoa(listenPort)); err != nil {
		return err
	}
	return h.SyncAll(ctx)
}

// SyncDevice adds or updates the peer for a single active device.
func (h *Hub) SyncDevice(ctx context.Context, deviceID string) error {
	if h == nil {
		return nil
	}

	peer, found, err := h.loadPeer(ctx, deviceID)
	if err != nil {
		return err
	}
	if !found {
		return h.SyncAll(ctx)
	}

	return h.applyPeer(ctx, peer)
}

// SyncAll reconciles the full active device peer set against wg0.
func (h *Hub) SyncAll(ctx context.Context) error {
	if h == nil {
		return nil
	}

	peers, err := h.loadAllPeers(ctx)
	if err != nil {
		return err
	}

	active := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		active[peer.PublicKey] = struct{}{}
		if applyErr := h.applyPeer(ctx, peer); applyErr != nil {
			return applyErr
		}
	}

	currentPeers, err := h.manager.CurrentPeers(ctx)
	if err != nil {
		return err
	}
	for _, current := range currentPeers {
		if _, ok := active[current]; ok {
			continue
		}
		if removeErr := h.manager.RemovePeer(ctx, current); removeErr != nil {
			return removeErr
		}
	}

	return nil
}

func (h *Hub) applyPeer(ctx context.Context, peer peerRecord) error {
	allowedIP := peer.OverlayIP + "/32"
	endpoint := ""
	if peer.EndpointHost != "" && peer.EndpointPort > 0 {
		endpoint = net.JoinHostPort(peer.EndpointHost, strconv.Itoa(peer.EndpointPort))
	}
	return h.manager.AddPeer(ctx, peer.PublicKey, allowedIP, endpoint)
}

func (h *Hub) loadPeer(ctx context.Context, deviceID string) (peerRecord, bool, error) {
	const query = `
SELECT d.id,
       dk.wg_public_key,
       host(d.overlay_ip),
       coalesce(d.external_endpoint_host, ''),
       coalesce(d.external_endpoint_port, 0)
FROM devices d
JOIN device_keys dk ON dk.device_id = d.id AND dk.state = 'active'
WHERE d.id = $1
  AND d.status = 'active'
  AND d.overlay_ip IS NOT NULL
`

	var peer peerRecord
	err := h.db.Pool.QueryRow(ctx, query, deviceID).Scan(
		&peer.DeviceID,
		&peer.PublicKey,
		&peer.OverlayIP,
		&peer.EndpointHost,
		&peer.EndpointPort,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return peerRecord{}, false, nil
		}
		return peerRecord{}, false, err
	}

	return peer, true, nil
}

func (h *Hub) loadAllPeers(ctx context.Context) ([]peerRecord, error) {
	const query = `
SELECT d.id,
       dk.wg_public_key,
       host(d.overlay_ip),
       coalesce(d.external_endpoint_host, ''),
       coalesce(d.external_endpoint_port, 0)
FROM devices d
JOIN device_keys dk ON dk.device_id = d.id AND dk.state = 'active'
WHERE d.status = 'active'
  AND d.overlay_ip IS NOT NULL
ORDER BY d.created_at ASC
`

	rows, err := h.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []peerRecord
	for rows.Next() {
		var peer peerRecord
		if err := rows.Scan(&peer.DeviceID, &peer.PublicKey, &peer.OverlayIP, &peer.EndpointHost, &peer.EndpointPort); err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return peers, nil
}
