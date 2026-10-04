// Package direct supplies owner-scoped WireGuard peers. The control plane never
// transports service bytes and never gives a peer a route through the hub.
package direct

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Peer struct {
	DeviceID    string `json:"device_id"`
	PublicKey   string `json:"public_key"`
	OverlayIP   string `json:"overlay_ip"`
	Endpoint    string `json:"endpoint,omitempty"`
	ServicePort int    `json:"service_port,omitempty"`
}

type Snapshot struct {
	NextExpiry time.Time `json:"-"`
	OverlayIP  string    `json:"overlay_ip"`
	Peers      []Peer    `json:"peers"`
	WGConfig   string    `json:"wg_config"`
}

func ValidateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return errors.New("endpoint must be a literal IP and UDP port")
	}
	ip, err := netip.ParseAddr(host)
	n, pErr := strconv.Atoi(port)
	if err != nil || pErr != nil || n < 1 || n > 65535 || !ip.IsGlobalUnicast() || ip.IsLoopback() {
		return errors.New("endpoint must be a unicast IP and UDP port")
	}
	return nil
}

func Render(ip string, peers []Peer, hubKey string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return "", errors.New("invalid overlay address")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "[Interface]\nAddress = %s/32\nMTU = 1280\n", addr)
	seen := make(map[string]bool)
	for _, peer := range peers {
		key, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		route, rErr := netip.ParseAddr(peer.OverlayIP)
		if err != nil || len(key) != 32 || peer.PublicKey == hubKey || rErr != nil || !route.Is4() || route == addr || seen[peer.OverlayIP] {
			return "", errors.New("invalid or duplicate direct peer")
		}
		seen[peer.OverlayIP] = true
		if peer.Endpoint != "" {
			if err := ValidateEndpoint(peer.Endpoint); err != nil {
				return "", err
			}
		}
		fmt.Fprintf(&out, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", peer.PublicKey, route)
		if peer.Endpoint != "" {
			fmt.Fprintf(&out, "Endpoint = %s\nPersistentKeepalive = 25\n", peer.Endpoint)
		}
	}
	return out.String(), nil
}
