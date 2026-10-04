// Package homepeer terminates WireGuard on the home machine and exposes one
// configured TCP service. No IP forwarding, internet gateway, or relay exists.
package homepeer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/unlikeotherai/selkie/internal/direct"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Peer struct {
	Device  *device.Device
	Network *netstack.Net
	address netip.Addr
	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

func New(privateKey, ip string, udpPort int) (*Peer, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() || udpPort < 0 || udpPort > 65535 {
		return nil, errors.New("invalid home interface")
	}
	key, err := keyHex(privateKey)
	if err != nil {
		return nil, err
	}
	tun, network, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1280)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "selkie-home: "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", key, udpPort)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &Peer{Device: dev, Network: network, address: addr, clients: make(map[net.Conn]struct{})}, nil
}

func keyHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

func (p *Peer) Apply(snapshot direct.Snapshot) error {
	if snapshot.OverlayIP != p.address.String() {
		return errors.New("overlay allocation changed")
	}
	if _, err := direct.Render(snapshot.OverlayIP, snapshot.Peers, ""); err != nil {
		return err
	}
	var config strings.Builder
	config.WriteString("replace_peers=true\n")
	for _, peer := range snapshot.Peers {
		key, err := keyHex(peer.PublicKey)
		if err != nil {
			return err
		}
		fmt.Fprintf(&config, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", key, peer.OverlayIP)
		if peer.Endpoint != "" {
			fmt.Fprintf(&config, "endpoint=%s\npersistent_keepalive_interval=25\n", peer.Endpoint)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Retire already-established service connections as part of any authority
	// change. Removing a WireGuard key alone must not leave buffered TCP alive.
	for client := range p.clients {
		_ = client.Close()
	}
	return p.Device.IpcSet(config.String())
}

func (p *Peer) Close() {
	p.mu.Lock()
	for client := range p.clients {
		_ = client.Close()
	}
	p.mu.Unlock()
	p.Device.Close()
}

func (p *Peer) Serve(ctx context.Context, port int, target string) error {
	host, _, err := net.SplitHostPort(target)
	addr, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !addr.IsLoopback() || port < 1 || port > 65535 {
		return errors.New("target must be a literal loopback TCP address; service port required")
	}
	listener, err := p.Network.ListenTCP(&net.TCPAddr{IP: net.ParseIP(p.address.String()), Port: port})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.clients[client] = struct{}{}
		p.mu.Unlock()
		go p.forward(ctx, client, target)
	}
}

func (p *Peer) forward(ctx context.Context, client net.Conn, target string) {
	defer func() { _ = client.Close(); p.mu.Lock(); delete(p.clients, client); p.mu.Unlock() }()
	local, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer local.Close()
	finished := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(client, local); finished <- struct{}{} }()
	_, _ = io.Copy(local, client)
	_ = local.Close()
	_ = client.Close()
	<-finished
}
