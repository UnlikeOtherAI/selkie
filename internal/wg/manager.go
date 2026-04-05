package wg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

type Manager struct {
	InterfaceName string
}

func New(interfaceName string) *Manager {
	return &Manager{InterfaceName: interfaceName}
}

func (m *Manager) Init(ctx context.Context, privateKey, address, listenPort string) error {
	kf, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		return fmt.Errorf("create key temp file: %w", err)
	}
	defer os.Remove(kf.Name())
	if _, err := kf.WriteString(privateKey); err != nil {
		kf.Close()
		return fmt.Errorf("write private key: %w", err)
	}
	kf.Close()

	cmds := [][]string{
		{"ip", "link", "add", m.InterfaceName, "type", "wireguard"},
		{"wg", "set", m.InterfaceName, "private-key", kf.Name(), "listen-port", listenPort},
		{"ip", "addr", "add", address, "dev", m.InterfaceName},
		{"ip", "link", "set", m.InterfaceName, "up"},
	}
	for _, args := range cmds {
		if err := run(ctx, args[0], args[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) AddPeer(ctx context.Context, pubKey, allowedIP string) error {
	return run(ctx, "wg", "set", m.InterfaceName,
		"peer", pubKey,
		"allowed-ips", allowedIP,
		"persistent-keepalive", "25")
}

func (m *Manager) RemovePeer(ctx context.Context, pubKey string) error {
	return run(ctx, "wg", "set", m.InterfaceName, "peer", pubKey, "remove")
}

func (m *Manager) Down(ctx context.Context) error {
	return run(ctx, "ip", "link", "del", m.InterfaceName)
}

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s %v: %w (output: %s)", name, args, err, string(out))
	}
	return nil
}
