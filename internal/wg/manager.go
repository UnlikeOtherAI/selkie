package wg

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"go.uber.org/zap"
)

type Manager struct {
	InterfaceName string
}

func New(interfaceName string) *Manager {
	return &Manager{InterfaceName: interfaceName}
}

func (m *Manager) Init(ctx context.Context, privateKey, address, listenPort string) error {
	keyFile, err := os.CreateTemp("", "silkie-wg-private-key-*")
	if err != nil {
		zap.L().Error("create wireguard private key temp file", zap.Error(err))
		return err
	}
	defer os.Remove(keyFile.Name())

	if _, err := keyFile.WriteString(privateKey); err != nil {
		_ = keyFile.Close()
		zap.L().Error("write wireguard private key", zap.Error(err), zap.String("interface", m.InterfaceName))
		return err
	}

	if err := keyFile.Close(); err != nil {
		zap.L().Error("close wireguard private key file", zap.Error(err), zap.String("interface", m.InterfaceName))
		return err
	}

	if err := run(ctx, "ip", "link", "add", m.InterfaceName, "type", "wireguard"); err != nil {
		return err
	}

	args := []string{"set", m.InterfaceName, "private-key", keyFile.Name()}
	if listenPort != "" {
		args = append(args, "listen-port", listenPort)
	}
	if err := run(ctx, "wg", args...); err != nil {
		return err
	}

	if err := run(ctx, "ip", "addr", "add", address, "dev", m.InterfaceName); err != nil {
		return err
	}

	if err := run(ctx, "ip", "link", "set", m.InterfaceName, "up"); err != nil {
		return err
	}

	return nil
}

func (m *Manager) AddPeer(ctx context.Context, pubKey, allowedIP string) error {
	return run(ctx, "wg", "set", m.InterfaceName, "peer", pubKey, "allowed-ips", allowedIP, "persistent-keepalive", "25")
}

func (m *Manager) RemovePeer(ctx context.Context, pubKey string) error {
	return run(ctx, "wg", "set", m.InterfaceName, "peer", pubKey, "remove")
}

func (m *Manager) Down(ctx context.Context) error {
	return run(ctx, "ip", "link", "del", m.InterfaceName)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		wrapped := fmt.Errorf("run %s %v: %w", name, args, err)
		zap.L().Error("wireguard command failed",
			zap.Error(wrapped),
			zap.String("command", name),
			zap.Strings("args", args),
			zap.ByteString("output", output),
		)
		return wrapped
	}

	return nil
}
