// Package wg provides WireGuard interface management via system commands.
package wg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// Manager controls a single WireGuard network interface.
type Manager struct {
	InterfaceName string
}

// New creates a Manager for the named WireGuard interface.
func New(interfaceName string) *Manager {
	return &Manager{InterfaceName: interfaceName}
}

// Init creates or updates the WireGuard interface, sets its private key,
// assigns its address, and brings it up.
func (m *Manager) Init(ctx context.Context, privateKey, address, listenPort string) error {
	keyFile, err := os.CreateTemp("", "selkie-wg-private-key-*")
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

	if err := m.ensureInterface(ctx); err != nil {
		return err
	}

	args := []string{"set", m.InterfaceName, "private-key", keyFile.Name()}
	if listenPort != "" {
		args = append(args, "listen-port", listenPort)
	}
	if err := run(ctx, "wg", args...); err != nil {
		return err
	}

	if err := run(ctx, "ip", "addr", "replace", address, "dev", m.InterfaceName); err != nil {
		return err
	}

	return run(ctx, "ip", "link", "set", m.InterfaceName, "up")
}

// AddPeer adds or updates a WireGuard peer with the given public key,
// allowed IP, endpoint, and the documented keepalive policy.
func (m *Manager) AddPeer(ctx context.Context, pubKey, allowedIP, endpoint string) error {
	args := []string{"set", m.InterfaceName, "peer", pubKey, "allowed-ips", allowedIP, "persistent-keepalive", "25"}
	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}
	return run(ctx, "wg", args...)
}

// RemovePeer removes a WireGuard peer by public key.
func (m *Manager) RemovePeer(ctx context.Context, pubKey string) error {
	return run(ctx, "wg", "set", m.InterfaceName, "peer", pubKey, "remove")
}

// CurrentPeers returns the currently configured peer public keys.
func (m *Manager) CurrentPeers(ctx context.Context) ([]string, error) {
	output, err := runOutput(ctx, "wg", "show", m.InterfaceName, "peers")
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return nil, nil
	}

	return strings.Fields(trimmed), nil
}

// Down tears down the WireGuard interface.
func (m *Manager) Down(ctx context.Context) error {
	return run(ctx, "ip", "link", "del", m.InterfaceName)
}

func (m *Manager) ensureInterface(ctx context.Context) error {
	exists, err := interfaceExists(ctx, m.InterfaceName)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return run(ctx, "ip", "link", "add", m.InterfaceName, "type", "wireguard")
}

func interfaceExists(ctx context.Context, name string) (bool, error) {
	cmd := exec.CommandContext(ctx, "ip", "link", "show", "dev", name)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}

	wrapped := fmt.Errorf("run ip [link show dev %s]: %w", name, err)
	zap.L().Error("wireguard command failed",
		zap.Error(wrapped),
		zap.String("command", "ip"),
		zap.Strings("args", []string{"link", "show", "dev", name}),
		zap.ByteString("output", output),
	)
	return false, wrapped
}

func run(ctx context.Context, name string, args ...string) error {
	_, err := runOutput(ctx, name, args...)
	return err
}

func runOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
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
		return nil, wrapped
	}

	return output, nil
}
