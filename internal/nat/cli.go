package nat

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

const coturnCLITimeout = 5 * time.Second

// CoturnCLI communicates with coturn's telnet management interface to
// list and forcefully cancel relay sessions.
type CoturnCLI struct {
	addr     string
	password string
	logger   *zap.Logger
}

// NewCoturnCLI creates a client for coturn's telnet CLI.
func NewCoturnCLI(addr, password string, logger *zap.Logger) *CoturnCLI {
	return &CoturnCLI{addr: addr, password: password, logger: logger}
}

// KillSession forcefully cancels a coturn session by TURN username.
// It connects to the telnet CLI, runs "ps <username>" to find session IDs,
// then runs "cs <session-id>" for each to terminate them.
func (c *CoturnCLI) KillSession(ctx context.Context, turnUsername string) error {
	if c.addr == "" {
		return errors.New("coturn CLI address not configured")
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("connect to coturn CLI: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Authenticate if password is set.
	if c.password != "" {
		if authErr := sendCommand(conn, reader, c.password); authErr != nil {
			return fmt.Errorf("authenticate with coturn CLI: %w", authErr)
		}
	}

	// List sessions for this username.
	output, err := sendCommandRead(conn, reader, "ps "+turnUsername)
	if err != nil {
		return fmt.Errorf("list sessions for %q: %w", turnUsername, err)
	}

	// Parse session IDs from the output. coturn outputs lines containing
	// session IDs in various formats; we look for numeric IDs.
	sessionIDs := parseSessionIDs(output)
	if len(sessionIDs) == 0 {
		c.logger.Debug("no active coturn sessions found for username",
			zap.String("username", turnUsername))
		return nil
	}

	// Cancel each session.
	for _, sid := range sessionIDs {
		c.logger.Info("canceling coturn session",
			zap.String("session_id", sid),
			zap.String("username", turnUsername))
		if cancelErr := sendCommand(conn, reader, "cs "+sid); cancelErr != nil {
			c.logger.Error("cancel coturn session", zap.Error(cancelErr),
				zap.String("session_id", sid))
		}
	}

	return nil
}

func (c *CoturnCLI) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = coturnCLITimeout
	return d.DialContext(ctx, "tcp", c.addr)
}

func sendCommand(conn net.Conn, reader *bufio.Reader, cmd string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(coturnCLITimeout)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return err
	}
	// Read and discard response lines until we hit a prompt or timeout.
	if err := conn.SetReadDeadline(time.Now().Add(coturnCLITimeout)); err != nil {
		return err
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil //nolint:nilerr // timeout or EOF is expected after command completes
		}
		if strings.Contains(line, "> ") {
			return nil
		}
	}
}

func sendCommandRead(conn net.Conn, reader *bufio.Reader, cmd string) (string, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(coturnCLITimeout)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := conn.SetReadDeadline(time.Now().Add(coturnCLITimeout)); err != nil {
		return "", err
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			// Timeout or EOF — return what we have so far.
			return sb.String(), nil //nolint:nilerr // timeout/EOF is the expected termination signal from coturn CLI
		}
		sb.WriteString(line)
		if strings.Contains(line, "> ") {
			break
		}
	}
	return sb.String(), nil
}

// parseSessionIDs extracts numeric session identifiers from coturn CLI output.
// The ps command outputs lines like "  1) id=001000000000000001, ...".
func parseSessionIDs(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Look for id=... pattern in ps output.
		if idx := strings.Index(line, "id="); idx >= 0 {
			rest := line[idx+3:]
			if comma := strings.IndexAny(rest, ", \t"); comma > 0 {
				ids = append(ids, rest[:comma])
			} else if len(rest) > 0 {
				ids = append(ids, strings.TrimSpace(rest))
			}
		}
	}
	return ids
}
