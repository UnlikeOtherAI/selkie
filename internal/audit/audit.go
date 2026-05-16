// Package audit provides structured audit event logging for the selkie control plane.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

// Event describes a single auditable action.
type Event struct {
	ActorUserID   *string        // nullable user UUID
	ActorDeviceID *string        // nullable device UUID
	Action        string         // e.g. "user.login", "device.create"
	Outcome       string         // success | failure | allow | deny | info
	TargetTable   string         // e.g. "users", "devices"
	TargetID      *string        // nullable target row UUID
	RemoteIP      string         // client IP
	UserAgent     string         // HTTP User-Agent header
	TraceID       string         // distributed trace correlation
	Metadata      map[string]any // arbitrary key-value context, stored as jsonb
}

// Logger writes audit events to the audit_events table.
type Logger struct {
	db     *store.DB
	logger *zap.Logger
}

// New creates an audit Logger with the given database and structured logger.
func New(db *store.DB, logger *zap.Logger) *Logger {
	return &Logger{db: db, logger: logger}
}

// Log inserts an audit event into the audit_events table.
// The id column is auto-generated; event_uuid is set to gen_random_uuid() in SQL.
// prev_hash and event_hash chaining is not yet implemented — event_hash is set to
// an empty byte array as a placeholder.
func (l *Logger) Log(ctx context.Context, evt Event) error {
	meta, err := json.Marshal(evt.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	if string(meta) == "null" {
		meta = []byte("{}")
	}

	_, err = l.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (
			event_uuid,
			actor_user_id,
			actor_device_id,
			action,
			outcome,
			target_table,
			target_id,
			remote_ip,
			user_agent,
			trace_id,
			metadata,
			prev_hash,
			event_hash
		) VALUES (
			gen_random_uuid(),
			$1, $2, $3, $4, $5, $6,
			$7::inet, $8, $9, $10::jsonb,
			NULL, '\x00'::bytea
		)
	`, evt.ActorUserID, evt.ActorDeviceID, evt.Action, evt.Outcome,
		evt.TargetTable, evt.TargetID,
		nullIfEmpty(evt.RemoteIP), evt.UserAgent, evt.TraceID, string(meta))
	if err != nil {
		l.logger.Error("write audit event", zap.Error(err), zap.String("action", evt.Action))
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}

// ClientIP extracts the originating client IP from an HTTP request.
//
// The immediate peer (r.RemoteAddr) is the only address the server can verify.
// X-Forwarded-For is only honored when the peer falls inside one of the
// trusted proxy CIDRs; otherwise the header is ignored to prevent untrusted
// clients from forging arbitrary IPs (e.g. for rate-limit key evasion).
//
// Returns the peer IP as a fallback when XFF is missing, malformed, or
// untrusted, and an empty string only when r.RemoteAddr itself is unparseable.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r.RemoteAddr)
	if !peer.IsValid() {
		return ""
	}
	if !ipInPrefixes(peer, trusted) {
		return peer.String()
	}
	fwd := r.Header.Get("X-Forwarded-For")
	if fwd == "" {
		return peer.String()
	}
	leftmost := strings.TrimSpace(strings.Split(fwd, ",")[0])
	if leftmost == "" {
		return peer.String()
	}
	forwarded, err := netip.ParseAddr(leftmost)
	if err != nil {
		return peer.String()
	}
	return forwarded.String()
}

func peerIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func ipInPrefixes(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// nullIfEmpty returns nil for empty strings so Postgres receives NULL for inet columns.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
