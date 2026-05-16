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

var (
	// v4Broadcast is the IPv4 limited-broadcast address (255.255.255.255).
	// Hoisted here so it is allocated once rather than on every XFF walk.
	v4Broadcast = netip.MustParseAddr("255.255.255.255")

	// ipv6SiteLocal is the deprecated site-local IPv6 unicast range fec0::/10
	// (RFC 3879). These addresses return IsGlobalUnicast=true and slip past
	// the standard bogus-class checks; they must be caught explicitly.
	ipv6SiteLocal = netip.MustParsePrefix("fec0::/10")
)

// ClientIP extracts the originating client IP from an HTTP request.
//
// The immediate peer (r.RemoteAddr) is the only address the server can verify.
// X-Forwarded-For is only honored when the peer falls inside one of the
// trusted proxy CIDRs; otherwise the header is ignored to prevent untrusted
// clients from forging arbitrary IPs (e.g. for rate-limit key evasion).
//
// When the peer is trusted, the XFF list is walked right-to-left and the
// first non-trusted (i.e. not inside a trusted prefix) IP is returned. This
// mirrors the canonical "rightmost-non-trusted" algorithm and is safe even
// when an upstream proxy (e.g. Caddy with default reverse_proxy semantics)
// appends the real peer to a client-supplied XFF rather than overwriting it.
// If every entry in the XFF list is itself trusted (chained trusted proxies)
// or unparseable, the immediate peer is returned.
//
// All XFF header instances are concatenated (Header.Values), so requests
// using Header.Add to produce multiple X-Forwarded-For lines are handled
// equivalently to a single comma-separated header.
//
// Returns the peer IP as a fallback when XFF is missing, malformed, or
// fully trusted, and an empty string only when r.RemoteAddr itself is
// unparseable.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r.RemoteAddr)
	if !peer.IsValid() {
		return ""
	}
	if !ipInPrefixes(peer, trusted) {
		return peer.Unmap().String()
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer.Unmap().String()
	}
	joined := strings.Join(values, ",")
	parts := strings.Split(joined, ",")
	// Walk right-to-left: skip trusted-prefix entries (chained trusted
	// proxies, including a Caddy-appended peer IP) and return the first
	// non-trusted address encountered. This rejects an attacker-controlled
	// leftmost value when one or more trusted hops sit to its right.
	for i := len(parts) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(parts[i])
		if entry == "" {
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			// Unparseable hop in an otherwise trusted chain: fall back to
			// the peer rather than trusting anything to its left.
			return peer.Unmap().String()
		}
		// Zoned IPv6 (e.g. fe80::1%eth0) round-trips through String() with
		// the zone suffix and Postgres rejects "%zone" on inet cast, which
		// would suppress the audit row. Strip the zone before any trust
		// check or persistence.
		if addr.Zone() != "" {
			addr = addr.WithZone("")
		}
		// Reject addresses that cannot belong to a real client: unspecified
		// (0.0.0.0 / ::), multicast (224.0.0.0/4, ff00::/8), link-local
		// unicast (169.254.0.0/16, fe80::/10), the IPv4 limited broadcast
		// (255.255.255.255), and the deprecated IPv6 site-local range
		// (fec0::/10, RFC 3879). Any of these in an XFF header is either a
		// misconfiguration or an attempt to pin callers onto a shared
		// rate-limit bucket / pollute audit rows. Treat as unparseable and
		// fall back to the peer.
		if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() ||
			addr == v4Broadcast || ipv6SiteLocal.Contains(addr) {
			return peer.Unmap().String()
		}
		if ipInPrefixes(addr, trusted) {
			continue
		}
		// Persist the unmapped form so rate-limit keys and audit rows
		// never see a 4in6 representation of an IPv4 address.
		return addr.Unmap().String()
	}
	// Entire chain is trusted (or empty after trimming).
	return peer.Unmap().String()
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
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap()
}

func ipInPrefixes(ip netip.Addr, prefixes []netip.Prefix) bool {
	// netip.Prefix.Contains is family-strict: an IPv4-mapped IPv6 address
	// (e.g. ::ffff:10.0.0.5) is NOT contained by an IPv4 prefix even though
	// it is semantically the same v4 host. Unmap so a 4in6 form cannot
	// bypass IPv4 trusted prefixes.
	ip = ip.Unmap()
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
