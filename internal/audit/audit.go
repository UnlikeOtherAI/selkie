// Package audit provides structured audit event logging for the silkie control plane.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/unlikeotherai/silkie/internal/store"
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

// RemoteAddr extracts the client IP from an HTTP request, preferring X-Forwarded-For.
func RemoteAddr(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// nullIfEmpty returns nil for empty strings so Postgres receives NULL for inet columns.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
