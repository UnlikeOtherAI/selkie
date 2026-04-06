// Package nat provides coturn relay allocation tracking via redis-statsdb.
//
// Coturn publishes allocation lifecycle and traffic events to Redis pub/sub
// when configured with --redis-statsdb. This subscriber consumes those events
// and persists them to PostgreSQL for audit, metrics, and billing.
//
// See docs/research/coturn-allocation-tracking.md for the full integration design.
package nat

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

// StatsSubscriber listens to coturn's redis-statsdb pub/sub channels and
// persists allocation lifecycle and traffic events to PostgreSQL.
type StatsSubscriber struct {
	rdb    *redis.Client
	db     *store.DB
	logger *zap.Logger
}

// NewStatsSubscriber creates a subscriber for coturn's redis-statsdb events.
// The rdb client should connect to the same Redis instance configured as
// coturn's --redis-statsdb (which may differ from the app's main Redis).
func NewStatsSubscriber(rdb *redis.Client, db *store.DB, logger *zap.Logger) *StatsSubscriber {
	return &StatsSubscriber{rdb: rdb, db: db, logger: logger}
}

// Run subscribes to coturn statsdb channels and processes events until ctx is canceled.
// It blocks and should be called in a goroutine.
func (s *StatsSubscriber) Run(ctx context.Context) {
	sub := s.rdb.PSubscribe(ctx,
		"turn/realm/*/user/*/allocation/*/status",
		"turn/realm/*/user/*/allocation/*/total_traffic",
	)
	defer sub.Close()

	s.logger.Info("coturn statsdb subscriber started")

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("coturn statsdb subscriber stopping")
			return
		case msg := <-ch:
			if msg == nil {
				return
			}
			s.handleMessage(ctx, msg.Channel, msg.Payload)
		}
	}
}

// channelRe extracts (realm, username, allocation_id, event_type) from a coturn
// redis-statsdb channel name.
var channelRe = regexp.MustCompile(
	`^turn/realm/([^/]+)/user/([^/]+)/allocation/([^/]+)/(.+)$`,
)

// trafficRe parses a coturn traffic payload like "rcvp=1025, rcvb=224660, sentp=1023, sentb=281136".
var trafficRe = regexp.MustCompile(`(\w+)=(\d+)`)

func (s *StatsSubscriber) handleMessage(ctx context.Context, channel, payload string) {
	m := channelRe.FindStringSubmatch(channel)
	if m == nil {
		s.logger.Debug("ignoring unrecognized statsdb channel", zap.String("channel", channel))
		return
	}
	realm, username, allocID, eventType := m[1], m[2], m[3], m[4]

	// Extract session ID from the TURN username. Our relay credential issuance
	// formats usernames as "expiry_timestamp:session_uuid".
	sessionID := extractSessionID(username)
	if sessionID == "" {
		s.logger.Debug("ignoring allocation for unrecognized username format",
			zap.String("username", username), zap.String("allocation_id", allocID))
		return
	}

	switch eventType {
	case "status":
		s.handleStatus(ctx, realm, sessionID, allocID, username, payload)
	case "total_traffic":
		s.handleTotalTraffic(ctx, sessionID, allocID, payload)
	}
}

func (s *StatsSubscriber) handleStatus(ctx context.Context, realm, sessionID, allocID, username, payload string) {
	switch {
	case strings.HasPrefix(payload, "new "):
		s.logger.Info("relay allocation started",
			zap.String("session_id", sessionID),
			zap.String("allocation_id", allocID),
			zap.String("realm", realm))

		allocKey := fmt.Sprintf("%s/%s/%s", realm, username, allocID)
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO relay_allocations (
				connect_session_id, allocation_key, transport, state, started_at
			) VALUES ($1, $2, 'udp', 'active', $3)
			ON CONFLICT (allocation_key) DO NOTHING`,
			sessionID, allocKey, time.Now().UTC())
		if err != nil {
			s.logger.Error("insert relay allocation", zap.Error(err),
				zap.String("session_id", sessionID), zap.String("allocation_key", allocKey))
		}

	case payload == "deleted":
		s.logger.Info("relay allocation ended",
			zap.String("session_id", sessionID),
			zap.String("allocation_id", allocID))

		allocKey := fmt.Sprintf("%s/%s/%s", realm, extractFullUsername(payload, allocID), allocID)
		// Use a broad match on allocation_key suffix since we may not have the full key.
		_, err := s.db.Pool.Exec(ctx,
			`UPDATE relay_allocations
			 SET state = 'closed', ended_at = $1, updated_at = $1
			 WHERE connect_session_id = $2 AND state = 'active'`,
			time.Now().UTC(), sessionID)
		if err != nil {
			s.logger.Error("close relay allocation", zap.Error(err),
				zap.String("session_id", sessionID), zap.String("allocation_key", allocKey))
		}
	}
}

func (s *StatsSubscriber) handleTotalTraffic(ctx context.Context, sessionID, allocID, payload string) {
	counters := parseTraffic(payload)
	bytesUp := counters["rcvb"]    // client to TURN
	bytesDown := counters["sentb"] // TURN to client

	s.logger.Info("relay allocation total traffic",
		zap.String("session_id", sessionID),
		zap.String("allocation_id", allocID),
		zap.Int64("bytes_up", bytesUp),
		zap.Int64("bytes_down", bytesDown))

	_, err := s.db.Pool.Exec(ctx,
		`UPDATE relay_allocations
		 SET bytes_up = $1, bytes_down = $2, updated_at = $3
		 WHERE id = (
			SELECT id FROM relay_allocations
			WHERE connect_session_id = $4
			ORDER BY started_at DESC LIMIT 1
		 )`,
		bytesUp, bytesDown, time.Now().UTC(), sessionID)
	if err != nil {
		s.logger.Error("update relay allocation traffic", zap.Error(err),
			zap.String("session_id", sessionID))
	}
}

// extractSessionID pulls the session UUID from a TURN username formatted as
// "expiry_timestamp:session_uuid".
func extractSessionID(username string) string {
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// extractFullUsername is a no-op helper; the full username is already in the
// channel path. Kept for clarity.
func extractFullUsername(_, _ string) string { return "" }

func parseTraffic(payload string) map[string]int64 {
	result := make(map[string]int64)
	for _, m := range trafficRe.FindAllStringSubmatch(payload, -1) {
		if v, err := strconv.ParseInt(m[2], 10, 64); err == nil {
			result[m[1]] = v
		}
	}
	return result
}
