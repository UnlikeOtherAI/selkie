package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

func TestMemoryLimiter_BasicAllow(t *testing.T) {
	l := ratelimit.NewMemoryLimiter()
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		decision, err := l.Allow(ctx, "k", 3, time.Second)
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !decision.Allowed {
			t.Fatalf("Allow %d: expected allowed under limit", i)
		}
		if decision.Count != i {
			t.Fatalf("Allow %d: count=%d want %d", i, decision.Count, i)
		}
	}
	decision, err := l.Allow(ctx, "k", 3, time.Second)
	if err != nil {
		t.Fatalf("Allow over limit: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("Allow over limit: expected !Allowed")
	}
}

func TestMemoryLimiter_RejectsEmptyKey(t *testing.T) {
	l := ratelimit.NewMemoryLimiter()
	_, err := l.Allow(context.Background(), "   ", 1, time.Second)
	if err == nil {
		t.Fatalf("expected error on empty key")
	}
}

func TestMemoryLimiter_RejectsBadLimitOrWindow(t *testing.T) {
	l := ratelimit.NewMemoryLimiter()
	if _, err := l.Allow(context.Background(), "k", 0, time.Second); err == nil {
		t.Fatalf("expected error on limit=0")
	}
	if _, err := l.Allow(context.Background(), "k", 1, 0); err == nil {
		t.Fatalf("expected error on window=0")
	}
}

func TestMemoryLimiter_ExpiredBucketResets(t *testing.T) {
	l := ratelimit.NewMemoryLimiter()
	ctx := context.Background()
	// Use a very short window so the second call lands after expiry.
	if _, err := l.Allow(ctx, "k", 1, 5*time.Millisecond); err != nil {
		t.Fatalf("first Allow: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	decision, err := l.Allow(ctx, "k", 1, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("second Allow: %v", err)
	}
	if !decision.Allowed || decision.Count != 1 {
		t.Fatalf("expected fresh bucket after expiry; got Allowed=%v Count=%d", decision.Allowed, decision.Count)
	}
}

// TestMemoryLimiter_OverloadReturnsSentinel proves that when the limiter is
// saturated by a distinct-key flood the next *new* key fails closed with
// ErrMemoryLimiterOverloaded rather than allocating without bound. The
// sentinel is what auth.shouldAuditReject keys on to drop reject-audit rows
// during overload — change the error and that defense becomes silent.
func TestMemoryLimiter_OverloadReturnsSentinel(t *testing.T) {
	// Skip in -short to keep the default unit run under a second; the cap
	// is intentionally large (100k buckets) so this is a slow test.
	if testing.Short() {
		t.Skip("skipping overload test in short mode")
	}
	l := ratelimit.NewMemoryLimiter()
	ctx := context.Background()
	// Fill the bucket map to capacity using distinct keys inside a single
	// window. Use a long window so nothing expires mid-flood.
	const bucketCap = 100_000
	for i := 0; i < bucketCap; i++ {
		_, err := l.Allow(ctx, fmt.Sprintf("k-%d", i), 1, time.Minute)
		if err != nil {
			t.Fatalf("priming Allow %d: %v", i, err)
		}
	}
	// The cap+1 distinct key must be refused with the sentinel.
	_, err := l.Allow(ctx, "overflow-key", 1, time.Minute)
	if err == nil {
		t.Fatalf("expected ErrMemoryLimiterOverloaded; got nil")
	}
	if !errors.Is(err, ratelimit.ErrMemoryLimiterOverloaded) {
		t.Fatalf("expected ErrMemoryLimiterOverloaded; got %v", err)
	}
	// An *existing* key at capacity must still serve (otherwise the cap
	// would break legitimate traffic, not just the attacker).
	decision, err := l.Allow(ctx, "k-0", 1, time.Minute)
	if err != nil {
		t.Fatalf("existing-key Allow after cap: %v", err)
	}
	if decision.Count == 0 {
		t.Fatalf("existing key did not increment after overload; got Count=%d", decision.Count)
	}
}
