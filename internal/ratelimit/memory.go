package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// memorySweepEvery is how often Allow walks the whole bucket map evicting
// expired entries. Without periodic sweep, a stream of distinct one-shot keys
// (e.g. per-IP for a dev scanner) leaks memory linearly: the lazy "evict on
// repeat access for this key" path never runs for keys that are never revisited.
const memorySweepEvery = 64

// MemoryLimiter is an in-memory implementation of Limiter intended for
// development environments where Redis is not available. Counters are kept in
// a process-local map keyed by the caller's key string. Expired entries are
// evicted in two ways: lazily, when a request reuses an expired key, and
// proactively, every memorySweepEvery calls a full-map sweep removes any
// bucket whose window has already closed.
//
// It is NOT safe to use across multiple replicas: a fleet of two dev servers
// each maintain independent buckets. This is acceptable in dev mode but would
// silently undercount rate limits in production, which is why production paths
// require RedisLimiter.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*memoryBucket
	sinceGC int
}

type memoryBucket struct {
	count    int64
	expireAt time.Time
}

func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{buckets: make(map[string]*memoryBucket)}
}

func (l *MemoryLimiter) Allow(_ context.Context, key string, limit int64, window time.Duration) (Decision, error) {
	if l == nil {
		return Decision{}, errors.New("rate limiter unavailable")
	}
	if strings.TrimSpace(key) == "" {
		return Decision{}, errors.New("rate limit key is required")
	}
	if limit <= 0 || window <= 0 {
		return Decision{}, errors.New("limit and window must be positive")
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinceGC++
	if l.sinceGC >= memorySweepEvery {
		l.sweepLocked(now)
		l.sinceGC = 0
	}
	b, ok := l.buckets[key]
	if !ok || !b.expireAt.After(now) {
		b = &memoryBucket{count: 0, expireAt: now.Add(window)}
		l.buckets[key] = b
	}
	b.count++
	remaining := time.Until(b.expireAt)
	if remaining < 0 {
		remaining = 0
	}
	return Decision{
		Allowed:    b.count <= limit,
		Count:      b.count,
		RetryAfter: remaining,
	}, nil
}

// sweepLocked evicts every bucket whose window has already closed. Caller
// must hold l.mu.
func (l *MemoryLimiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if !b.expireAt.After(now) {
			delete(l.buckets, k)
		}
	}
}
