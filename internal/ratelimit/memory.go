package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// MemoryLimiter is an in-memory implementation of Limiter intended for
// development environments where Redis is not available. Counters are kept in
// a process-local map keyed by the caller's key string. The map is sweep-GC'd
// lazily on access so an idle process does not accumulate stale entries
// indefinitely.
//
// It is NOT safe to use across multiple replicas: a fleet of two dev servers
// each maintain independent buckets. This is acceptable in dev mode but would
// silently undercount rate limits in production, which is why production paths
// require RedisLimiter.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*memoryBucket
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
