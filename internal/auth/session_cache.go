package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const maxSessionCacheEntries = 1024

type sessionCacheEntry struct {
	fingerprint string
	expires     time.Time
	claims      UOAClaims
}

type sessionCache struct {
	mu      sync.Mutex
	entries map[string]sessionCacheEntry
	flights map[string]chan struct{}
}

func capabilityFingerprint(sealed []byte) string {
	digest := sha256.Sum256(sealed)
	return hex.EncodeToString(digest[:])
}

func (c *sessionCache) acquire(ctx context.Context, id string) (func(), error) {
	for {
		c.mu.Lock()
		if pending, exists := c.flights[id]; exists {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, errSessionUnavailable
			case <-pending:
				continue
			}
		}
		if len(c.flights) >= maxSessionCacheEntries {
			c.mu.Unlock()
			return nil, errSessionUnavailable
		}
		pending := make(chan struct{})
		c.flights[id] = pending
		c.mu.Unlock()
		return func() { c.mu.Lock(); delete(c.flights, id); close(pending); c.mu.Unlock() }, nil
	}
}

func (c *sessionCache) get(id, fingerprint string) (*UOAClaims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok || entry.fingerprint != fingerprint || !time.Now().Before(entry.expires) {
		delete(c.entries, id)
		return nil, false
	}
	claims := entry.claims
	return &claims, true
}

func (c *sessionCache) put(id string, claims *UOAClaims) {
	expiry := time.Now().Add(2 * time.Minute)
	if claims.ExpiresAt == nil || !claims.ExpiresAt.After(time.Now()) {
		return
	}
	if claims.ExpiresAt.Before(expiry) {
		expiry = claims.ExpiresAt.Time
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxSessionCacheEntries {
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	c.entries[id] = sessionCacheEntry{fingerprint: claims.CapabilityFingerprint, expires: expiry, claims: *claims}
}
