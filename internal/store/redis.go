package store

import (
	"context"
	"errors"
	"fmt"

	redis "github.com/redis/go-redis/v9"
	"github.com/unlikeotherai/silkie/internal/config"
)

// Redis wraps a go-redis Client for pub/sub and caching.
type Redis struct {
	*redis.Client
}

// NewRedis connects to Redis, pings, and returns a ready client.
func NewRedis(ctx context.Context, cfg config.Config) (*Redis, error) {
	if cfg.RedisURL == "" {
		return nil, errors.New("redis url is required")
	}

	options, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(options)
	store := &Redis{Client: client}
	if err := store.Ping(ctx); err != nil {
		_ = store.Close() //nolint:errcheck // best-effort close on error path
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return store, nil
}

// Ping checks Redis connectivity.
func (r *Redis) Ping(ctx context.Context) error {
	if r == nil || r.Client == nil {
		return errors.New("redis client is nil")
	}

	return r.Client.Ping(ctx).Err()
}

// Close shuts down the Redis client connection.
func (r *Redis) Close() error {
	if r == nil || r.Client == nil {
		return nil
	}

	return r.Client.Close()
}
