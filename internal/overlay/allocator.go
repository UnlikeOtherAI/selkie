// Package overlay manages WireGuard overlay IP allocation from a CIDR block.
package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// dbtx is satisfied by both *pgxpool.Pool and pgx.Tx.
type dbtx interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Allocator assigns overlay IPs from a configured CIDR range.
type Allocator struct {
	pool *pgxpool.Pool
	cidr *net.IPNet
}

// New creates an Allocator for the given CIDR string.
func New(pool *pgxpool.Pool, cidrStr string) (*Allocator, error) {
	if pool == nil {
		return nil, errors.New("overlay allocator: nil pool")
	}

	ip, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("parse overlay cidr: %w", err)
	}

	cidr.IP = ip.Mask(cidr.Mask)

	return &Allocator{pool: pool, cidr: cidr}, nil
}

// Allocate assigns the next available overlay IP to the given device.
func (a *Allocator) Allocate(ctx context.Context, deviceID string) (net.IP, error) {
	if a == nil || a.pool == nil || a.cidr == nil {
		return nil, errors.New("overlay allocator: not initialized")
	}
	return a.allocateOn(ctx, a.pool, deviceID)
}

// AllocateTx performs allocation within an existing transaction so it can be
// atomic with the caller's device creation.
func (a *Allocator) AllocateTx(ctx context.Context, tx pgx.Tx, deviceID string) (net.IP, error) {
	if a == nil || a.cidr == nil {
		return nil, errors.New("overlay allocator: not initialized")
	}
	if tx == nil {
		return nil, errors.New("overlay allocator: nil tx")
	}
	return a.allocateOn(ctx, tx, deviceID)
}

func (a *Allocator) allocateOn(ctx context.Context, q dbtx, deviceID string) (net.IP, error) {
	const query = `
WITH range AS (
    SELECT ($2::inet + n)::inet AS ip
    FROM generate_series(1, $1) AS s(n)
)
SELECT host(r.ip)
FROM range r
WHERE NOT EXISTS (
    SELECT 1 FROM devices d WHERE d.overlay_ip = r.ip
)
ORDER BY r.ip
LIMIT 1
`

	ones, bits := a.cidr.Mask.Size()
	hostBits := bits - ones
	maxHosts := (1 << hostBits) - 2
	if maxHosts < 1 {
		return nil, fmt.Errorf("overlay cidr %s has no usable hosts", a.cidr.String())
	}

	var ipStr string
	if err := q.QueryRow(ctx, query, maxHosts, a.cidr.IP.String()).Scan(&ipStr); err != nil {
		return nil, fmt.Errorf("select overlay ip: %w", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid overlay ip: %q", ipStr)
	}

	if _, err := q.Exec(ctx, `
UPDATE devices
SET overlay_ip = $1,
    overlay_ip_allocated_at = now()
WHERE id = $2
`, ip.String(), deviceID); err != nil {
		return nil, fmt.Errorf("assign overlay ip: %w", err)
	}

	return ip, nil
}

// Release clears the overlay IP assignment for the given device.
func (a *Allocator) Release(ctx context.Context, deviceID string) error {
	if a == nil || a.pool == nil {
		return errors.New("overlay allocator: not initialized")
	}

	if _, err := a.pool.Exec(ctx, `
UPDATE devices
SET overlay_ip = NULL,
    overlay_ip_allocated_at = NULL
WHERE id = $1
`, deviceID); err != nil {
		return fmt.Errorf("release overlay ip: %w", err)
	}

	return nil
}
