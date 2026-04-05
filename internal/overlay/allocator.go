package overlay

import (
    "context"
    "fmt"
    "net"

    "github.com/jackc/pgx/v5/pgxpool"
)

type Allocator struct {
    pool *pgxpool.Pool
    cidr *net.IPNet
}

func New(pool *pgxpool.Pool, cidrStr string) (*Allocator, error) {
    if pool == nil {
        return nil, fmt.Errorf("overlay allocator: nil pool")
    }

    ip, cidr, err := net.ParseCIDR(cidrStr)
    if err != nil {
        return nil, fmt.Errorf("parse overlay cidr: %w", err)
    }

    cidr.IP = ip.Mask(cidr.Mask)

    return &Allocator{pool: pool, cidr: cidr}, nil
}

func (a *Allocator) Allocate(ctx context.Context, deviceID string) (net.IP, error) {
    if a == nil || a.pool == nil || a.cidr == nil {
        return nil, fmt.Errorf("overlay allocator: not initialized")
    }

    const query = `
WITH range AS (
    SELECT host(ip)::inet AS ip
    FROM generate_series(1, $1) s(n),
         LATERAL (SELECT ($2::inet + n)::inet AS ip) t
)
SELECT r.ip
FROM range r
WHERE NOT EXISTS (
    SELECT 1
    FROM devices d
    WHERE d.overlay_ip = r.ip
)
ORDER BY r.ip
LIMIT 1
`

    var ipStr string
    if err := a.pool.QueryRow(ctx, query, 65534, a.cidr.IP.String()).Scan(&ipStr); err != nil {
        return nil, fmt.Errorf("select overlay ip: %w", err)
    }

    ip := net.ParseIP(ipStr)
    if ip == nil {
        return nil, fmt.Errorf("invalid overlay ip: %q", ipStr)
    }

    if _, err := a.pool.Exec(ctx, `
UPDATE devices
SET overlay_ip = $1,
    overlay_ip_allocated_at = now()
WHERE id = $2
`, ip.String(), deviceID); err != nil {
        return nil, fmt.Errorf("assign overlay ip: %w", err)
    }

    return ip, nil
}

func (a *Allocator) Release(ctx context.Context, deviceID string) error {
    if a == nil || a.pool == nil {
        return fmt.Errorf("overlay allocator: not initialized")
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
