package mobile

import (
	"context"
	"errors"
	"fmt"

	"github.com/unlikeotherai/selkie/internal/store"
)

// pgDisconnector is the production [mobileDeviceDisconnector] backed by
// PostgreSQL. It revokes a user's mobile devices and retires their active
// WireGuard key rows inside a single transaction.
type pgDisconnector struct {
	db *store.DB
}

// DisconnectMobileDevices marks all of the user's active iOS/Android device
// rows as revoked, retires their active device_keys rows, and returns the
// affected device IDs so the caller can drive hub sync and audit logging.
func (p pgDisconnector) DisconnectMobileDevices(ctx context.Context, userID string) ([]string, error) {
	if p.db == nil || p.db.Pool == nil {
		return nil, errors.New("database unavailable")
	}

	tx, err := p.db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin disconnect tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	rows, err := tx.Query(ctx, `
UPDATE devices
SET status = 'revoked',
    revoked_at = now(),
    overlay_ip_reclaim_after = now() + interval '24 hours',
    updated_at = now()
WHERE owner_user_id = $1
  AND status = 'active'
  AND os_platform IN ('ios', 'android')
RETURNING id
`, userID)
	if err != nil {
		return nil, fmt.Errorf("revoke mobile devices: %w", err)
	}
	deviceIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return nil, fmt.Errorf("scan revoked device id: %w", scanErr)
		}
		deviceIDs = append(deviceIDs, id)
	}
	rows.Close()
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate revoked devices: %w", rowsErr)
	}

	if len(deviceIDs) == 0 {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return nil, fmt.Errorf("commit disconnect tx: %w", commitErr)
		}
		return deviceIDs, nil
	}

	if _, execErr := tx.Exec(ctx, `
UPDATE device_keys
SET state = 'retired', retired_at = now()
WHERE device_id = ANY($1::uuid[])
  AND state = 'active'
`, deviceIDs); execErr != nil {
		return nil, fmt.Errorf("retire mobile device keys: %w", execErr)
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return nil, fmt.Errorf("commit disconnect tx: %w", commitErr)
	}
	return deviceIDs, nil
}
