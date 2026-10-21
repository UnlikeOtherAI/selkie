package auth

import (
	"context"
	"sync"
	"time"
)

// RetryCleanup bounds both rows per sweep and time spent contacting UOA.
func (m *SessionManager) RetryCleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rows, err := m.db.Pool.Query(ctx, `SELECT id FROM uoa_sessions WHERE closing AND cleanup_after<=now() ORDER BY created_at LIMIT 20`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	var firstErr error
	for _, id := range ids {
		if err = m.cleanupOne(ctx, id); err == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if firstErr == nil {
			firstErr = err
		}
		if _, scheduleErr := m.db.Pool.Exec(ctx, `UPDATE uoa_sessions SET cleanup_after=now()+interval '2 minutes' WHERE id::text=$1 AND closing`, id); scheduleErr != nil {
			return scheduleErr
		}
	}
	return firstErr
}

// StartMaintenance returns a stop function that drains this owned background task.
func (m *SessionManager) StartMaintenance(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.RetryCleanup(ctx); err != nil {
					continue
				}
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}
