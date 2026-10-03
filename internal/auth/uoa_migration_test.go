//nolint:testpackage // Tests the identity migration against pre-existing product references.
package auth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/store"
)

func TestIdentityMigrationPreservesDeviceOwnershipAndScrubsProfiles(t *testing.T) {
	connection := os.Getenv("SELKIE_TEST_DATABASE_URL")
	if connection == "" {
		t.Skip("SELKIE_TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	db, err := store.OpenDB(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	schema := fmt.Sprintf("identity_upgrade_%d", time.Now().UnixNano())
	if _, err = tx.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+",public"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001_initial.sql", "002_mobile_handoff_codes.sql", "003_device_keys_active_unique.sql"} {
		body, readErr := os.ReadFile("../../migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	var original string
	if err = tx.QueryRow(ctx, `INSERT INTO users(external_id,email,display_name,is_super) VALUES('stable-uoa-sub','old@example.com','Old copied profile',true) RETURNING id`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO devices(owner_user_id,hostname,credential_hash,agent_version,os_platform,os_version,os_arch,kernel_version,cpu_model,cpu_cores,total_memory_bytes,disk_total_bytes,disk_free_bytes) VALUES($1,'existing-device','product-hash','fixture','linux','fixture','amd64','fixture','fixture',1,0,0,0)`, original); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mobile_handoff_codes(code_hash,user_id,expires_at) VALUES(sha256('old-handoff'::bytea),$1,now()+interval '1 minute')`, original); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"004_uoa_relying_party_sessions.sql", "005_bounded_broker_capabilities.sql"} {
		body, readErr := os.ReadFile("../../migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	var subject, owner string
	var isSuper bool
	if err = tx.QueryRow(ctx, `SELECT u.external_id,u.is_super,d.owner_user_id FROM users u JOIN devices d ON d.owner_user_id=u.id WHERE d.hostname='existing-device'`).Scan(&subject, &isSuper, &owner); err != nil {
		t.Fatal(err)
	}
	if owner != original || subject != "stable-uoa-sub" || !isSuper {
		t.Fatal("stable product references changed")
	}
	var fields, handoffs int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='users' AND column_name IN ('email','display_name')`, schema).Scan(&fields); err != nil {
		t.Fatal(err)
	}
	if fields != 0 {
		t.Fatal("copied human profiles remain durable")
	}
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM mobile_handoff_codes").Scan(&handoffs); err != nil {
		t.Fatal(err)
	}
	if handoffs != 0 {
		t.Fatal("old handoff without UOA capability survived upgrade")
	}
}
