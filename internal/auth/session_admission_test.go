//nolint:testpackage // Tests staged capability cleanup and durable retry boundaries.
package auth

import (
	"context"
	"testing"
)

func freshFamily(t *testing.T, authority *sessionAuthorityFixture, family int) *UOAClaims {
	t.Helper()
	authority.mu.Lock()
	tokens := authority.tokens(family)
	authority.mu.Unlock()
	claims, err := decodeUOAToken(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	claims.RefreshToken = tokens["refresh_token"].(string)
	claims.RefreshExpiresIn = 86400
	return claims
}

func TestRejectedAdmissionRetainsSealedFamilyUntilRevocationRecovers(t *testing.T) {
	h, authority, _ := sessionFixture(t)
	claims := freshFamily(t, authority, 55)
	authority.profileFails = true
	authority.revokeFails = true
	if _, _, _, err := h.admitFreshFamily(context.Background(), claims); err == nil {
		t.Fatal("profile rejection admitted session")
	}
	var id string
	var sealed []byte
	var closing bool
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT id,sealed_capability,closing FROM uoa_sessions WHERE subject=$1 AND user_id IS NULL`, claims.Subject).Scan(&id, &sealed, &closing); err != nil {
		t.Fatalf("cleanup capability lost: %v", err)
	}
	if !closing || string(sealed) == claims.RefreshToken {
		t.Fatal("staged family must be encrypted and unusable")
	}
	if _, _, err := h.sessions.resolve(context.Background(), id, ""); err == nil {
		t.Fatal("unadmitted session became usable")
	}
	authority.profileFails = false
	authority.revokeFails = false
	if err := h.sessions.RetryCleanup(context.Background()); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	var exists bool
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM uoa_sessions WHERE id::text=$1)`, id).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	revoked := authority.revoked[55]
	authority.mu.Unlock()
	if exists || !revoked {
		t.Fatal("retry did not revoke and remove staged family")
	}
}

func TestStageDatabaseFailureAttemptsImmediateUpstreamCleanup(t *testing.T) {
	h, authority, _ := sessionFixture(t)
	claims := freshFamily(t, authority, 77)
	h.sessions.db = nil
	if _, _, _, err := h.admitFreshFamily(context.Background(), claims); err == nil {
		t.Fatal("missing durable store admitted family")
	}
	authority.mu.Lock()
	revoked := authority.revoked[77]
	profileReads := authority.profileReads
	authority.mu.Unlock()
	if !revoked || profileReads != 0 {
		t.Fatal("stage failure must revoke before profile work")
	}
}

func TestStagedFamilyCannotBecomeActiveWithoutUserReference(t *testing.T) {
	h, authority, _ := sessionFixture(t)
	claims := freshFamily(t, authority, 88)
	id, err := h.sessions.stage(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.db.Pool.Exec(context.Background(), `UPDATE uoa_sessions SET closing=false WHERE id::text=$1`, id); err == nil {
		t.Fatal("database allowed unowned active capability")
	}
	h.cleanupStaged(context.Background(), id)
}

func TestCleanupFailureDoesNotStarveLaterFamilies(t *testing.T) {
	h, authority, _ := sessionFixture(t)
	broken := freshFamily(t, authority, 91)
	brokenID, err := h.sessions.stage(context.Background(), broken)
	if err != nil {
		t.Fatal(err)
	}
	valid := freshFamily(t, authority, 92)
	validID, err := h.sessions.stage(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.db.Pool.Exec(context.Background(), `UPDATE uoa_sessions SET cleanup_after=now(),sealed_capability=CASE WHEN id::text=$1 THEN 'broken'::bytea ELSE sealed_capability END WHERE id::text IN ($1,$2)`, brokenID, validID); err != nil {
		t.Fatal(err)
	}
	if err = h.sessions.RetryCleanup(context.Background()); err == nil {
		t.Fatal("undecryptable row failure was not reported")
	}
	var pending bool
	var scheduled bool
	if err = h.db.Pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM uoa_sessions WHERE id::text=$1),EXISTS(SELECT 1 FROM uoa_sessions WHERE id::text=$2 AND closing AND cleanup_after>now())`, validID, brokenID).Scan(&pending, &scheduled); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	revoked := authority.revoked[92]
	authority.mu.Unlock()
	if pending || !scheduled || !revoked {
		t.Fatal("old failure starved later cleanup or lacked bounded retry scheduling")
	}
}

func TestCleanupRechecksEligibilityAndTreatsChangedRowsAsDone(t *testing.T) {
	h, authority, token := sessionFixture(t)
	source, _ := authenticateBearer("Bearer "+token, []byte(h.cfg.InternalSessionSecret))
	capability := freshFamily(t, authority, 93)
	id, err := h.sessions.stage(context.Background(), capability)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.sessions.cleanupOne(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	revoked := authority.revoked[93]
	authority.mu.Unlock()
	if revoked {
		t.Fatal("maintenance raced the active admission window")
	}
	if _, err = h.db.Pool.Exec(context.Background(), `UPDATE uoa_sessions SET user_id=$2::uuid,closing=false WHERE id::text=$1`, id, source.Sub); err != nil {
		t.Fatal(err)
	}
	if err = h.sessions.cleanupOne(context.Background(), id); err != nil {
		t.Fatalf("admitted row stopped cleanup %v", err)
	}
	if _, err = h.db.Pool.Exec(context.Background(), `DELETE FROM uoa_sessions WHERE id::text=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err = h.sessions.cleanupOne(context.Background(), id); err != nil {
		t.Fatalf("already deleted row stopped cleanup %v", err)
	}
}
