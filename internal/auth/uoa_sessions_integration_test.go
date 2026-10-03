//nolint:testpackage // Exercises confidential transport and private session store boundaries.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
	"go.uber.org/zap"
)

type sessionAuthorityFixture struct {
	mu                sync.Mutex
	subject           string
	generation        int
	families          map[string]int
	grants            map[string]int
	revoked           map[int]bool
	cancelOnRefresh   context.CancelFunc
	profileReads      int
	profileFails      bool
	revokeFails       bool
	brokerRefused     bool
	brokerUnavailable bool
	latest            string
}

func (f *sessionAuthorityFixture) tokens(family int) map[string]any {
	f.generation++
	refresh := fmt.Sprintf("family-%d-refresh-%d", family, f.generation)
	f.families[refresh] = family
	f.latest = refresh
	claims := UOAClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: f.subject, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	access, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("upstream-fixture"))
	return map[string]any{"access_token": access, "refresh_token": refresh, "expires_in": 3600, "refresh_token_expires_in": 86400}
}

func (f *sessionAuthorityFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/domain/users" {
		f.profileReads++
		if f.profileFails {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Query().Get("user_id") != f.subject {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]string{{"id": f.subject, "email": "current@example.com", "name": "Current profile"}}})
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	family, ok := f.families[body["refresh_token"]]
	switch r.URL.Path {
	case "/auth/session-broker/validate":
		if f.brokerUnavailable {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if f.brokerRefused || body["token"] != "approved-broker" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": f.subject, "expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339), "active": map[string]string{"orgId": "org", "teamId": "team"}})
	case "/auth/token":
		if !ok || f.revoked[family] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		delete(f.families, body["refresh_token"])
		if f.cancelOnRefresh != nil {
			f.cancelOnRefresh()
		}
		_ = json.NewEncoder(w).Encode(f.tokens(family))
	case "/auth/debug-login/issue":
		if !ok || f.revoked[family] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		delete(f.grants, body["previous_token"])
		code := fmt.Sprintf("%043d", f.generation+1)
		f.generation++
		f.grants[code] = family
		_ = json.NewEncoder(w).Encode(map[string]any{"token": code, "expires_in": 1800})
	case "/auth/debug-login/redeem":
		source, exists := f.grants[body["token"]]
		if !exists || f.revoked[source] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		delete(f.grants, body["token"])
		_ = json.NewEncoder(w).Encode(f.tokens(f.generation + 100))
	case "/auth/revoke":
		if f.revokeFails {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !ok || body["scope"] != "family" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.revoked[family] = true
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func sessionFixture(t *testing.T) (*CallbackHandler, *sessionAuthorityFixture, string) {
	t.Helper()
	connection := os.Getenv("SELKIE_TEST_DATABASE_URL")
	if connection == "" {
		t.Skip("SELKIE_TEST_DATABASE_URL required")
	}
	db, err := store.OpenDB(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err = db.RunMigrations(context.Background(), "../../migrations"); err != nil {
		t.Fatal(err)
	}
	authority := &sessionAuthorityFixture{subject: fmt.Sprintf("session-proof-%d", time.Now().UnixNano()), families: map[string]int{}, grants: map[string]int{}, revoked: map[int]bool{}}
	upstream := httptest.NewServer(authority)
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), "DELETE FROM uoa_sessions WHERE subject=$1", authority.subject)
	})
	cfg := config.Config{UOABaseURL: upstream.URL, UOAConfigURL: upstream.URL + "/config", UOARedirectURL: "http://localhost:15344/auth/callback", UOASharedSecret: "fixture-secret", InternalSessionSecret: strings.Repeat("s", 32)}
	h := NewCallbackHandler(db, cfg, nil, zap.NewNop(), fakeLimiter{decision: ratelimit.Decision{Allowed: true}})
	claims := &UOAClaims{RefreshToken: "source-refresh", RefreshExpiresIn: 86400}
	claims.Subject = authority.subject
	authority.families[claims.RefreshToken] = 1
	userID, isSuper, err := h.upsertUser(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), "DELETE FROM users WHERE id::text=$1", userID) })
	id, err := NewSessionManager(db, cfg).create(context.Background(), userID, claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.mintSessionToken(userID, isSuper, id, []string{AudienceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	return h, authority, token
}

func sessionPost(t *testing.T, h *CallbackHandler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	h.Mount(router)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestDebugLoginCreatesIndependentFamilyAndRejectsReplay(t *testing.T) {
	h, _, source := sessionFixture(t)
	issue := sessionPost(t, h, "/auth/debug-login/issue", source, "{}")
	if issue.Code != 200 {
		t.Fatalf("issue %d %s", issue.Code, issue.Body.String())
	}
	var grant map[string]string
	if err := json.Unmarshal(issue.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if len(grant) != 2 || grant["url"] != "http://localhost:15344/" || !debugCodePattern.MatchString(grant["token"]) {
		t.Fatalf("invalid grant shape %#v", grant)
	}
	redeem := sessionPost(t, h, "/auth/debug-login/redeem", "", fmt.Sprintf(`{"token":%q}`, grant["token"]))
	if redeem.Code != 200 {
		t.Fatalf("redeem %d %s", redeem.Code, redeem.Body.String())
	}
	var session map[string]string
	if err := json.Unmarshal(redeem.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	old, _ := authenticateBearer("Bearer "+source, []byte(h.cfg.InternalSessionSecret))
	fresh, _ := authenticateBearer("Bearer "+session["token"], []byte(h.cfg.InternalSessionSecret))
	if old.SessionID == fresh.SessionID || old.Sub != fresh.Sub {
		t.Fatal("recipient must have distinct session reference for same subject")
	}
	if replay := sessionPost(t, h, "/auth/debug-login/redeem", "", fmt.Sprintf(`{"token":%q}`, grant["token"])); replay.Code != 401 {
		t.Fatalf("replay accepted %d", replay.Code)
	}
	if logout := sessionPost(t, h, "/auth/logout", source, ""); logout.Code != 204 {
		t.Fatalf("source logout %d", logout.Code)
	}
	if _, _, err := NewSessionManager(h.db, h.cfg).resolve(context.Background(), fresh.SessionID, fresh.Sub); err != nil {
		t.Fatalf("recipient lost after source logout: %v", err)
	}
}

func TestProfileOutageRetainsRotatedCapability(t *testing.T) {
	h, authority, token := sessionFixture(t)
	claims, _ := authenticateBearer("Bearer "+token, []byte(h.cfg.InternalSessionSecret))
	authority.profileFails = true
	manager := NewSessionManager(h.db, h.cfg)
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err == nil {
		t.Fatal("profile outage accepted")
	}
	var sealed []byte
	if err := h.db.Pool.QueryRow(context.Background(), "SELECT sealed_capability FROM uoa_sessions WHERE id::text=$1", claims.SessionID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	saved, err := manager.open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if saved == "source-refresh" || saved != authority.latest {
		t.Fatal("rotated capability was not saved before profile read")
	}
	authority.profileFails = false
	profile, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub)
	if err != nil || profile.DisplayName != "Current profile" {
		t.Fatalf("retry did not recover %v", err)
	}
}

func TestFailedLogoutRetainsClosingSessionForRetry(t *testing.T) {
	h, authority, token := sessionFixture(t)
	authority.revokeFails = true
	if response := sessionPost(t, h, "/auth/logout", token, ""); response.Code != 503 {
		t.Fatalf("failure %d", response.Code)
	}
	claims, _ := authenticateBearer("Bearer "+token, []byte(h.cfg.InternalSessionSecret))
	if _, _, err := NewSessionManager(h.db, h.cfg).resolve(context.Background(), claims.SessionID, claims.Sub); !errors.Is(err, errSessionClosing) {
		t.Fatalf("closing must remain retryable unavailable: %v", err)
	}
	authority.revokeFails = false
	if response := sessionPost(t, h, "/auth/logout", token, ""); response.Code != 204 {
		t.Fatalf("retry %d", response.Code)
	}
}

func TestBrokerRequiresCurrentCapabilityAndCapsExpiry(t *testing.T) {
	h, authority, _ := sessionFixture(t)
	h.cfg.InternalServiceKey = "broker-fixture-service-key"
	h.createBrokerFn = NewSessionManager(h.db, h.cfg).createBroker
	body := fmt.Sprintf(`{"uoaSub":%q,"capability":"approved-broker"}`, authority.subject)
	response := sessionPost(t, h, "/api/v1/internal/mint-session", h.cfg.InternalServiceKey, body)
	if response.Code != http.StatusOK {
		t.Fatalf("broker %d %s", response.Code, response.Body.String())
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	claims, reason := authenticateBearer("Bearer "+result.Token, []byte(h.cfg.InternalSessionSecret))
	if reason != "" || claims.SessionID == "" || result.ExpiresAt.After(time.Now().Add(5*time.Minute)) {
		t.Fatal("broker handle must be bounded and session-backed")
	}
	if claims.HasAudience(AudienceAdmin) || !claims.HasAudience(AudienceMobile) {
		t.Fatal("broker handle must retain mobile-only audience")
	}
	manager := NewSessionManager(h.db, h.cfg)
	authority.brokerUnavailable = true
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err == nil {
		t.Fatal("authority outage accepted")
	}
	authority.brokerUnavailable = false
	authority.brokerRefused = true
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err == nil {
		t.Fatal("revoked delegation accepted")
	}
	authority.brokerRefused = false
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatalf("outage discarded bounded handle: %v", err)
	}
	mismatch := sessionPost(t, h, "/api/v1/internal/mint-session", h.cfg.InternalServiceKey, `{"uoaSub":"other-subject","capability":"approved-broker"}`)
	if mismatch.Code != http.StatusUnauthorized {
		t.Fatalf("caller subject trusted %d", mismatch.Code)
	}
	old := sessionPost(t, h, "/api/v1/internal/mint-session", h.cfg.InternalServiceKey, fmt.Sprintf(`{"uoaSub":%q,"email":"copied@example.com","displayName":"Copied"}`, authority.subject))
	if old.Code != http.StatusBadRequest {
		t.Fatal("retired caller profile accepted")
	}
}

func TestDebugRelayLimitsBeforeSessionOrDatabase(t *testing.T) {
	h := NewCallbackHandler(nil, config.Config{}, nil, zap.NewNop(), fakeLimiter{decision: ratelimit.Decision{Allowed: false, RetryAfter: time.Minute}})
	for _, path := range []string{"/auth/debug-login/issue", "/auth/debug-login/redeem"} {
		response := sessionPost(t, h, path, "", "{}")
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("%s limiter did not run first: %d", path, response.Code)
		}
	}
	h.limiter = nil
	if response := sessionPost(t, h, "/auth/debug-login/redeem", "", "{}"); response.Code != http.StatusServiceUnavailable {
		t.Fatal("limiter outage did not fail closed")
	}
}

func TestBoundedCacheHonorsDatabaseLifecycleAndOtherInstanceRotation(t *testing.T) {
	h, authority, token := sessionFixture(t)
	claims, _ := authenticateBearer("Bearer "+token, []byte(h.cfg.InternalSessionSecret))
	manager := h.sessions
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if authority.generation != 1 || authority.profileReads != 1 {
		t.Fatalf("burst made %d rotations and %d profile reads", authority.generation, authority.profileReads)
	}
	other := NewSessionManager(h.db, h.cfg)
	if _, _, err := other.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatal(err)
	}
	if authority.generation != 3 {
		t.Fatal("other-instance ciphertext did not invalidate cache")
	}
	manager.cache.mu.Lock()
	entry := manager.cache.entries[claims.SessionID]
	entry.expires = time.Now().Add(-time.Second)
	manager.cache.entries[claims.SessionID] = entry
	manager.cache.mu.Unlock()
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatal(err)
	}
	if authority.generation != 4 {
		t.Fatal("expired authority cache did not refresh")
	}
	if _, err := h.db.Pool.Exec(context.Background(), "UPDATE uoa_sessions SET closing=true WHERE id::text=$1", claims.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); !errors.Is(err, errSessionClosing) {
		t.Fatal("warm cache bypassed closing")
	}
	if _, err := h.db.Pool.Exec(context.Background(), "UPDATE uoa_sessions SET closing=false WHERE id::text=$1", claims.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(context.Background(), "UPDATE users SET status='disabled' WHERE id::text=$1", claims.Sub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.resolve(context.Background(), claims.SessionID, claims.Sub); !errors.Is(err, errSessionExpired) {
		t.Fatal("warm cache bypassed product suspension")
	}
}

func TestMiddlewareWithoutAuthorityValidatorFailsClosed(t *testing.T) {
	h, _, token := sessionFixture(t)
	router := chi.NewRouter()
	router.Use(Middleware(h.cfg, nil, nil))
	router.Get("/protected", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("missing authority validator allowed request")
	}
}

func TestRenewInvalidatesPreviouslyDisplayedCode(t *testing.T) {
	h, _, source := sessionFixture(t)
	first := sessionPost(t, h, "/auth/debug-login/issue", source, "{}")
	var old map[string]string
	if err := json.Unmarshal(first.Body.Bytes(), &old); err != nil {
		t.Fatal(err)
	}
	renewed := sessionPost(t, h, "/auth/debug-login/issue", source, fmt.Sprintf(`{"previous_token":%q}`, old["token"]))
	var fresh map[string]string
	if err := json.Unmarshal(renewed.Body.Bytes(), &fresh); err != nil {
		t.Fatal(err)
	}
	if old["token"] == fresh["token"] {
		t.Fatal("renew reused code")
	}
	if response := sessionPost(t, h, "/auth/debug-login/redeem", "", fmt.Sprintf(`{"token":%q}`, old["token"])); response.Code != http.StatusUnauthorized {
		t.Fatal("renewed old code remained usable")
	}
	if response := sessionPost(t, h, "/auth/debug-login/redeem", "", fmt.Sprintf(`{"token":%q}`, fresh["token"])); response.Code != http.StatusOK {
		t.Fatal("renewed code unusable")
	}
}

func TestRequestCancellationDoesNotDiscardRefreshSuccessor(t *testing.T) {
	h, authority, token := sessionFixture(t)
	claims, _ := authenticateBearer("Bearer "+token, []byte(h.cfg.InternalSessionSecret))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authority.cancelOnRefresh = cancel
	if _, _, err := h.sessions.resolve(ctx, claims.SessionID, claims.Sub); err == nil {
		t.Fatal("canceled request completed profile action")
	}
	var sealed []byte
	if err := h.db.Pool.QueryRow(context.Background(), "SELECT sealed_capability FROM uoa_sessions WHERE id::text=$1", claims.SessionID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	saved, err := h.sessions.open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if saved == "source-refresh" || saved != authority.latest {
		t.Fatal("browser cancellation discarded rotated successor")
	}
	authority.cancelOnRefresh = nil
	if _, _, err := h.sessions.resolve(context.Background(), claims.SessionID, claims.Sub); err != nil {
		t.Fatalf("successor could not recover: %v", err)
	}
}
