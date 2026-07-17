//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

const testServiceKey = "svc-key-super-secret-value-123456"

// fakeUpserter records the UOA subs it is asked to upsert and hands back a
// deterministic user id per sub, so the mint-session handler can be exercised
// without a live database while still proving idempotency by sub.
type fakeUpserter struct {
	bySub   map[string]string
	creates map[string]int
	nextID  int
}

func newFakeUpserter() *fakeUpserter {
	return &fakeUpserter{bySub: map[string]string{}, creates: map[string]int{}}
}

func (f *fakeUpserter) upsert(_ context.Context, claims *UOAClaims) (string, bool, error) {
	sub := claims.Subject
	if id, ok := f.bySub[sub]; ok {
		return id, false, nil
	}
	f.nextID++
	id := "user-" + strconv.Itoa(f.nextID)
	f.bySub[sub] = id
	f.creates[sub]++
	return id, false, nil
}

func newMintSessionHandler(t *testing.T, key string, upserter *fakeUpserter) *CallbackHandler {
	t.Helper()
	cfg := config.Config{InternalSessionSecret: "test-secret", InternalServiceKey: key}
	h := NewCallbackHandler(nil, cfg, nil, zap.NewNop(), fakeLimiter{decision: ratelimit.Decision{Allowed: true}})
	if upserter != nil {
		h.upsertUserFn = upserter.upsert
	}
	return h
}

func postMintSession(t *testing.T, h *CallbackHandler, authHeader, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	h.Mount(router)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/mint-session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestInternalMintSession_DisabledWhenUnconfigured(t *testing.T) {
	h := newMintSessionHandler(t, "", nil)
	rec := postMintSession(t, h, "Bearer anything", `{"uoaSub":"sub-1","email":"a@example.com"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestInternalMintSession_MissingKeyUnauthorized(t *testing.T) {
	h := newMintSessionHandler(t, testServiceKey, nil)
	rec := postMintSession(t, h, "", `{"uoaSub":"sub-1","email":"a@example.com"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestInternalMintSession_WrongKeyUnauthorized(t *testing.T) {
	h := newMintSessionHandler(t, testServiceKey, nil)
	rec := postMintSession(t, h, "Bearer wrong-key", `{"uoaSub":"sub-1","email":"a@example.com"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestInternalMintSession_MissingFields(t *testing.T) {
	h := newMintSessionHandler(t, testServiceKey, newFakeUpserter())
	for _, body := range []string{
		`{"email":"a@example.com"}`,
		`{"uoaSub":"  ","email":"a@example.com"}`,
		`{"uoaSub":"sub-1"}`,
		`{"uoaSub":"sub-1","email":"  "}`,
	} {
		rec := postMintSession(t, h, "Bearer "+testServiceKey, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

// TestInternalMintSession_MintsMobileTokenThatPassesMiddleware is the core
// happy-path test: a valid service-key call mints a mobile-audience session JWT
// that selkie's OWN middleware accepts for a mobile-only route.
func TestInternalMintSession_MintsMobileTokenThatPassesMiddleware(t *testing.T) {
	upserter := newFakeUpserter()
	h := newMintSessionHandler(t, testServiceKey, upserter)

	rec := postMintSession(t, h, "Bearer "+testServiceKey, `{"uoaSub":"sub-abc","email":"a@example.com","displayName":"Ada"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected a non-empty token")
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected expires_at to be set")
	}

	// The minted token must pass selkie's own auth stack for a mobile route.
	protected := chi.NewRouter()
	protected.Group(func(r chi.Router) {
		r.Use(Middleware(h.cfg, nil, nil))
		r.Use(RequireAudience(AudienceMobile))
		r.Get("/api/v1/mobile/ping", func(w http.ResponseWriter, req *http.Request) {
			claims, _ := ClaimsFromContext(req.Context())
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(claims.Sub))
		})
	})
	mreq := httptest.NewRequest(http.MethodGet, "/api/v1/mobile/ping", nil)
	mreq.Header.Set("Authorization", "Bearer "+resp.Token)
	mrec := httptest.NewRecorder()
	protected.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("minted token rejected by middleware: status = %d, body=%s", mrec.Code, mrec.Body.String())
	}
	if got := mrec.Body.String(); got != upserter.bySub["sub-abc"] {
		t.Fatalf("token subject = %q, want the upserted user id %q", got, upserter.bySub["sub-abc"])
	}
}

// TestInternalMintSession_UpsertIdempotentBySub confirms the broker keys the
// user on the UOA sub: two calls with the same sub resolve to the same user id
// and only ever create the row once.
func TestInternalMintSession_UpsertIdempotentBySub(t *testing.T) {
	upserter := newFakeUpserter()
	h := newMintSessionHandler(t, testServiceKey, upserter)

	body := `{"uoaSub":"sub-dup","email":"dup@example.com"}`
	rec1 := postMintSession(t, h, "Bearer "+testServiceKey, body)
	rec2 := postMintSession(t, h, "Bearer "+testServiceKey, body)
	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Fatalf("statuses = %d, %d, want 200, 200", rec1.Code, rec2.Code)
	}
	if upserter.creates["sub-dup"] != 1 {
		t.Fatalf("sub upserted %d times, want 1 (idempotent by sub)", upserter.creates["sub-dup"])
	}
	if len(upserter.bySub) != 1 {
		t.Fatalf("distinct users = %d, want 1", len(upserter.bySub))
	}
}
