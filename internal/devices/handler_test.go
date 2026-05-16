//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package devices

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

type fakeLimiter struct {
	decision ratelimit.Decision
	peek     ratelimit.Decision
	hit      ratelimit.Decision
	err      error
}

func (f fakeLimiter) Allow(_ context.Context, _ string, _ int64, _ time.Duration) (ratelimit.Decision, error) {
	return f.decision, f.err
}

func (f fakeLimiter) Peek(_ context.Context, _ string) (ratelimit.Decision, error) {
	return f.peek, f.err
}

func (f fakeLimiter) Hit(_ context.Context, _ string, _ time.Duration) (ratelimit.Decision, error) {
	return f.hit, f.err
}

func TestHandleHeartbeatRateLimited(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: false, RetryAfter: 3 * time.Second},
	})

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/device-1/heartbeat", strings.NewReader(`{"external_endpoint_host":"198.51.100.7","external_endpoint_port":51820,"agent_version":"0.1.0","disk_free_bytes":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-1"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want 3", got)
	}
}

func TestHandlePairStartRateLimited(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: false, RetryAfter: 4 * time.Second},
	})

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/pair/start", strings.NewReader(`{"wg_public_key":"pub","hostname":"mbp","os_platform":"darwin","os_arch":"arm64","agent_version":"0.1.0"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-1"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "4" {
		t.Fatalf("Retry-After = %q, want 4", got)
	}
}

func TestHandlePairClaimLockedOut(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		peek: ratelimit.Decision{Count: pairClaimFailureLimit, RetryAfter: 15 * time.Minute},
	})

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/pair/claim", strings.NewReader(`{"code":"ABC123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-1"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "900" {
		t.Fatalf("Retry-After = %q, want 900", got)
	}
}

func signedToken(t *testing.T, secret, subject string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": subject,
		"iss": "selkie",
		"aud": []string{"admin"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestHeartbeatRequestAllowsOmittedOptionalFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/device-1/heartbeat", strings.NewReader(`{"agent_version":"0.1.0"}`))

	var body heartbeatRequest
	if err := decodeJSON(req, &body); err != nil {
		t.Fatalf("decode heartbeat: %v", err)
	}
	if body.AgentVersion == nil || *body.AgentVersion != "0.1.0" {
		t.Fatalf("agent_version = %#v, want 0.1.0", body.AgentVersion)
	}
	if body.ExternalEndpointHost != nil {
		t.Fatalf("external_endpoint_host = %#v, want nil", body.ExternalEndpointHost)
	}
	if body.ExternalEndpointPort != nil {
		t.Fatalf("external_endpoint_port = %#v, want nil", body.ExternalEndpointPort)
	}
	if body.DiskFreeBytes != nil {
		t.Fatalf("disk_free_bytes = %#v, want nil", body.DiskFreeBytes)
	}
}
