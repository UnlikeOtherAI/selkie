//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package mobile

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
	err      error
}

func (f fakeLimiter) Allow(_ context.Context, _ string, _ int64, _ time.Duration) (ratelimit.Decision, error) {
	return f.decision, f.err
}

func TestRenderMobileWGConfig(t *testing.T) {
	h := &Handler{cfg: config.Config{
		WGOverlayCIDR:     "10.100.0.0/16",
		WGServerPublicKey: "server-public-key",
		WGServerEndpoint:  "relay.selkie.live",
		WGServerPort:      51820,
	}}

	got, err := h.renderMobileWGConfig("10.100.0.9")
	if err != nil {
		t.Fatalf("renderMobileWGConfig: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"Address = 10.100.0.9/32",
		"Endpoint = relay.selkie.live:51820",
		"AllowedIPs = 10.100.0.1/32",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("config missing %q:\n%s", want, got)
		}
	}
}

func TestHandleEnrollRateLimited(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: false, RetryAfter: 7 * time.Second},
	})

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", strings.NewReader(`{"hostname":"iphone","os_platform":"ios","os_arch":"arm64","app_version":"0.1.0","wg_public_key":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-1"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "7" {
		t.Fatalf("Retry-After = %q, want 7", got)
	}
}

func signedToken(t *testing.T, secret, subject string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": subject,
		"iss": "selkie",
		"aud": []string{"mobile"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}
