//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
)

type fakeLimiter struct {
	decision ratelimit.Decision
	err      error
}

func (f fakeLimiter) Allow(_ context.Context, _ string, _ int64, _ time.Duration) (ratelimit.Decision, error) {
	return f.decision, f.err
}

func TestMobileRedirectURLIncludesHandoffCodeAndState(t *testing.T) {
	got, err := mobileRedirectURL("selkie://auth", "handoff-123", "state-abc")
	if err != nil {
		t.Fatalf("mobileRedirectURL: %v", err)
	}
	want := "selkie://auth?handoff_code=handoff-123&state=state-abc"
	if got != want {
		t.Fatalf("redirect url = %q, want %q", got, want)
	}
}

func TestMobileRedirectURLErrorsWithoutBaseURL(t *testing.T) {
	if _, err := mobileRedirectURL("", "handoff-123", ""); err == nil {
		t.Fatal("expected error for empty mobile redirect url")
	}
}

func TestServeCallbackRequiresPKCEVerifier(t *testing.T) {
	h := &CallbackHandler{cfg: config.Config{InternalSessionSecret: "secret"}, logger: zap.NewNop()}

	// No PKCE verifier cookie => the callback must reject before any exchange.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil)
	rec := httptest.NewRecorder()
	h.ServeCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "missing or expired login session") {
		t.Fatalf("body = %q, want missing/expired login session", rec.Body.String())
	}
}

func TestMintTokenRequiresAudience(t *testing.T) {
	h := &CallbackHandler{cfg: config.Config{InternalSessionSecret: "secret"}}

	if _, err := h.mintToken("u", false, "", "", "", nil); err == nil {
		t.Fatal("expected error for missing audience")
	}

	signed, err := h.mintToken("u-1", false, "", "", "", []string{AudienceAdmin})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	parsed := jwtClaims{}
	_, err = jwt.ParseWithClaims(signed, &parsed, func(_ *jwt.Token) (any, error) {
		return []byte("secret"), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(AudienceAdmin),
	)
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
}

func TestServeCallback_VerifierClearedEvenOnExchangeFailure(t *testing.T) {
	h := &CallbackHandler{cfg: config.Config{InternalSessionSecret: "secret"}, logger: zap.NewNop()}

	// Valid PKCE verifier cookie but no `code` query param: exchangeAndUpsertUser
	// returns errMissingCode before any upstream call, and the verifier cookie
	// must still be cleared so it cannot be replayed.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req.AddCookie(&http.Cookie{Name: pkceVerifierCookieName, Value: "test-verifier"})
	rec := httptest.NewRecorder()

	h.ServeCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "missing code") {
		t.Fatalf("body = %q, want missing code", rec.Body.String())
	}

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name != pkceVerifierCookieName {
			continue
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected PKCE verifier cookie to be cleared even when exchange fails")
	}
}

func TestServeMobileHandoffExchangeRateLimited(t *testing.T) {
	h := NewCallbackHandler(nil, config.Config{}, nil, zap.NewNop(), fakeLimiter{
		decision: ratelimit.Decision{Allowed: false, RetryAfter: 5 * time.Second},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/handoff/exchange", strings.NewReader(`{"handoff_code":"abc123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeMobileHandoffExchange(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want 5", got)
	}
	if !strings.Contains(rec.Body.String(), "rate limit exceeded") {
		t.Fatalf("body = %q, want rate limit message", rec.Body.String())
	}
}
