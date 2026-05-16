//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package auth

import (
	"context"
	"encoding/base64"
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

func TestIsWellFormedOAuthState(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, oauthStateByteLen))
	if !isWellFormedOAuthState(good) {
		t.Fatalf("expected base64 state of correct length to be accepted: %q", good)
	}
	if isWellFormedOAuthState("") {
		t.Fatal("empty state must be rejected")
	}
	if isWellFormedOAuthState("not-base64-or-hex") {
		t.Fatal("garbage state must be rejected")
	}
	short := base64.RawURLEncoding.EncodeToString(make([]byte, oauthStateByteLen-1))
	if isWellFormedOAuthState(short) {
		t.Fatal("short state must be rejected")
	}
}

func TestVerifyOAuthState(t *testing.T) {
	h := &CallbackHandler{}

	state := "round-trip-state"
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state, nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: state})
	rec := httptest.NewRecorder()
	if !h.verifyOAuthState(rec, req) {
		t.Fatalf("expected verifyOAuthState to accept matching cookie + state, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/callback?state=mismatch", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: state})
	rec = httptest.NewRecorder()
	if h.verifyOAuthState(rec, req) {
		t.Fatal("expected mismatched state to be rejected")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// On mismatch the cookie must be cleared so a future request cannot replay it.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected state cookie to be cleared on mismatch")
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state, nil)
	rec = httptest.NewRecorder()
	if h.verifyOAuthState(rec, req) {
		t.Fatal("expected missing cookie to be rejected")
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
