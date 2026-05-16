package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
)

const middlewareTestSecret = "test-session-secret-256-bits-long!"

// signClaims builds and signs a token from a free-form MapClaims. Callers can
// omit individual claims (iss, exp, aud) to exercise the negative paths.
func signClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(middlewareTestSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newProtectedRouter(extraMW ...func(http.Handler) http.Handler) http.Handler {
	r := chi.NewRouter()
	cfg := config.Config{InternalSessionSecret: middlewareTestSecret}
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(cfg, nil, nil))
		for _, mw := range extraMW {
			r.Use(mw)
		}
		r.Get("/protected", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	return r
}

func doRequest(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestMiddleware_RejectsMissingIssuer(t *testing.T) {
	h := newProtectedRouter()
	token := signClaims(t, jwt.MapClaims{
		"sub": "user-1",
		"aud": []string{"admin"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for token without iss", rr.Code)
	}
}

func TestMiddleware_RejectsWrongIssuer(t *testing.T) {
	h := newProtectedRouter()
	token := signClaims(t, jwt.MapClaims{
		"iss": "not-selkie",
		"sub": "user-1",
		"aud": []string{"admin"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong iss", rr.Code)
	}
}

func TestMiddleware_RejectsMissingExpiry(t *testing.T) {
	h := newProtectedRouter()
	token := signClaims(t, jwt.MapClaims{
		"iss": "selkie",
		"sub": "user-1",
		"aud": []string{"admin"},
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for token without exp", rr.Code)
	}
}

func TestMiddleware_RejectsUnknownAudience(t *testing.T) {
	h := newProtectedRouter()
	token := signClaims(t, jwt.MapClaims{
		"iss": "selkie",
		"sub": "user-1",
		"aud": []string{"other"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unknown audience", rr.Code)
	}
}

func TestRequireAudience_RejectsMobileTokenOnAdminGate(t *testing.T) {
	h := newProtectedRouter(auth.RequireAudience(auth.AudienceAdmin))
	token := signClaims(t, jwt.MapClaims{
		"iss": "selkie",
		"sub": "user-1",
		"aud": []string{"mobile"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for mobile-only token on admin route", rr.Code)
	}
}

func TestRequireAudience_AcceptsMatchingAudience(t *testing.T) {
	h := newProtectedRouter(auth.RequireAudience(auth.AudienceAdmin))
	token := signClaims(t, jwt.MapClaims{
		"iss": "selkie",
		"sub": "user-1",
		"aud": []string{"admin"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rr := doRequest(t, h, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for admin token on admin route", rr.Code)
	}
}
