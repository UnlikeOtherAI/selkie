package admin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/admin"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/store"
)

const testSecret = "test-session-secret-256-bits-long!"

func mintToken(t *testing.T, sub string, isSuper bool) string {
	t.Helper()

	claims := &struct {
		IsSuper bool `json:"is_super"`
		jwt.RegisteredClaims
	}{
		IsSuper: isSuper,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	return signed
}

func setupRouter(t *testing.T) chi.Router {
	t.Helper()

	cfg := config.Config{InternalSessionSecret: testSecret}
	db := &store.DB{}
	h := admin.New(db, nil, cfg)

	r := chi.NewRouter()
	h.Mount(r)

	return r
}

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, want, rr.Body.String())
	}
}

// --- Auth rejection (401) ---

func TestAudit_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestSystemInfo_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestAudit_BadToken(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestSystemInfo_BadToken(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

// --- Super-user gate (403) ---

func TestAudit_NonSuperUser(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-regular", false))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestSystemInfo_NonSuperUser(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-regular", false))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusForbidden)
}

// --- Verify super-user passes the gate (reaches DB, which is nil, so panics → we recover) ---

func TestAudit_SuperUserReachesDB(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "admin-user", true))
	rr := httptest.NewRecorder()

	// With a nil DB pool, the handler will panic when it tries to query.
	// A panic here proves the request passed auth + super-user gates.
	defer func() {
		if rec := recover(); rec == nil {
			// If no panic, the handler returned a response — check it's not 401/403.
			if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
				t.Errorf("super-user request was blocked: status %d", rr.Code)
			}
		}
		// Panic recovered = auth + authz gates passed, DB was reached. Success.
	}()

	r.ServeHTTP(rr, req)
}

func TestSystemInfo_SuperUserReachesDB(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "admin-user", true))
	rr := httptest.NewRecorder()

	defer func() {
		if rec := recover(); rec == nil {
			if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
				t.Errorf("super-user request was blocked: status %d", rr.Code)
			}
		}
	}()

	r.ServeHTTP(rr, req)
}

// --- Route wiring ---

func TestAdminRedirect(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}

	if loc := rr.Header().Get("Location"); loc != "/admin" {
		t.Errorf("redirect location = %q, want /admin", loc)
	}
}
