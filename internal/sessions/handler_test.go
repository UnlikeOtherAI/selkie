package sessions_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/sessions"
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
	// DB with nil Pool — tests that return before DB access work fine;
	// tests that would hit the DB are not included here.
	db := &store.DB{}
	h := sessions.New(db, nil, nil, cfg, nil)

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

func assertErrorBody(t *testing.T, rr *httptest.ResponseRecorder, wantMsg string) {
	t.Helper()

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v (raw: %s)", err, rr.Body.String())
	}

	if got := body["error"]; got != wantMsg {
		t.Errorf("error = %q, want %q", got, wantMsg)
	}
}

// --- Auth rejection tests (401) ---

func TestCreateSession_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCreateSession_BadToken(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCreateSession_WrongSigningKey(t *testing.T) {
	r := setupRouter(t)

	// Token signed with a different secret.
	claims := &jwt.RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-secret"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCreateSession_ExpiredToken(t *testing.T) {
	r := setupRouter(t)

	claims := &jwt.RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSecret))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCreateSession_EmptySubject(t *testing.T) {
	r := setupRouter(t)

	// Token with empty subject — auth middleware rejects it.
	claims := &jwt.RegisteredClaims{
		Subject:   "",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSecret))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestListSessions_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCandidates_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/some-id/candidates", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestRelay_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/some-id/relay", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestDeviceEvents_NoAuth(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/some-id/events", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

// --- Input validation tests (400) ---

func TestCreateSession_MissingFields(t *testing.T) {
	r := setupRouter(t)

	// Valid auth but missing required fields in body.
	body := `{"requester_device_id":"d1","target_device_id":"","target_service_id":"svc","requested_action":"connect"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-2", false))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr, "missing required fields")
}

func TestCreateSession_InvalidJSON(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString("{invalid"))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-3", false))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr, "invalid request body")
}

func TestCreateSession_UnknownFields(t *testing.T) {
	r := setupRouter(t)
	body := `{"requester_device_id":"d1","target_device_id":"d2","target_service_id":"svc","requested_action":"connect","extra":"field"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-4", false))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr, "invalid request body")
}

func TestCandidates_InvalidRole(t *testing.T) {
	r := setupRouter(t)
	body := `{"role":"attacker","candidates":[{"candidate":"c1"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/some-id/candidates", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-5", false))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr, "invalid role")
}

func TestCandidates_InvalidJSON(t *testing.T) {
	r := setupRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/some-id/candidates", bytes.NewBufferString("{bad"))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-6", false))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr, "invalid request body")
}

func TestRelay_NoCoturnSecret(t *testing.T) {
	// CoturnSecret is empty → 503 "relay not configured".
	cfg := config.Config{InternalSessionSecret: testSecret, CoturnSecret: ""}
	db := &store.DB{}
	h := sessions.New(db, nil, nil, cfg, nil)

	r := chi.NewRouter()
	h.Mount(r)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/some-id/relay", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-7", true))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// The handler checks claims first, then session ID, then coturn secret.
	// With a valid token and non-empty session ID, it should reach the coturn check.
	assertStatus(t, rr, http.StatusServiceUnavailable)
	assertErrorBody(t, rr, "relay not configured")
}

// --- Route wiring tests ---

func TestRoutes_MethodNotAllowed(t *testing.T) {
	r := setupRouter(t)

	// GET on a POST-only endpoint.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/some-id/candidates", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, "user-8", false))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed && rr.Code != http.StatusNotFound {
		t.Errorf("expected 405 or 404 for wrong method, got %d", rr.Code)
	}
}
