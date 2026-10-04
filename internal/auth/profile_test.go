//nolint:testpackage // Tests verify private bounded-cache expiry and exact UOA response handling.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
)

func TestProfileExactSubjectCacheAndExpiryFailClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	var refused atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/domain/users" || r.URL.Query().Get("user_id") != "uoa-sub" || r.URL.Query().Get("domain") != "selkie.test" || r.Header.Get("Authorization") != "Bearer "+uoaAuthorizationToken("selkie.test", "per-domain-secret") {
			t.Error("profile request was not exact authenticated subject/domain")
		}
		if refused.Load() {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]string{{"id": "uoa-sub", "email": "current@example.com", "name": "Current UOA Name"}}})
	}))
	defer server.Close()
	h := NewCallbackHandler(nil, config.Config{DevMode: true, UOABaseURL: server.URL, UOADomain: "selkie.test", UOASharedSecret: "per-domain-secret"}, nil, nil, nil)
	first, err := h.profile(t.Context(), "uoa-sub")
	if err != nil || first.DisplayName != "Current UOA Name" {
		t.Fatalf("current profile unavailable: %v", err)
	}
	if _, cacheErr := h.profile(t.Context(), "uoa-sub"); cacheErr != nil || calls.Load() != 1 {
		t.Fatal("bounded memory cache not used")
	}
	h.profiles.mu.Lock()
	item := h.profiles.values["uoa-sub"]
	item.expires = time.Now().Add(-time.Second)
	h.profiles.values["uoa-sub"] = item
	h.profiles.mu.Unlock()
	refused.Store(true)
	stale, err := h.profile(t.Context(), "uoa-sub")
	if err == nil || stale.DisplayName != "" || calls.Load() != 2 {
		t.Fatal("expired profile fell back to copied data after UOA refusal")
	}
}

func TestProfileRejectsOtherSubjectAndRedirect(t *testing.T) {
	t.Parallel()
	for _, redirect := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirect {
				http.Redirect(w, r, "/other", http.StatusFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]string{{"id": "another-subject", "name": "Other"}}})
		}))
		h := NewCallbackHandler(nil, config.Config{DevMode: true, UOABaseURL: server.URL, UOADomain: "selkie.test", UOASharedSecret: "per-domain-secret"}, nil, nil, nil)
		_, err := h.profile(context.Background(), "uoa-sub")
		server.Close()
		if err == nil {
			t.Fatal("other subject or redirect accepted")
		}
	}
}

func TestReferenceSessionRemovesPersistedProfilesAndPreservesExpiry(t *testing.T) {
	t.Parallel()
	secret := "test-session-signing-secret"
	expires := time.Now().Add(time.Hour).Unix()
	old := jwt.MapClaims{"iss": Issuer, "sub": "local-reference", "aud": []string{AudienceAdmin}, "exp": expires, "iat": time.Now().Unix(), "email": "copied@example.com", "display_name": "Copied", "picture": "https://copied.test/image"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, old).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	h := NewCallbackHandler(nil, config.Config{InternalSessionSecret: secret}, nil, nil, nil)
	router := chi.NewRouter()
	h.Mount(router)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session migration status %d", response.Code)
	}
	var result map[string]string
	if decodeErr := json.Unmarshal(response.Body.Bytes(), &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	clean := jwt.MapClaims{}
	if _, _, parseErr := jwt.NewParser().ParseUnverified(result[responseTokenField], clean); parseErr != nil {
		t.Fatal(parseErr)
	}
	for _, field := range []string{"email", "display_name", "picture"} {
		if _, exists := clean[field]; exists {
			t.Fatal("profile persisted in replacement JWT")
		}
	}
	if int64(clean["exp"].(float64)) != expires {
		t.Fatal("migration extended authorization")
	}
	mobile, err := h.mintToken("local-reference", false, []string{AudienceMobile})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/auth/session", "/api/v1/auth/profile"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+mobile)
		denied := httptest.NewRecorder()
		router.ServeHTTP(denied, request)
		if denied.Code != http.StatusUnauthorized {
			t.Fatalf("mobile accessed profile/session: %d", denied.Code)
		}
	}
}
