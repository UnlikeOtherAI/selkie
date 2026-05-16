package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
)

func TestServeUOAConfig(t *testing.T) {
	h := auth.NewCallbackHandler(nil, config.Config{
		UOAConfigURL:         "https://api.selkie.live/auth/uoa-config",
		UOADomain:            "admin.selkie.live",
		UOARedirectURL:       "https://admin.selkie.live/auth/callback",
		UOAMobileRedirectURL: "https://api.selkie.live/auth/mobile/callback",
		UOAAudience:          "authentication.unlikeotherai.com",
		UOASharedSecret:      "shared-secret",
	}, nil, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/uoa-config", nil)
	h.ServeUOAConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content-type = %q, want text/plain", got)
	}

	tokenString := strings.TrimSpace(rr.Body.String())
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (any, error) {
		return []byte("shared-secret"), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("token is invalid")
	}
	if got := claims["domain"]; got != "api.selkie.live" {
		t.Fatalf("domain = %#v", got)
	}
	redirectURLs, ok := claims["redirect_urls"].([]any)
	if !ok || len(redirectURLs) != 2 || redirectURLs[0] != "https://admin.selkie.live/auth/callback" || redirectURLs[1] != "https://api.selkie.live/auth/mobile/callback" {
		t.Fatalf("redirect_urls = %#v", claims["redirect_urls"])
	}
	methods, ok := claims["enabled_auth_methods"].([]any)
	if !ok || len(methods) != 3 || methods[0] != "email_password" {
		t.Fatalf("enabled_auth_methods = %#v", claims["enabled_auth_methods"])
	}
	allowed, ok := claims["allowed_social_providers"].([]any)
	if !ok || len(allowed) != 2 || allowed[0] != "google" || allowed[1] != "apple" {
		t.Fatalf("allowed_social_providers = %#v", claims["allowed_social_providers"])
	}
	if audience, ok := claims["aud"].(string); !ok || audience != "authentication.unlikeotherai.com" {
		t.Fatalf("audience = %#v", claims["aud"])
	}
}

func TestServeUOAConfigIncomplete(t *testing.T) {
	h := auth.NewCallbackHandler(nil, config.Config{}, nil, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/uoa-config", nil)
	h.ServeUOAConfig(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestBuildAuthURLUsesConfigURL(t *testing.T) {
	t.Setenv("DEV_MODE", "true") // config.Load() panics if TRUSTED_PROXY_CIDRS empty in non-dev
	t.Setenv("UOA_BASE_URL", "https://authentication.unlikeotherai.com")
	t.Setenv("UOA_CONFIG_URL", "https://api.selkie.live/auth/uoa-config")
	t.Setenv("UOA_REDIRECT_URL", "https://admin.selkie.live/auth/callback")

	got := auth.BuildAuthURL()
	if !strings.HasPrefix(got, "https://authentication.unlikeotherai.com/auth?") {
		t.Fatalf("auth url uses wrong path: %s", got)
	}
	if !strings.Contains(got, "config_url=https%3A%2F%2Fapi.selkie.live%2Fauth%2Fuoa-config") {
		t.Fatalf("auth url missing config_url: %s", got)
	}
	if !strings.Contains(got, "redirect_url=https%3A%2F%2Fadmin.selkie.live%2Fauth%2Fcallback") {
		t.Fatalf("auth url missing redirect_url: %s", got)
	}
}

func TestExchangeCodeUsesDocumentedAuthTokenContract(t *testing.T) {
	sharedSecret := "shared-secret"
	configURL := "https://api.selkie.live/auth/uoa-config"
	sum := sha256.Sum256([]byte("api.selkie.live" + sharedSecret))
	expectedAuthorization := "Bearer " + hex.EncodeToString(sum[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token" {
			t.Fatalf("path = %q, want /auth/token", r.URL.Path)
		}
		if got := r.URL.Query().Get("config_url"); got != configURL {
			t.Fatalf("config_url = %q, want %q", got, configURL)
		}
		if got := r.Header.Get("Authorization"); got != expectedAuthorization {
			t.Fatalf("authorization = %q, want %q", got, expectedAuthorization)
		}

		accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.UOAClaims{
			Email:       "user@example.com",
			DisplayName: "Example User",
			RegisteredClaims: jwt.RegisteredClaims{
				Audience:  jwt.ClaimStrings{"authentication.unlikeotherai.com"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
		}).SignedString([]byte(sharedSecret))
		if err != nil {
			t.Fatalf("sign access token: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + accessToken + `"}`))
	}))
	defer server.Close()

	t.Setenv("DEV_MODE", "true") // config.Load() panics if TRUSTED_PROXY_CIDRS empty in non-dev
	t.Setenv("UOA_BASE_URL", server.URL)
	t.Setenv("UOA_CONFIG_URL", configURL)
	t.Setenv("UOA_DOMAIN", "admin.selkie.live")
	t.Setenv("UOA_SHARED_SECRET", sharedSecret)
	t.Setenv("UOA_AUDIENCE", "authentication.unlikeotherai.com")

	claims, err := auth.ExchangeCode(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", claims.Email)
	}
	if claims.DisplayName != "Example User" {
		t.Fatalf("display_name = %q, want Example User", claims.DisplayName)
	}
}

func TestServeUOAConfigPayloadShape(t *testing.T) {
	h := auth.NewCallbackHandler(nil, config.Config{
		UOAConfigURL:    "https://api.selkie.live/auth/uoa-config",
		UOARedirectURL:  "https://admin.selkie.live/auth/callback",
		UOAAudience:     "authentication.unlikeotherai.com",
		UOASharedSecret: "shared-secret",
	}, nil, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/uoa-config", nil)
	h.ServeUOAConfig(rr, req)

	parts := strings.Split(strings.TrimSpace(rr.Body.String()), ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body["user_scope"] != "global" {
		t.Fatalf("user_scope = %#v", body["user_scope"])
	}
	uiTheme, ok := body["ui_theme"].(map[string]any)
	if !ok {
		t.Fatalf("ui_theme = %#v", body["ui_theme"])
	}
	typography, ok := uiTheme["typography"].(map[string]any)
	if !ok || typography["font_family"] != "sans" || typography["base_text_size"] != "md" {
		t.Fatalf("typography = %#v", uiTheme["typography"])
	}
	logo, ok := uiTheme["logo"].(map[string]any)
	if !ok || logo["alt"] != "Selkie logo" || logo["text"] != "Selkie" {
		t.Fatalf("logo = %#v", uiTheme["logo"])
	}
	if audience, ok := body["aud"].(string); !ok || audience != "authentication.unlikeotherai.com" {
		t.Fatalf("aud = %#v", body["aud"])
	}
}
