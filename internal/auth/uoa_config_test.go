package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
)

// testRSAKeyPEM returns a fresh RSA private key as PKCS#8 PEM plus the public
// key, for exercising the RS256 config-JWT signing path.
func testRSAKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(pemBytes), &key.PublicKey
}

func TestServeUOAConfig(t *testing.T) {
	keyPEM, pub := testRSAKeyPEM(t)
	h := auth.NewCallbackHandler(nil, config.Config{
		UOAConfigURL:           "https://api.selkie.live/auth/uoa-config",
		UOADomain:              "admin.selkie.live",
		UOARedirectURL:         "https://admin.selkie.live/auth/callback",
		UOAMobileRedirectURL:   "https://api.selkie.live/auth/mobile/callback",
		UOAConfigSigningKeyPEM: keyPEM,
		UOAConfigSigningKID:    "selkie-test",
		UOAContactEmail:        "ops@selkie.live",
	}, nil, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/uoa-config", nil)
	h.ServeUOAConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/jwt" {
		t.Fatalf("content-type = %q, want application/jwt", got)
	}

	tokenString := strings.TrimSpace(rr.Body.String())
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("token is invalid")
	}
	if got := token.Header["kid"]; got != "selkie-test" {
		t.Fatalf("kid = %#v, want selkie-test", got)
	}
	if got := claims["domain"]; got != "api.selkie.live" {
		t.Fatalf("domain = %#v", got)
	}
	if got := claims["jwks_url"]; got != "https://api.selkie.live/.well-known/jwks.json" {
		t.Fatalf("jwks_url = %#v", got)
	}
	if got := claims["contact_email"]; got != "ops@selkie.live" {
		t.Fatalf("contact_email = %#v", got)
	}
	redirectURLs, ok := claims["redirect_urls"].([]any)
	if !ok || len(redirectURLs) != 2 || redirectURLs[0] != "https://admin.selkie.live/auth/callback" || redirectURLs[1] != "https://api.selkie.live/auth/mobile/callback" {
		t.Fatalf("redirect_urls = %#v", claims["redirect_urls"])
	}
	methods, ok := claims["enabled_auth_methods"].([]any)
	if !ok || len(methods) != 3 || methods[0] != "email_password" {
		t.Fatalf("enabled_auth_methods = %#v", claims["enabled_auth_methods"])
	}
}

func TestServeJWKS(t *testing.T) {
	keyPEM, pub := testRSAKeyPEM(t)
	h := auth.NewCallbackHandler(nil, config.Config{
		UOAConfigSigningKeyPEM: keyPEM,
		UOAConfigSigningKID:    "selkie-test",
	}, nil, nil, nil)

	rr := httptest.NewRecorder()
	h.ServeJWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["kid"] != "selkie-test" {
		t.Fatalf("jwk header = %#v", k)
	}
	// The published modulus must match the signing key's modulus.
	wantN := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	if k["n"] != wantN {
		t.Fatalf("jwk modulus mismatch")
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

func TestBuildAuthURLIncludesPKCE(t *testing.T) {
	t.Setenv("DEV_MODE", "true") // config.Load() panics if TRUSTED_PROXY_CIDRS empty in non-dev
	t.Setenv("UOA_BASE_URL", "https://authentication.unlikeotherai.com")
	t.Setenv("UOA_CONFIG_URL", "https://api.selkie.live/auth/uoa-config")
	t.Setenv("UOA_REDIRECT_URL", "https://admin.selkie.live/auth/callback")

	got := auth.BuildAuthURL("the-challenge")
	if !strings.HasPrefix(got, "https://authentication.unlikeotherai.com/auth?") {
		t.Fatalf("auth url uses wrong path: %s", got)
	}
	for _, want := range []string{
		"config_url=https%3A%2F%2Fapi.selkie.live%2Fauth%2Fuoa-config",
		"redirect_url=https%3A%2F%2Fadmin.selkie.live%2Fauth%2Fcallback",
		"code_challenge=the-challenge",
		"code_challenge_method=S256",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("auth url missing %q: %s", want, got)
		}
	}
}

func TestExchangeCodeUsesDocumentedAuthTokenContract(t *testing.T) {
	sharedSecret := "client-secret"
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
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]string
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		if reqBody["code"] != "auth-code" {
			t.Fatalf("code = %q", reqBody["code"])
		}
		if reqBody["redirect_url"] != "https://admin.selkie.live/auth/callback" {
			t.Fatalf("redirect_url = %q", reqBody["redirect_url"])
		}
		if reqBody["code_verifier"] != "the-verifier" {
			t.Fatalf("code_verifier = %q", reqBody["code_verifier"])
		}

		// UOA signs access tokens with its own HS256 secret which RPs do not
		// hold; selkie must decode (not verify) it. Sign with an unrelated
		// secret to prove no verification happens.
		accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.UOAClaims{
			Email:       "user@example.com",
			DisplayName: "Example User",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "uoa-sub-123",
				Audience:  jwt.ClaimStrings{"uoa:access-token"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
		}).SignedString([]byte("a-secret-the-rp-does-not-know"))
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

	claims, err := auth.ExchangeCode(context.Background(), "auth-code", "https://admin.selkie.live/auth/callback", "the-verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if claims.Subject != "uoa-sub-123" {
		t.Fatalf("subject = %q, want uoa-sub-123", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", claims.Email)
	}
	if claims.DisplayName != "Example User" {
		t.Fatalf("display_name = %q, want Example User", claims.DisplayName)
	}
}

func TestServeUOAConfigPayloadShape(t *testing.T) {
	keyPEM, _ := testRSAKeyPEM(t)
	h := auth.NewCallbackHandler(nil, config.Config{
		UOAConfigURL:           "https://api.selkie.live/auth/uoa-config",
		UOARedirectURL:         "https://admin.selkie.live/auth/callback",
		UOAConfigSigningKeyPEM: keyPEM,
		UOAContactEmail:        "ops@selkie.live",
	}, nil, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/uoa-config", nil)
	h.ServeUOAConfig(rr, req)

	parts := strings.Split(strings.TrimSpace(rr.Body.String()), ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d, want 3", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var head map[string]any
	if headErr := json.Unmarshal(header, &head); headErr != nil {
		t.Fatalf("unmarshal header: %v", headErr)
	}
	if head["alg"] != "RS256" {
		t.Fatalf("alg = %#v, want RS256", head["alg"])
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
	if body["jwks_url"] != "https://api.selkie.live/.well-known/jwks.json" {
		t.Fatalf("jwks_url = %#v", body["jwks_url"])
	}
}
