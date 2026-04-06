// Package integration_test verifies that our interfaces to third-party libraries
// produce correct results. These are compile-time and runtime sanity checks that
// our usage of chi, JWT, pgx, redis, and HMAC-SHA1 (coturn) is correct.
package integration_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"

	"github.com/unlikeotherai/selkie/internal/overlay"
)

// --- chi v5: route registration, URL params, middleware ---

func TestChi_RouteRegistrationAndURLParams(t *testing.T) {
	r := chi.NewRouter()

	var capturedID string
	r.Get("/api/v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		capturedID = chi.URLParam(r, "id")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/abc-123", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if capturedID != "abc-123" {
		t.Errorf("URL param id = %q, want %q", capturedID, "abc-123")
	}
}

func TestChi_MiddlewareOrdering(t *testing.T) {
	r := chi.NewRouter()

	var order []string

	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, "middleware")
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/test", func(w http.ResponseWriter, _ *http.Request) {
			order = append(order, "handler")
			w.WriteHeader(http.StatusOK)
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if len(order) != 2 || order[0] != "middleware" || order[1] != "handler" {
		t.Errorf("middleware ordering = %v, want [middleware handler]", order)
	}
}

func TestChi_GroupIsolation(t *testing.T) {
	r := chi.NewRouter()

	middlewareHit := false

	// Routes inside the group use the middleware.
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				middlewareHit = true
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/guarded", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	// Route outside the group does NOT use the middleware.
	r.Get("/open", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Hit the open route first — middleware should NOT fire.
	req := httptest.NewRequest(http.MethodGet, "/open", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if middlewareHit {
		t.Error("group middleware fired for route outside the group")
	}

	// Hit the guarded route — middleware SHOULD fire.
	req = httptest.NewRequest(http.MethodGet, "/guarded", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if !middlewareHit {
		t.Error("group middleware did not fire for guarded route")
	}
}

// --- golang-jwt v5: sign, parse, claims roundtrip ---

func TestJWT_SignAndParseRoundtrip(t *testing.T) {
	secret := []byte("test-jwt-secret-32-bytes-long!!!")

	type customClaims struct {
		IsSuper bool `json:"is_super"`
		jwt.RegisteredClaims
	}

	original := &customClaims{
		IsSuper: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, original)
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parsed := &customClaims{}
	tok, err := jwt.ParseWithClaims(signed, parsed, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !tok.Valid {
		t.Error("token is not valid")
	}

	if parsed.Subject != "user-42" {
		t.Errorf("subject = %q, want %q", parsed.Subject, "user-42")
	}

	if !parsed.IsSuper {
		t.Error("expected IsSuper to be true")
	}
}

func TestJWT_ExpiredTokenRejected(t *testing.T) {
	secret := []byte("test-jwt-secret-32-bytes-long!!!")

	claims := &jwt.RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString(secret)

	_, err := jwt.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWT_WrongSecretRejected(t *testing.T) {
	signSecret := []byte("sign-secret")
	verifySecret := []byte("different-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, _ := token.SignedString(signSecret)

	_, err := jwt.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return verifySecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

// --- pgx v5: connection string parsing ---

func TestPgx_ParseConfig(t *testing.T) {
	// Verify our typical DATABASE_URL format parses correctly.
	url := "postgres://user:pass@localhost:5432/selkie?sslmode=disable"
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if cfg.ConnConfig.Host != "localhost" {
		t.Errorf("host = %q, want %q", cfg.ConnConfig.Host, "localhost")
	}

	if cfg.ConnConfig.Port != 5432 {
		t.Errorf("port = %d, want %d", cfg.ConnConfig.Port, 5432)
	}

	if cfg.ConnConfig.Database != "selkie" {
		t.Errorf("database = %q, want %q", cfg.ConnConfig.Database, "selkie")
	}
}

func TestPgx_ParseConfigInvalidURL(t *testing.T) {
	_, err := pgxpool.ParseConfig("not-a-valid-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// --- go-redis v9: URL parsing and option creation ---

func TestRedis_ParseURL(t *testing.T) {
	opts, err := redis.ParseURL("redis://localhost:6379/0")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	if opts.Addr != "localhost:6379" {
		t.Errorf("addr = %q, want %q", opts.Addr, "localhost:6379")
	}

	if opts.DB != 0 {
		t.Errorf("db = %d, want 0", opts.DB)
	}
}

func TestRedis_ParseURLWithPassword(t *testing.T) {
	opts, err := redis.ParseURL("redis://:mysecret@redis.example.com:6380/2")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	if opts.Addr != "redis.example.com:6380" {
		t.Errorf("addr = %q, want %q", opts.Addr, "redis.example.com:6380")
	}

	if opts.Password != "mysecret" {
		t.Errorf("password = %q, want %q", opts.Password, "mysecret")
	}

	if opts.DB != 2 {
		t.Errorf("db = %d, want 2", opts.DB)
	}
}

func TestRedis_PubSubChannelNaming(t *testing.T) {
	// Verify our channel naming convention produces the expected format.
	deviceID := "d-abc-123"
	channel := fmt.Sprintf("selkie:device:%s:events", deviceID)

	if channel != "selkie:device:d-abc-123:events" {
		t.Errorf("channel = %q, unexpected format", channel)
	}
}

func TestRedis_SubscribeUnsubscribe(_ *testing.T) {
	// Verify PubSub lifecycle doesn't panic with a nil-context cancel.
	client := redis.NewClient(&redis.Options{Addr: "localhost:1"}) // won't connect
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	sub := client.Subscribe(ctx, "test-channel")
	_ = sub.Close()
}

// --- HMAC-SHA1: coturn ephemeral credential generation ---

func TestCoturnCredential_HMACSHA1(t *testing.T) {
	// Reproduce the exact credential generation logic from relay.go
	// and verify it produces deterministic, correctly formatted output.
	secret := "my-coturn-secret"
	sessionID := "session-abc-123"
	expiresAt := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)

	username := fmt.Sprintf("%d:%s", expiresAt.Unix(), sessionID)

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Username must have format "timestamp:sessionID".
	expectedUsername := fmt.Sprintf("%d:%s", expiresAt.Unix(), sessionID)
	if username != expectedUsername {
		t.Errorf("username = %q, want %q", username, expectedUsername)
	}

	// Password must be base64-encoded, non-empty.
	if password == "" {
		t.Fatal("password is empty")
	}

	// Verify base64 is valid by decoding.
	decoded, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		t.Fatalf("password is not valid base64: %v", err)
	}

	// SHA1 produces 20-byte digests.
	if len(decoded) != 20 {
		t.Errorf("decoded password length = %d, want 20 (SHA1 digest)", len(decoded))
	}

	// Verify determinism: same inputs produce same output.
	mac2 := hmac.New(sha1.New, []byte(secret))
	mac2.Write([]byte(username))
	password2 := base64.StdEncoding.EncodeToString(mac2.Sum(nil))

	if password != password2 {
		t.Error("HMAC-SHA1 is not deterministic")
	}

	// Verify different secret produces different output.
	mac3 := hmac.New(sha1.New, []byte("different-secret"))
	mac3.Write([]byte(username))
	password3 := base64.StdEncoding.EncodeToString(mac3.Sum(nil))

	if password == password3 {
		t.Error("different secrets produced same password")
	}
}

func TestCoturnCredential_TTLFormat(t *testing.T) {
	// Verify the TTL constant and expiration calculation match coturn expectations.
	const relayCredentialTTL = 3600

	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(relayCredentialTTL * time.Second)

	expectedExpiry := time.Date(2026, 4, 6, 13, 0, 0, 0, time.UTC)
	if !expiresAt.Equal(expectedExpiry) {
		t.Errorf("expiresAt = %v, want %v", expiresAt, expectedExpiry)
	}

	// Username timestamp must be Unix seconds (not milliseconds).
	username := fmt.Sprintf("%d:%s", expiresAt.Unix(), "session-1")
	if username != fmt.Sprintf("%d:session-1", expectedExpiry.Unix()) {
		t.Errorf("username format mismatch: %q", username)
	}
}

func TestOverlay_ServerAddressDerivation(t *testing.T) {
	serverIP, err := overlay.ServerOverlayIP("10.100.0.0/16")
	if err != nil {
		t.Fatalf("server overlay ip: %v", err)
	}
	if serverIP != "10.100.0.1" {
		t.Fatalf("server overlay ip = %q, want %q", serverIP, "10.100.0.1")
	}

	ifaceAddr, err := overlay.ServerInterfaceAddress("10.100.0.0/16")
	if err != nil {
		t.Fatalf("server interface address: %v", err)
	}
	if ifaceAddr != "10.100.0.1/16" {
		t.Fatalf("server interface address = %q, want %q", ifaceAddr, "10.100.0.1/16")
	}
}

func TestOverlay_ServerAddressRejectsTooSmallSubnet(t *testing.T) {
	_, err := overlay.ServerOverlayIP("10.100.0.0/31")
	if err == nil {
		t.Fatal("expected error for subnet with fewer than 2 host bits")
	}
}

func TestOverlay_GeneratePeerConfigHubAndSpoke(t *testing.T) {
	pc := overlay.GeneratePeerConfig(
		"server-public",
		"relay.selkie.live",
		51820,
		"10.100.0.1",
		"device-public",
		"10.100.0.7",
	)

	if pc.OverlayIP != "10.100.0.7" {
		t.Fatalf("overlay ip = %q, want %q", pc.OverlayIP, "10.100.0.7")
	}
	if !strings.Contains(pc.DeviceSide, "AllowedIPs = 10.100.0.1/32") {
		t.Fatalf("device-side config missing server /32: %q", pc.DeviceSide)
	}
	if strings.Contains(pc.DeviceSide, "AllowedIPs = 10.100.0.0/16") {
		t.Fatalf("device-side config still contains overlay cidr: %q", pc.DeviceSide)
	}
	if !strings.Contains(pc.DeviceSide, "PersistentKeepalive = 25") {
		t.Fatalf("device-side config missing keepalive: %q", pc.DeviceSide)
	}
	if !strings.Contains(pc.ServerSide, "AllowedIPs = 10.100.0.7/32") {
		t.Fatalf("server-side config missing device /32: %q", pc.ServerSide)
	}
	if !strings.Contains(pc.ServerSide, "PersistentKeepalive = 25") {
		t.Fatalf("server-side config missing keepalive: %q", pc.ServerSide)
	}
}
