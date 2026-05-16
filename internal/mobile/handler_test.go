//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
)

// validWGKey is a base64-encoded 32-byte WireGuard public key used as a
// validation-passing fixture; it is not a real key.
const validWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type fakeLimiter struct {
	decision ratelimit.Decision
	err      error
}

func (f fakeLimiter) Allow(_ context.Context, _ string, _ int64, _ time.Duration) (ratelimit.Decision, error) {
	return f.decision, f.err
}

type fakeDisconnector struct {
	calls     int
	lastUser  string
	deviceIDs []string
	err       error
}

func (f *fakeDisconnector) DisconnectMobileDevices(_ context.Context, userID string) ([]string, error) {
	f.calls++
	f.lastUser = userID
	if f.err != nil {
		return nil, f.err
	}
	return f.deviceIDs, nil
}

type fakeHub struct {
	syncedDevices []string
}

func (*fakeHub) SyncAll(_ context.Context) error { return nil }

func (f *fakeHub) SyncDevice(_ context.Context, deviceID string) error {
	f.syncedDevices = append(f.syncedDevices, deviceID)
	return nil
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

	body := fmt.Sprintf(`{"hostname":"iphone","os_platform":"ios","os_arch":"arm64","app_version":"0.1.0","wg_public_key":%q}`, validWGKey)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", strings.NewReader(body))
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

func TestValidateEnrollRequest(t *testing.T) {
	t.Parallel()
	longHostname := strings.Repeat("a", maxHostnameLen+1)
	longArch := strings.Repeat("x", maxOSArchLen+1)
	longVersion := strings.Repeat("v", maxAppVersionLen+1)

	cases := []struct {
		name      string
		req       enrollRequest
		wantField string
	}{
		{
			name:      "valid ios",
			req:       enrollRequest{Hostname: "iphone.local", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "",
		},
		{
			name:      "valid android",
			req:       enrollRequest{Hostname: "pixel-7", OSPlatform: "android", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "",
		},
		{
			name:      "missing hostname",
			req:       enrollRequest{Hostname: "  ", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname too long",
			req:       enrollRequest{Hostname: longHostname, OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname illegal chars",
			req:       enrollRequest{Hostname: "phone_with_underscore", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "unsupported os_platform",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "darwin", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_platform",
		},
		{
			name:      "empty os_platform",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_platform",
		},
		{
			name:      "empty os_arch",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_arch",
		},
		{
			name:      "os_arch too long",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: longArch, AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_arch",
		},
		{
			name:      "empty app_version",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "", WGPublicKey: validWGKey},
			wantField: "app_version",
		},
		{
			name:      "app_version too long",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: longVersion, WGPublicKey: validWGKey},
			wantField: "app_version",
		},
		{
			name:      "empty wg_public_key",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: ""},
			wantField: "wg_public_key",
		},
		{
			name:      "wg_public_key not base64",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: "not-valid-base64!!!"},
			wantField: "wg_public_key",
		},
		{
			name:      "wg_public_key wrong length",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: "QUJD"}, // base64 of "ABC", only 3 bytes
			wantField: "wg_public_key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateEnrollRequest(tc.req)
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected validation error for field %q, got nil", tc.wantField)
			}
			var verr *enrollValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("expected *enrollValidationError, got %T (%v)", err, err)
			}
			if verr.Field != tc.wantField {
				t.Fatalf("field = %q, want %q", verr.Field, tc.wantField)
			}
		})
	}
}

func TestHandleEnrollValidationErrorResponse(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})

	router := chi.NewRouter()
	h.Mount(router)

	// hostname uses an underscore (DNS-unsafe). The bad value must not be echoed.
	body := `{"hostname":"phone_secret","os_platform":"ios","os_arch":"arm64","app_version":"1.0.0","wg_public_key":"` + validWGKey + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-1"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["field"] != "hostname" {
		t.Fatalf("field = %q, want hostname", payload["field"])
	}
	if strings.Contains(rec.Body.String(), "phone_secret") {
		t.Fatalf("response leaked bad hostname value: %s", rec.Body.String())
	}
}

func TestBuildEnrollResponseNilOverlay(t *testing.T) {
	// The nil-overlay guard must short-circuit before WG config rendering.
	h := &Handler{logger: zap.NewNop(), cfg: config.Config{
		WGOverlayCIDR:     "10.100.0.0/16",
		WGServerPublicKey: "server-public-key",
		WGServerEndpoint:  "relay.selkie.live",
		WGServerPort:      51820,
	}}

	rec := httptest.NewRecorder()
	ok := h.writeMobileEnrollSuccess(rec, "device-123", "user-9", nil)
	if ok {
		t.Fatal("expected writeMobileEnrollSuccess to return false on nil overlay")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "overlay not allocated") {
		t.Fatalf("body missing overlay message: %s", rec.Body.String())
	}
}

func TestHandleDisconnectRateLimited(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	disc := &fakeDisconnector{}
	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: false, RetryAfter: 4 * time.Second},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-2"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "4" {
		t.Fatalf("Retry-After = %q, want 4", got)
	}
	if disc.calls != 0 {
		t.Fatalf("disconnector called %d times, want 0", disc.calls)
	}
}

func TestHandleDisconnectRetiresDevices(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	hub := &fakeHub{}
	disc := &fakeDisconnector{deviceIDs: []string{"dev-aaa", "dev-bbb"}}

	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-3"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if disc.calls != 1 {
		t.Fatalf("disconnector calls = %d, want 1", disc.calls)
	}
	if disc.lastUser != "user-3" {
		t.Fatalf("disconnector userID = %q, want user-3", disc.lastUser)
	}
	if len(hub.syncedDevices) != 2 || hub.syncedDevices[0] != "dev-aaa" || hub.syncedDevices[1] != "dev-bbb" {
		t.Fatalf("hub synced = %v, want [dev-aaa dev-bbb]", hub.syncedDevices)
	}
}

func TestHandleDisconnectStoreFailure(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	disc := &fakeDisconnector{err: errors.New("boom")}

	h := New(nil, nil, cfg, nil, nil, nil, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-4"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func signedToken(t *testing.T, secret, subject string) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": subject}).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}
