//nolint:testpackage // White-box tests cover package-private helpers and handlers.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
)

// validWGKey is a base64-encoded 32-byte WireGuard public key used as a
// validation-passing fixture. It is 32 random non-zero bytes that decode
// outside the Curve25519 low-order set; it is not a real key.
const validWGKey = "X9VHANJ9krFqd+B0Z/AlbWbiD1RnHmjwGEDtTBvDhk0="

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
	syncAllCalls  int
	syncAllErr    error
}

func (f *fakeHub) SyncAll(_ context.Context) error {
	f.syncAllCalls++
	return f.syncAllErr
}

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
	longLabel := strings.Repeat("a", maxDNSLabelLen+1)

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
			// Mixed case is canonicalized to lowercase before validation,
			// so it must still pass.
			name:      "valid mixed-case hostname",
			req:       enrollRequest{Hostname: "Phone.Local", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "",
		},
		{
			name:      "wg_public_key whitespace-padded",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: "  " + validWGKey + "  "},
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
			// Turkish dotted-I (U+0130) ToLowers to ASCII 'i' under Unicode
			// case-folding; the rejection must fire BEFORE ToLower so it
			// can't homograph-collide with a real ASCII hostname.
			name:      "hostname turkish dotted I",
			req:       enrollRequest{Hostname: "Phone\u0130.local", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname latin small e with acute",
			req:       enrollRequest{Hostname: "caf\u00e9.local", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname zero-width space",
			req:       enrollRequest{Hostname: "a\u200Bb", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname leading hyphen",
			req:       enrollRequest{Hostname: "-foo", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname trailing hyphen",
			req:       enrollRequest{Hostname: "foo-", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname double dot",
			req:       enrollRequest{Hostname: "a..b", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname leading dot",
			req:       enrollRequest{Hostname: ".a", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname trailing dot",
			req:       enrollRequest{Hostname: "a.", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "hostname",
		},
		{
			name:      "hostname label too long",
			req:       enrollRequest{Hostname: longLabel + ".local", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
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
			name:      "os_arch with embedded newline",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm\n64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_arch",
		},
		{
			// Cf format chars (ZWSP, BOM, ...) are not Cc so unicode.IsControl
			// misses them — the predicate also has to require IsPrint.
			name:      "os_arch with zero-width space",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm\u200B64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
			wantField: "os_arch",
		},
		{
			name:      "os_arch with bom",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm\uFEFF64", AppVersion: "1.0.0", WGPublicKey: validWGKey},
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
			name:      "app_version with null byte",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0\x00.0", WGPublicKey: validWGKey},
			wantField: "app_version",
		},
		{
			name:      "app_version with zero-width space",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0\u200B.0", WGPublicKey: validWGKey},
			wantField: "app_version",
		},
		{
			name:      "app_version with bom",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "\uFEFF1.0.0", WGPublicKey: validWGKey},
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
		{
			// URL-safe base64 has the same byte length as the standard
			// alphabet but uses `-`/`_`; the regex must reject it so the DB
			// only stores canonical-alphabet keys.
			name:      "wg_public_key url-safe alphabet",
			req:       enrollRequest{Hostname: "iphone", OSPlatform: "ios", OSArch: "arm64", AppVersion: "1.0.0", WGPublicKey: strings.Repeat("-", 43) + "="},
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

func TestParseEnrollRequestCanonicalizes(t *testing.T) {
	t.Parallel()
	// Input: mixed-case hostname, whitespace-padded wg_public_key. The
	// returned request must carry the lowercased hostname and trimmed key
	// so the DB upsert and hub join-key see canonical values.
	body := fmt.Sprintf(`{"hostname":"Phone.Local","os_platform":"ios","os_arch":"arm64","app_version":"1.0.0","wg_public_key":"  %s  "}`, validWGKey)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	parsed, ok := parseEnrollRequest(rec, req)
	if !ok {
		t.Fatalf("parseEnrollRequest failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if parsed.Hostname != "phone.local" {
		t.Fatalf("hostname = %q, want %q", parsed.Hostname, "phone.local")
	}
	if parsed.WGPublicKey != validWGKey {
		t.Fatalf("wg_public_key = %q, want %q (trimmed)", parsed.WGPublicKey, validWGKey)
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
	disc := &fakeDisconnector{deviceIDs: []string{"dev-aaa", "dev-bbb", "dev-ccc"}}

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
	// Multi-device retirement must result in exactly one SyncAll, never
	// per-device SyncDevice calls (those fan out to N reconciliations
	// because revoked devices no longer match `status='active'`).
	if hub.syncAllCalls != 1 {
		t.Fatalf("hub.SyncAll calls = %d, want 1", hub.syncAllCalls)
	}
	if len(hub.syncedDevices) != 0 {
		t.Fatalf("hub.SyncDevice unexpectedly called: %v", hub.syncedDevices)
	}
}

// TestHandleDisconnectNoDevicesStillSyncs confirms that even when the store
// reports no active mobile devices, SyncAll still runs — the retry contract
// requires SyncAll on every disconnect call so a second call after a 503
// (where the DB rows are already revoked and DisconnectMobileDevices returns
// empty) still removes stale wireguard peers from the hub.
func TestHandleDisconnectNoDevicesStillSyncs(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	hub := &fakeHub{}
	disc := &fakeDisconnector{deviceIDs: nil}

	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-5"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	// SyncAll must fire even when no active devices remain — idempotent
	// reconcile removes stale peers left from a prior failed sync.
	if hub.syncAllCalls != 1 {
		t.Fatalf("hub.SyncAll calls = %d, want 1", hub.syncAllCalls)
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

func TestValidateWGPublicKey_RejectsAllZeros(t *testing.T) {
	t.Parallel()
	// The all-zeros (32-byte) key is the X25519 identity / order-1 point.
	// Pre-2026 fixtures used this as a "validation-passing" stand-in, which
	// also enabled a global pre-registration DoS (devices.wg_public_key is
	// globally UNIQUE).
	const allZerosKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	err := validateWGPublicKey(allZerosKey)
	if err == nil {
		t.Fatalf("expected validation error for all-zeros wg key, got nil")
	}
	var verr *enrollValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *enrollValidationError, got %T (%v)", err, err)
	}
	if verr.Field != "wg_public_key" {
		t.Fatalf("field = %q, want wg_public_key", verr.Field)
	}
	if !strings.Contains(verr.Reason, "low-order") {
		t.Fatalf("reason = %q, want it to mention low-order", verr.Reason)
	}
}

func TestValidateWGPublicKey_RejectsKnownLowOrderPoint(t *testing.T) {
	t.Parallel()
	// All 13 canonical Curve25519 low-order representatives (incl. high-bit
	// variants per RFC 7748 §5) must be rejected.
	cases := []struct {
		name string
		key  string
	}{
		{"order2 one", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{"order2 one high bit", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA="},
		{"order8 p1", "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuAA="},
		{"order8 p1 high bit", "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuIA="},
		{"order8 p2", "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEVc="},
		{"order8 p2 high bit", "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEdc="},
		{"p-1", "7P///////////////////////////////////////38="},
		{"p-1 high bit", "7P////////////////////////////////////////8="},
		{"p", "7f///////////////////////////////////////38="},
		{"p high bit", "7f////////////////////////////////////////8="},
		{"p+1", "7v///////////////////////////////////////38="},
		{"p+1 high bit", "7v////////////////////////////////////////8="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateWGPublicKey(tc.key)
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", tc.name)
			}
			var verr *enrollValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("expected *enrollValidationError, got %T (%v)", err, err)
			}
			if verr.Field != "wg_public_key" {
				t.Fatalf("field = %q, want wg_public_key", verr.Field)
			}
			if !strings.Contains(verr.Reason, "low-order") {
				t.Fatalf("reason = %q, want it to mention low-order", verr.Reason)
			}
		})
	}
}

// fakeDisconnectorWithStatus records what status the device rows would be
// in after the DB commit. Real production rollback is impossible once the
// commit has happened, so this stub flips the row to "revoked" before
// returning — and the handler must NOT unwind that even when SyncAll fails.
type fakeDisconnectorWithStatus struct {
	deviceIDs []string
	rowStatus map[string]string
}

func (f *fakeDisconnectorWithStatus) DisconnectMobileDevices(_ context.Context, _ string) ([]string, error) {
	if f.rowStatus == nil {
		f.rowStatus = make(map[string]string)
	}
	for _, id := range f.deviceIDs {
		f.rowStatus[id] = "revoked"
	}
	return f.deviceIDs, nil
}

func TestHandleDisconnectSyncFailureReturns503(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	syncSentinel := errors.New("wg sync exploded")
	hub := &fakeHub{syncAllErr: syncSentinel}
	disc := &fakeDisconnectorWithStatus{deviceIDs: []string{"dev-xyz"}}

	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-9"))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	if hub.syncAllCalls != 1 {
		t.Fatalf("hub.SyncAll calls = %d, want 1", hub.syncAllCalls)
	}
	// DB commit already happened — the revoked status must persist. The
	// 503 just tells the client to retry so SyncAll can finish.
	if got := disc.rowStatus["dev-xyz"]; got != "revoked" {
		t.Fatalf("device row status = %q, want revoked (commit must persist)", got)
	}
	// Response body must carry retry guidance.
	if !strings.Contains(rec.Body.String(), "retry to fully tear down") {
		t.Fatalf("body missing retry guidance: %s", rec.Body.String())
	}
}

// TestValidateWGPublicKey_RejectsZeroWithHighBit is the CRITICAL regression
// test: the all-zeros identity with byte[31]=0x80 ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=")
// was previously accepted because the map had no entry for that bit pattern.
// After masking byte 31 to 0x7f before lookup it collapses to the all-zeros
// entry and is correctly rejected.
func TestValidateWGPublicKey_RejectsZeroWithHighBit(t *testing.T) {
	t.Parallel()
	const zeroHighBit = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA="
	err := validateWGPublicKey(zeroHighBit)
	if err == nil {
		t.Fatalf("expected rejection for all-zeros+high-bit key, got nil")
	}
	var verr *enrollValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *enrollValidationError, got %T (%v)", err, err)
	}
	if verr.Field != "wg_public_key" {
		t.Fatalf("field = %q, want wg_public_key", verr.Field)
	}
	if !strings.Contains(verr.Reason, "low-order") {
		t.Fatalf("reason = %q, want it to mention low-order", verr.Reason)
	}
}

// TestValidateWGPublicKey_RejectsAllBasePointsWithHighBit verifies that every
// known low-order base point with byte[31]|=0x80 is also rejected after the
// RFC 7748 §5 high-bit mask is applied before the map lookup.
func TestValidateWGPublicKey_RejectsAllBasePointsWithHighBit(t *testing.T) {
	t.Parallel()
	// Each pair is (low-bit canonical key, high-bit variant key).
	cases := []struct {
		name       string
		lowBit     string
		highBitKey string
	}{
		{
			name:       "identity all-zeros",
			lowBit:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			highBitKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=",
		},
		{
			name:       "order2 one",
			lowBit:     "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			highBitKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=",
		},
		{
			name:       "order8 p1",
			lowBit:     "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuAA=",
			highBitKey: "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuIA=",
		},
		{
			name:       "order8 p2",
			lowBit:     "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEVc=",
			highBitKey: "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEdc=",
		},
		{
			name:       "p-1",
			lowBit:     "7P///////////////////////////////////////38=",
			highBitKey: "7P////////////////////////////////////////8=",
		},
		{
			name:       "p",
			lowBit:     "7f///////////////////////////////////////38=",
			highBitKey: "7f////////////////////////////////////////8=",
		},
		{
			name:       "p+1",
			lowBit:     "7v///////////////////////////////////////38=",
			highBitKey: "7v////////////////////////////////////////8=",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, key := range []string{tc.lowBit, tc.highBitKey} {
				err := validateWGPublicKey(key)
				if err == nil {
					t.Fatalf("key %q: expected rejection, got nil", key)
				}
				var verr *enrollValidationError
				if !errors.As(err, &verr) {
					t.Fatalf("key %q: expected *enrollValidationError, got %T (%v)", key, err, err)
				}
				if verr.Field != "wg_public_key" {
					t.Fatalf("key %q: field = %q, want wg_public_key", key, verr.Field)
				}
				if !strings.Contains(verr.Reason, "low-order") {
					t.Fatalf("key %q: reason = %q, want it to mention low-order", key, verr.Reason)
				}
			}
		})
	}
}

// TestHandleDisconnect_RetryAfterSyncFailureReconciles exercises the retry
// contract for Fix 2: after a 503 (first call with SyncAll failure), the DB
// rows are already revoked; a second call returns no active deviceIDs but
// must still invoke SyncAll to tear down stale wireguard peers.
func TestHandleDisconnect_RetryAfterSyncFailureReconciles(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	syncSentinel := errors.New("hub unreachable")
	hub := &fakeHub{syncAllErr: syncSentinel}

	// First call: 1 active device; SyncAll fails → 503, DB rows revoked.
	disc := &fakeDisconnectorWithStatus{deviceIDs: []string{"dev-retry"}}
	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req1.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-retry"))
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("first call: status = %d, want 503; body=%s", rec1.Code, rec1.Body.String())
	}
	if hub.syncAllCalls != 1 {
		t.Fatalf("first call: hub.SyncAll calls = %d, want 1", hub.syncAllCalls)
	}
	if got := disc.rowStatus["dev-retry"]; got != "revoked" {
		t.Fatalf("first call: device row status = %q, want revoked", got)
	}

	// Second call (retry): clear the sync error and use empty disconnector
	// (simulates all rows already revoked — DisconnectMobileDevices returns []).
	hub.syncAllErr = nil
	emptyDisc := &fakeDisconnectorWithStatus{deviceIDs: nil}
	h.disconnector = emptyDisc

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req2.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-retry"))
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second call (retry): status = %d, want 204; body=%s", rec2.Code, rec2.Body.String())
	}
	// SyncAll must have been called on the retry (total = 2 across both calls).
	if hub.syncAllCalls != 2 {
		t.Fatalf("second call (retry): hub.SyncAll total calls = %d, want 2", hub.syncAllCalls)
	}
}

// spyAuditLogger captures the most recent audit.Event for assertion in tests.
type spyAuditLogger struct {
	events []audit.Event
}

func (s *spyAuditLogger) Log(_ context.Context, evt audit.Event) error {
	s.events = append(s.events, evt)
	return nil
}

func (s *spyAuditLogger) last() (audit.Event, bool) {
	if len(s.events) == 0 {
		return audit.Event{}, false
	}
	return s.events[len(s.events)-1], true
}

// TestHandleDisconnectSyncFailureAuditOutcome verifies Fix 1: the audit event
// written on SyncAll failure uses outcome="failure" (a valid CHECK enum value)
// and records failure_reason="wg_sync_failed" in metadata. Previously the code
// passed outcomeOverride="sync_failed" which violates the DB CHECK constraint
// at migrations/001_initial.sql:285 and caused every 503 path to silently drop
// the audit row with a 23514 check_violation.
func TestHandleDisconnectSyncFailureAuditOutcome(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	spy := &spyAuditLogger{}
	hub := &fakeHub{syncAllErr: errors.New("hub exploded")}
	disc := &fakeDisconnectorWithStatus{deviceIDs: []string{"dev-audit"}}

	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc
	h.audit = spy

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-audit"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	evt, ok := spy.last()
	if !ok {
		t.Fatal("no audit event recorded; expected one with outcome=failure")
	}
	if evt.Outcome != "failure" {
		t.Fatalf("audit outcome = %q, want %q (must satisfy DB CHECK constraint)", evt.Outcome, "failure")
	}
	reason, _ := evt.Metadata["failure_reason"].(string)
	if reason != "wg_sync_failed" {
		t.Fatalf("audit metadata.failure_reason = %q, want %q", reason, "wg_sync_failed")
	}
}

// TestHandleDisconnectSyncFailureRetryAfterHeader verifies Fix 2: a 503 on
// SyncAll failure must carry a Retry-After header equal to the
// mobileDisconnectWindow in seconds so clients can back off programmatically.
func TestHandleDisconnectSyncFailureRetryAfterHeader(t *testing.T) {
	cfg := config.Config{InternalSessionSecret: "test-secret"}
	hub := &fakeHub{syncAllErr: errors.New("hub unreachable")}
	disc := &fakeDisconnectorWithStatus{deviceIDs: []string{"dev-ra"}}

	h := New(nil, nil, cfg, nil, nil, hub, fakeLimiter{
		decision: ratelimit.Decision{Allowed: true},
	})
	h.disconnector = disc

	router := chi.NewRouter()
	h.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/disconnect", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, cfg.InternalSessionSecret, "user-ra"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	want := strconv.Itoa(int(mobileDisconnectWindow.Seconds()))
	if got := rec.Header().Get("Retry-After"); got != want {
		t.Fatalf("Retry-After = %q, want %q", got, want)
	}
}

// TestAuditMobileDisconnectUTF8Truncation verifies Fix 3: a sync error whose
// message contains a multi-byte UTF-8 sequence that straddles the 200-byte
// boundary is truncated without producing invalid UTF-8 sequences in metadata.
func TestAuditMobileDisconnectUTF8Truncation(t *testing.T) {
	spy := &spyAuditLogger{}
	h := &Handler{logger: zap.NewNop(), audit: spy}

	// Build a 210-byte string: 199 ASCII bytes followed by a 3-byte UTF-8
	// rune (U+4E16, 世), then more ASCII. Naive msg[:200] would cut the 3-byte
	// rune after its first byte, producing invalid UTF-8.
	base := strings.Repeat("a", 199) + "世" + strings.Repeat("b", 10)
	syncErr := errors.New(base)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	h.auditMobileDisconnect(context.Background(), req, "u1", []string{"d1"}, "failure", syncErr)

	evt, ok := spy.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	msg, _ := evt.Metadata["sync_error"].(string)
	if msg == "" {
		t.Fatal("sync_error missing from metadata")
	}
	for i, r := range msg {
		if r == '\uFFFD' {
			t.Fatalf("sync_error contains U+FFFD replacement at byte %d; truncation is not UTF-8 safe", i)
		}
	}
	if len(msg) > 200 {
		t.Fatalf("sync_error length = %d, want <= 200 bytes", len(msg))
	}
}

func signedToken(t *testing.T, secret, subject string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": subject,
		"iss": "selkie",
		"aud": []string{"mobile"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}
