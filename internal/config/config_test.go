package config_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/unlikeotherai/selkie/internal/config"
)

func TestLoad_PanicsOnEmptyTrustedProxiesInNonDev(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when TRUSTED_PROXY_CIDRS is empty and DEV_MODE=false")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic payload not a string: %#v", r)
		}
		if !strings.Contains(msg, "TRUSTED_PROXY_CIDRS") {
			t.Fatalf("panic message should mention TRUSTED_PROXY_CIDRS; got %q", msg)
		}
	}()

	_ = config.Load()
}

func TestLoad_AllowsEmptyTrustedProxiesInDevMode(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")

	cfg := config.Load()
	if !cfg.DevMode {
		t.Fatal("DevMode should be true")
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Fatalf("TrustedProxyCIDRs should be empty; got %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoad_InvalidCIDREntryProducesWarning(t *testing.T) {
	t.Setenv("DEV_MODE", "true") // avoid the empty-non-dev panic; we want at least one good entry below
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, not-a-cidr, 192.168.0.0/16")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("expected 2 valid prefixes; got %d (%v)", len(cfg.TrustedProxyCIDRs), cfg.TrustedProxyCIDRs)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("expected at least one warning for invalid CIDR entry")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "not-a-cidr") && strings.Contains(w, "TRUSTED_PROXY_CIDRS") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("warning should mention invalid entry 'not-a-cidr'; got %v", cfg.Warnings)
	}
}

func TestLoad_ValidTrustedProxiesNoWarnings(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("expected 2 trusted prefixes; got %d", len(cfg.TrustedProxyCIDRs))
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("expected no warnings; got %v", cfg.Warnings)
	}
}

// TestLoad_DualStackLoopbackWarning asserts that an IPv4 loopback prefix
// without a matching ::1/128 emits the dual-stack warning. Go's default
// listener is dual-stack, so a ::1 peer would otherwise be untrusted and
// silently collapse onto a shared rate-limit bucket.
func TestLoad_DualStackLoopbackWarning(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8")

	cfg := config.Load()
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "::1/128") && strings.Contains(w, "dual-stack") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dual-stack loopback warning; got %v", cfg.Warnings)
	}
}

// TestLoad_DualStackLoopbackWarningSuppressedWhenV6Present asserts that
// the warning does not fire when ::1/128 is also trusted.
func TestLoad_DualStackLoopbackWarningSuppressedWhenV6Present(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128")

	cfg := config.Load()
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "dual-stack") {
			t.Fatalf("dual-stack warning should be suppressed when ::1/128 is present; got %q", w)
		}
	}
}

// TestParseTrustedProxyCIDRs_4in6PrefixNormalized asserts that a 4in6 prefix
// like ::ffff:10.0.0.0/104 is accepted, produces a warning about normalization,
// and the resulting prefix contains the canonical IPv4 address 10.0.0.5.
func TestParseTrustedProxyCIDRs_4in6PrefixNormalized(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "::ffff:10.0.0.0/104")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 1 {
		t.Fatalf("expected 1 prefix after normalization; got %d (%v)", len(cfg.TrustedProxyCIDRs), cfg.TrustedProxyCIDRs)
	}
	// The prefix must contain the canonical IPv4 address, not just the 4in6 form.
	target := netip.MustParseAddr("10.0.0.5")
	if !cfg.TrustedProxyCIDRs[0].Contains(target) {
		t.Fatalf("normalized prefix %v should contain 10.0.0.5", cfg.TrustedProxyCIDRs[0])
	}
	// A warning must be emitted advising the operator to use the canonical form.
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "4in6") && strings.Contains(w, "::ffff:10.0.0.0/104") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected normalization warning for 4in6 prefix; got %v", cfg.Warnings)
	}
}

// TestParseTrustedProxyCIDRs_4in6WideMaskRejected is a table-driven test
// asserting that 4in6 prefixes whose normalized v4 mask is shorter than /8
// are dropped with the "too wide" warning rather than silently trusting a
// vast address range (e.g. ::ffff:0.0.0.0/96 → 0.0.0.0/0).
func TestParseTrustedProxyCIDRs_4in6WideMaskRejected(t *testing.T) {
	cases := []struct {
		entry    string
		normBits int
	}{
		{"::ffff:0.0.0.0/96", 0},
		{"::ffff:0.0.0.0/97", 1},
		{"::ffff:10.0.0.0/103", 7},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			t.Setenv("DEV_MODE", "true")
			t.Setenv("TRUSTED_PROXY_CIDRS", tc.entry)

			cfg := config.Load()
			if len(cfg.TrustedProxyCIDRs) != 0 {
				t.Fatalf("wide 4in6 prefix %q should be dropped; got %v", tc.entry, cfg.TrustedProxyCIDRs)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "too wide") && strings.Contains(w, tc.entry) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected 'too wide' warning for %q; got %v", tc.entry, cfg.Warnings)
			}
		})
	}
}

// TestParseTrustedProxyCIDRs_4in6AcceptedAtMinimum asserts that a 4in6 prefix
// whose normalized v4 mask is exactly /8 (the minimum) is accepted normally.
// ::ffff:10.0.0.0/104 normalizes to 10.0.0.0/8.
func TestParseTrustedProxyCIDRs_4in6AcceptedAtMinimum(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "::ffff:10.0.0.0/104")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 1 {
		t.Fatalf("expected 1 prefix for /8-normalized 4in6 entry; got %d (%v)", len(cfg.TrustedProxyCIDRs), cfg.TrustedProxyCIDRs)
	}
	// Must contain 10.x.x.x addresses.
	target := netip.MustParseAddr("10.0.0.5")
	if !cfg.TrustedProxyCIDRs[0].Contains(target) {
		t.Fatalf("normalized prefix %v should contain 10.0.0.5", cfg.TrustedProxyCIDRs[0])
	}
	// Must NOT emit a "too wide" warning.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "too wide") {
			t.Fatalf("minimum-mask 4in6 prefix should not trigger 'too wide' warning; got %q", w)
		}
	}
}

// TestParseTrustedProxyCIDRs_4in6PrefixTooWide asserts that a 4in6 prefix
// whose bit-length is less than 96 (so subtracting 96 would yield a negative
// IPv4 prefix length) is dropped with a distinct warning.
func TestParseTrustedProxyCIDRs_4in6PrefixTooWide(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "::ffff:10.0.0.0/64")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Fatalf("too-wide 4in6 prefix should be dropped; got %v", cfg.TrustedProxyCIDRs)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bits<96") && strings.Contains(w, "::ffff:10.0.0.0/64") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected bits<96 warning for too-wide 4in6 prefix; got %v", cfg.Warnings)
	}
}
