package config_test

import (
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
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8")

	cfg := config.Load()
	if len(cfg.TrustedProxyCIDRs) != 1 {
		t.Fatalf("expected 1 trusted prefix; got %d", len(cfg.TrustedProxyCIDRs))
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("expected no warnings; got %v", cfg.Warnings)
	}
}
