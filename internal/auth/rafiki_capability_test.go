//nolint:testpackage // Exercises the structural machine-capability boundary.
package auth

import (
	"testing"
	"time"

	"github.com/unlikeotherai/selkie/internal/config"
)

func TestRafikiDirectCapabilityDoesNotBecomeAnAccountSession(t *testing.T) {
	now := time.Now()
	cfg := config.Config{RafikiServiceKey: "dedicated-service-key", RafikiHomeDeviceID: "home"}
	original := Claims{
		CapabilityKind: RafikiDirectCapability, Sub: "user", DirectHomeID: "home",
		Audience: []string{AudienceMobile}, ExpiresAt: now.Add(5 * time.Minute),
	}
	if !validRafikiDirect(cfg, original, now) {
		t.Fatal("configured five-minute machine grant refused")
	}
	for _, change := range []func(*Claims){
		func(c *Claims) { c.CapabilityKind = "" },
		func(c *Claims) { c.SessionID = "human-session" },
		func(c *Claims) { c.DirectHomeID = "foreign-home" },
		func(c *Claims) { c.IsSuper = true },
		func(c *Claims) { c.Audience = []string{AudienceMobile, AudienceAdmin} },
		func(c *Claims) { c.ExpiresAt = now },
		func(c *Claims) { c.ExpiresAt = now.Add(5*time.Minute + time.Second) },
	} {
		candidate := original
		change(&candidate)
		if validRafikiDirect(cfg, candidate, now) {
			t.Fatal("invalid machine authority accepted")
		}
	}
	cfg.RafikiServiceKey = ""
	if validRafikiDirect(cfg, original, now) {
		t.Fatal("disabled service accepted")
	}
}
