package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/unlikeotherai/selkie/internal/config"
)

func TestValidate_MissingSecretInProd(t *testing.T) {
	cfg := config.Config{DevMode: false}
	err := cfg.Validate()
	if !errors.Is(err, config.ErrMissingSessionSecret) {
		t.Fatalf("Validate err = %v, want ErrMissingSessionSecret", err)
	}
}

func TestValidate_WeakSecretInProd(t *testing.T) {
	cfg := config.Config{
		DevMode:               false,
		InternalSessionSecret: "too-short",
	}
	err := cfg.Validate()
	if !errors.Is(err, config.ErrWeakSessionSecret) {
		t.Fatalf("Validate err = %v, want ErrWeakSessionSecret", err)
	}
}

func TestValidate_AcceptsStrongSecret(t *testing.T) {
	cfg := config.Config{
		DevMode:               false,
		InternalSessionSecret: strings.Repeat("x", config.MinSessionSecretLen),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate err = %v, want nil", err)
	}
}

func TestValidate_DevModeAllowsEmptySecret(t *testing.T) {
	t.Setenv("CONFIRM_DEV_MODE", "true")
	cfg := config.Config{DevMode: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate err = %v, want nil in dev mode", err)
	}
}

func TestValidate_DevModeWithoutConfirmRejected(t *testing.T) {
	cases := map[string]string{
		"unset": "",
		"empty": "",
		"false": "false",
		"yes":   "yes",
		"1":     "1",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "unset" {
				// t.Setenv with empty string only unsets via the cleanup hook,
				// but we still need CONFIRM_DEV_MODE to be effectively empty
				// for this subtest. Setting to "" achieves that.
				t.Setenv("CONFIRM_DEV_MODE", "")
			} else {
				t.Setenv("CONFIRM_DEV_MODE", value)
			}
			cfg := config.Config{DevMode: true}
			err := cfg.Validate()
			if !errors.Is(err, config.ErrUnconfirmedDevMode) {
				t.Fatalf("Validate err = %v, want ErrUnconfirmedDevMode", err)
			}
		})
	}
}
