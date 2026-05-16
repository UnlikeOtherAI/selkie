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
	cfg := config.Config{DevMode: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate err = %v, want nil in dev mode", err)
	}
}
