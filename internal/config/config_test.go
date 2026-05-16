package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/unlikeotherai/selkie/internal/config"
)

const validRedisURL = "redis://:secret@127.0.0.1:6379/0"

func strongSecret() string {
	return strings.Repeat("x", config.MinSessionSecretLen)
}

func TestValidate_MissingSecretInProd(t *testing.T) {
	cfg := config.Config{DevMode: false, RedisURL: validRedisURL}
	err := cfg.Validate()
	if !errors.Is(err, config.ErrMissingSessionSecret) {
		t.Fatalf("Validate err = %v, want ErrMissingSessionSecret", err)
	}
}

func TestValidate_WeakSecretInProd(t *testing.T) {
	cfg := config.Config{
		DevMode:               false,
		InternalSessionSecret: "too-short",
		RedisURL:              validRedisURL,
	}
	err := cfg.Validate()
	if !errors.Is(err, config.ErrWeakSessionSecret) {
		t.Fatalf("Validate err = %v, want ErrWeakSessionSecret", err)
	}
}

func TestValidate_AcceptsStrongSecret(t *testing.T) {
	cfg := config.Config{
		DevMode:               false,
		InternalSessionSecret: strongSecret(),
		RedisURL:              validRedisURL,
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

func TestValidate_RedisRules(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		setupFn func(*testing.T)
		wantErr error
	}{
		{
			name:    "empty redis url in prod is rejected",
			cfg:     config.Config{RedisURL: "", InternalSessionSecret: strongSecret(), DevMode: false},
			wantErr: config.ErrMissingRedisURL,
		},
		{
			name: "empty redis url in dev is allowed",
			cfg:  config.Config{RedisURL: "", DevMode: true},
			setupFn: func(t *testing.T) {
				t.Setenv("CONFIRM_DEV_MODE", "true")
			},
		},
		{
			name:    "redis url without password in prod is rejected",
			cfg:     config.Config{RedisURL: "redis://127.0.0.1:6379/0", InternalSessionSecret: strongSecret(), DevMode: false},
			wantErr: config.ErrMissingRedisPassword,
		},
		{
			name:    "redis url with empty password in prod is rejected",
			cfg:     config.Config{RedisURL: "redis://:@127.0.0.1:6379/0", InternalSessionSecret: strongSecret(), DevMode: false},
			wantErr: config.ErrMissingRedisPassword,
		},
		{
			name: "redis url without password in dev is allowed",
			cfg:  config.Config{RedisURL: "redis://127.0.0.1:6379/0", DevMode: true},
			setupFn: func(t *testing.T) {
				t.Setenv("CONFIRM_DEV_MODE", "true")
			},
		},
		{
			name: "redis url with password is allowed",
			cfg:  config.Config{RedisURL: "redis://:secret@127.0.0.1:6379/0", InternalSessionSecret: strongSecret(), DevMode: false},
		},
		{
			name: "redis url with user and password is allowed",
			cfg:  config.Config{RedisURL: "redis://default:secret@127.0.0.1:6379/0", InternalSessionSecret: strongSecret(), DevMode: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupFn != nil {
				tc.setupFn(t)
			}
			err := tc.cfg.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateInvalidRedisURL(t *testing.T) {
	cfg := config.Config{
		RedisURL:              "://not a url",
		InternalSessionSecret: strongSecret(),
		DevMode:               false,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for malformed URL")
	}
}
