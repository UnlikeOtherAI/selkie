package config_test

import (
	"errors"
	"testing"

	"github.com/unlikeotherai/selkie/internal/config"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantErr error
	}{
		{
			name: "empty redis url is allowed",
			cfg:  config.Config{RedisURL: ""},
		},
		{
			name:    "redis url without password in prod is rejected",
			cfg:     config.Config{RedisURL: "redis://127.0.0.1:6379/0", DevMode: false},
			wantErr: config.ErrMissingRedisPassword,
		},
		{
			name:    "redis url with empty password in prod is rejected",
			cfg:     config.Config{RedisURL: "redis://:@127.0.0.1:6379/0", DevMode: false},
			wantErr: config.ErrMissingRedisPassword,
		},
		{
			name: "redis url without password in dev is allowed",
			cfg:  config.Config{RedisURL: "redis://127.0.0.1:6379/0", DevMode: true},
		},
		{
			name: "redis url with password is allowed",
			cfg:  config.Config{RedisURL: "redis://:secret@127.0.0.1:6379/0", DevMode: false},
		},
		{
			name: "redis url with user and password is allowed",
			cfg:  config.Config{RedisURL: "redis://default:secret@127.0.0.1:6379/0", DevMode: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
	cfg := config.Config{RedisURL: "://not a url", DevMode: false}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for malformed URL")
	}
}
