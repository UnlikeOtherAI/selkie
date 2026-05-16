// Package config loads environment-based configuration for the selkie server.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
)

// ErrMissingRedisPassword is returned by Validate when REDIS_URL is set but
// carries no password and DevMode is false. Empty passwords with redis 7
// silently disable AUTH while protected-mode is still satisfied by the bind,
// so we reject it explicitly at startup.
var ErrMissingRedisPassword = errors.New("config: REDIS_URL missing password (set userinfo or omit REDIS_URL for dev)")

// ErrMissingRedisURL is returned by Validate when REDIS_URL is empty and
// DevMode is false. Redis is required in production for rate limiting and
// SSE fan-out; allowing it to be empty would crash main.go on the nil
// rdb.Client dereference at boot.
var ErrMissingRedisURL = errors.New("config: REDIS_URL is required in non-dev mode")

// Config holds all runtime configuration values loaded from the environment.
type Config struct {
	UOABaseURL               string
	UOADomain                string
	UOASharedSecret          string
	UOAAudience              string
	UOAConfigURL             string
	UOARedirectURL           string
	UOAMobileRedirectURL     string
	UOAOwnerSub              string
	MobileRedirectURL        string
	DatabaseURL              string
	RedisURL                 string
	InternalSessionSecret    string
	TurnHost                 string
	TurnPort                 int
	CoturnSecret             string
	CoturnRealm              string
	CoturnRedisStatsDB       string
	CoturnCLIAddr            string
	CoturnCLIPassword        string
	WGOverlayCIDR            string
	WGInterfaceName          string
	WGPrivateKey             string
	WGServerPublicKey        string
	WGServerEndpoint         string
	WGServerPort             int
	ServerPort               int
	LogLevel                 string
	OTELExporterOTLPEndpoint string
	OPAEndpoint              string
	DevMode                  bool
}

// Load reads all configuration from environment variables with sensible defaults.
func Load() Config {
	return Config{
		UOABaseURL:               os.Getenv("UOA_BASE_URL"),
		UOADomain:                os.Getenv("UOA_DOMAIN"),
		UOASharedSecret:          os.Getenv("UOA_SHARED_SECRET"),
		UOAAudience:              os.Getenv("UOA_AUDIENCE"),
		UOAConfigURL:             os.Getenv("UOA_CONFIG_URL"),
		UOARedirectURL:           os.Getenv("UOA_REDIRECT_URL"),
		UOAMobileRedirectURL:     os.Getenv("UOA_MOBILE_REDIRECT_URL"),
		UOAOwnerSub:              os.Getenv("UOA_OWNER_SUB"),
		MobileRedirectURL:        getenv("MOBILE_REDIRECT_URL", "selkie://auth"),
		DatabaseURL:              os.Getenv("DATABASE_URL"),
		RedisURL:                 os.Getenv("REDIS_URL"),
		InternalSessionSecret:    os.Getenv("INTERNAL_SESSION_SECRET"),
		TurnHost:                 os.Getenv("TURN_HOST"),
		TurnPort:                 getenvInt("TURN_PORT", 3478),
		CoturnSecret:             os.Getenv("COTURN_SECRET"),
		CoturnRealm:              getenv("COTURN_REALM", "selkie"),
		CoturnRedisStatsDB:       os.Getenv("COTURN_REDIS_STATSDB"),
		CoturnCLIAddr:            getenv("COTURN_CLI_ADDR", "127.0.0.1:5766"),
		CoturnCLIPassword:        os.Getenv("COTURN_CLI_PASSWORD"),
		WGOverlayCIDR:            os.Getenv("WG_OVERLAY_CIDR"),
		WGInterfaceName:          getenv("WG_INTERFACE_NAME", "wg0"),
		WGPrivateKey:             os.Getenv("WG_PRIVATE_KEY"),
		WGServerPublicKey:        os.Getenv("WG_SERVER_PUBLIC_KEY"),
		WGServerEndpoint:         os.Getenv("WG_SERVER_ENDPOINT"),
		WGServerPort:             getenvInt("WG_SERVER_PORT", 51820),
		ServerPort:               getenvIntMulti([]string{"PORT", "SERVER_PORT"}, 8080),
		LogLevel:                 getenv("LOG_LEVEL", "info"),
		OTELExporterOTLPEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		OPAEndpoint:              os.Getenv("OPA_ENDPOINT"),
		DevMode:                  getenvBool("DEV_MODE", false),
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func getenvIntMulti(keys []string, fallback int) int {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				return parsed
			}
		}
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return parsed
}

// Validate enforces invariants that must hold before the server boots in
// non-dev mode. It requires REDIS_URL to be set in production (so the
// rate limiter and SSE fan-out clients can initialize without a nil
// dereference) and, when set, that it carries a non-empty password
// component.
func (c Config) Validate() error {
	if c.RedisURL == "" {
		if c.DevMode {
			return nil
		}
		return ErrMissingRedisURL
	}
	u, err := url.Parse(c.RedisURL)
	if err != nil {
		return fmt.Errorf("config: parse REDIS_URL: %w", err)
	}
	password, hasPassword := u.User.Password()
	if !hasPassword || password == "" {
		if c.DevMode {
			return nil
		}
		return ErrMissingRedisPassword
	}
	return nil
}

func getenvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
