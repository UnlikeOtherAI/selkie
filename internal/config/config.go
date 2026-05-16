// Package config loads environment-based configuration for the selkie server.
package config

import (
	"errors"
	"os"
	"strconv"
)

// ErrMissingSessionSecret indicates that INTERNAL_SESSION_SECRET was not set in
// a non-development environment. The control-server must refuse to start when
// this condition is detected so that requests are never authenticated against
// an empty HMAC key.
var ErrMissingSessionSecret = errors.New("INTERNAL_SESSION_SECRET is required when DEV_MODE is false")

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

// Validate returns an error when required configuration values are missing.
// It is intentionally strict in non-dev mode so the server fails closed instead
// of silently accepting any HMAC signature against an empty secret.
func (c Config) Validate() error {
	if c.InternalSessionSecret == "" && !c.DevMode {
		return ErrMissingSessionSecret
	}
	return nil
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
