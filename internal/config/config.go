// Package config loads environment-based configuration for the selkie server.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

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
	TrustedProxyCIDRs        []netip.Prefix
	// Warnings collects non-fatal configuration issues surfaced during
	// Load() so callers can emit them through their structured logger
	// (Load() itself runs before the logger is built). Treat each entry
	// as a high-severity warning.
	Warnings []string
}

// Load reads all configuration from environment variables with sensible defaults.
func Load() Config {
	trustedRaw := os.Getenv("TRUSTED_PROXY_CIDRS")
	trusted, trustedWarnings := parseTrustedProxyCIDRs(trustedRaw)
	devMode := getenvBool("DEV_MODE", false)
	warnings := trustedWarnings
	if len(trusted) == 0 && !devMode {
		// Forgotten TRUSTED_PROXY_CIDRS in production collapses every
		// request onto Caddy's loopback peer, producing a universal
		// rate-limit bucket and a trivial DoS surface. Refuse to start
		// rather than silently misbehave; the operator must opt into
		// "no trusted proxies" by setting DEV_MODE=true.
		panic("config: TRUSTED_PROXY_CIDRS is empty and DEV_MODE=false; refusing to start (set TRUSTED_PROXY_CIDRS to your edge proxy CIDR or DEV_MODE=true for local dev)")
	}
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
		DevMode:                  devMode,
		TrustedProxyCIDRs:        trusted,
		Warnings:                 warnings,
	}
}

// parseTrustedProxyCIDRs parses a comma-separated list of CIDR blocks. Invalid
// entries are dropped from the returned slice (so a misconfigured value cannot
// cause the server to start trusting arbitrary proxies) but each parse failure
// is surfaced via the returned warnings so the caller can log it — silently
// discarding entries makes "all my CIDRs are typos" indistinguishable from
// "no XFF trust intended" at runtime.
func parseTrustedProxyCIDRs(raw string) ([]netip.Prefix, []string) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	var warnings []string
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: ignoring invalid entry %q: %v", entry, err))
			continue
		}
		// Normalize 4in6 prefixes (e.g. ::ffff:10.0.0.0/104) to their
		// canonical IPv4 form so they line up with unmapped candidate IPs in
		// the trust check. Without this, Contains is family-strict and a
		// 4in6-configured trusted CIDR silently stops matching any peer.
		if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: ignoring 4in6 prefix %q with bits<96; use the canonical IPv4 form", entry))
				continue
			}
			warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: 4in6 prefix %q normalized to canonical IPv4 form; configure the IPv4 CIDR directly to silence this warning", entry))
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
		prefixes = append(prefixes, prefix)
	}
	if w := dualStackLoopbackWarning(prefixes); w != "" {
		warnings = append(warnings, w)
	}
	return prefixes, warnings
}

// dualStackLoopbackWarning surfaces an operator misconfiguration: an IPv4
// loopback prefix is trusted but ::1/128 is not. Go's default listener is
// dual-stack, so a request from `::1` (e.g. a sidecar binding to IPv6
// loopback only) lands as an untrusted peer and silently collapses every
// such caller onto a single rate-limit bucket while bypassing XFF trust.
func dualStackLoopbackWarning(prefixes []netip.Prefix) string {
	v4Loop := netip.MustParseAddr("127.0.0.1")
	v6Loop := netip.MustParseAddr("::1")
	var haveV4Loopback, haveV6Loopback bool
	for _, p := range prefixes {
		if p.Contains(v4Loop) {
			haveV4Loopback = true
		}
		if p.Contains(v6Loop) {
			haveV6Loopback = true
		}
	}
	if haveV4Loopback && !haveV6Loopback {
		return "TRUSTED_PROXY_CIDRS: IPv4 loopback present but ::1/128 missing; dual-stack listeners may receive untrusted ::1 peers and silently lose rate-limit isolation"
	}
	return ""
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
