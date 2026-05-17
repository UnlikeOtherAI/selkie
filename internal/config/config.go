// Package config loads environment-based configuration for the selkie server.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
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

// ErrMissingSessionSecret indicates that INTERNAL_SESSION_SECRET was not set in
// a non-development environment. The control-server must refuse to start when
// this condition is detected so that requests are never authenticated against
// an empty HMAC key.
var ErrMissingSessionSecret = errors.New("INTERNAL_SESSION_SECRET is required when DEV_MODE is false")

// ErrWeakSessionSecret indicates that INTERNAL_SESSION_SECRET is set but too
// short to provide meaningful HMAC strength. We require at least 32 bytes in
// production so brute-forcing the HMAC key is not feasible.
var ErrWeakSessionSecret = errors.New("INTERNAL_SESSION_SECRET must be at least 32 bytes when DEV_MODE is false")

// ErrUnconfirmedDevMode indicates that DEV_MODE=true was set without the
// matching CONFIRM_DEV_MODE=true acknowledgement. A single misconfigured env
// var must not be enough to silently disable HMAC validation and unlock
// /auth/dev-login in production.
var ErrUnconfirmedDevMode = errors.New("DEV_MODE=true requires CONFIRM_DEV_MODE=true to start; refusing to boot without explicit confirmation")

// MinSessionSecretLen is the minimum acceptable length for the HMAC session
// secret in production. 32 bytes matches the output width of HMAC-SHA256.
const MinSessionSecretLen = 32

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
	// devModeConfirmed mirrors CONFIRM_DEV_MODE at Load() time. Unexported
	// so a struct literal in test or alt-entrypoint code cannot bypass the
	// env tripwire by setting Config{DevMode: true, DevModeConfirmed: true}.
	// Validate consults this field; only Load() (or this package's own
	// tests via setDevModeConfirmed) may set it.
	devModeConfirmed  bool
	TrustedProxyCIDRs []netip.Prefix
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
	// DEV_MODE must be the literal string "true". The companion env
	// CONFIRM_DEV_MODE is checked the same way (see below); accepting
	// strconv.ParseBool's wider set ("1", "t", "T", "TRUE", "True") on one
	// side while the other side checks a literal would let a typo on one
	// variable disable the tripwire on the other half.
	devMode := os.Getenv("DEV_MODE") == "true"
	warnings := trustedWarnings
	if len(trusted) == 0 && !devMode {
		// Forgotten TRUSTED_PROXY_CIDRS in production collapses every
		// request onto Caddy's loopback peer, producing a universal
		// rate-limit bucket and a trivial DoS surface. Refuse to start
		// rather than silently misbehave; the operator must opt into
		// "no trusted proxies" by setting DEV_MODE=true.
		msg := "config: TRUSTED_PROXY_CIDRS is empty and DEV_MODE=false; refusing to start (set TRUSTED_PROXY_CIDRS to your edge proxy CIDR or DEV_MODE=true for local dev)"
		if len(trustedWarnings) > 0 {
			msg = msg + "; parse warnings: " + strings.Join(trustedWarnings, "; ")
		}
		panic(msg)
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
		// CONFIRM_DEV_MODE must be the literal string "true". Accepting
		// ParseBool's wider set (1, t, T, TRUE, True) would silently widen
		// a security gate that should require an unambiguous, human-typed
		// acknowledgement.
		devModeConfirmed:  os.Getenv("CONFIRM_DEV_MODE") == "true",
		TrustedProxyCIDRs: trusted,
		Warnings:          warnings,
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
		//
		// Guard against degenerate masks: ::ffff:0.0.0.0/96 normalizes to
		// 0.0.0.0/0, which trusts the entire public internet. Refuse any
		// 4in6 prefix whose normalized v4 mask is shorter than /8 — anything
		// wider than a single class-A block is almost certainly a typo and
		// would create a silent security hole. The same floor applies to
		// canonical IPv4/IPv6 prefixes: bare 0.0.0.0/0 or ::/0 in the trust
		// list lets any source spoof its XFF chain.
		const minV4Bits = 8
		const minV6Bits = 16
		if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: ignoring 4in6 prefix %q with bits<96; use the canonical IPv4 form", entry))
				continue
			}
			if bits < minV4Bits {
				warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: refusing 4in6 prefix %q; normalized v4 mask /%d trusts too wide a range (min /%d). Use the canonical IPv4 CIDR (e.g. 10.0.0.0/8, 127.0.0.1/32) instead.", entry, bits, minV4Bits))
				continue
			}
			warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: 4in6 prefix %q normalized to canonical IPv4 form; configure the IPv4 CIDR directly to silence this warning", entry))
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		} else if prefix.Addr().Is4() {
			if prefix.Bits() < minV4Bits {
				warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: refusing IPv4 prefix %q; mask /%d trusts too wide a range (min /%d)", entry, prefix.Bits(), minV4Bits))
				continue
			}
		} else {
			if prefix.Bits() < minV6Bits {
				warnings = append(warnings, fmt.Sprintf("TRUSTED_PROXY_CIDRS: refusing IPv6 prefix %q; mask /%d trusts too wide a range (min /%d)", entry, prefix.Bits(), minV6Bits))
				continue
			}
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

// Validate enforces invariants that must hold before the server boots.
//
// DEV_MODE=true requires CONFIRM_DEV_MODE=true so a single misconfigured env
// var cannot silently disable HMAC validation and unlock /auth/dev-login.
//
// In non-dev mode:
//   - INTERNAL_SESSION_SECRET must be set and at least MinSessionSecretLen
//     bytes long; otherwise requests would be authenticated against an empty
//     or weak HMAC key.
//   - REDIS_URL must be set and carry a non-empty password — rate limiter and
//     SSE fan-out clients depend on a working Redis, and redis 7 silently
//     disables AUTH when the password is empty.
func (c Config) Validate() error {
	if c.DevMode {
		if !c.devModeConfirmed {
			return ErrUnconfirmedDevMode
		}
	} else {
		if c.InternalSessionSecret == "" {
			return ErrMissingSessionSecret
		}
		if len(c.InternalSessionSecret) < MinSessionSecretLen {
			return ErrWeakSessionSecret
		}
	}
	if c.RedisURL == "" {
		if c.DevMode {
			return nil
		}
		return ErrMissingRedisURL
	}
	u, err := url.Parse(c.RedisURL)
	if err != nil {
		// Intentionally do not wrap err: url.Error.Error() embeds the
		// input URL verbatim, which would leak the password through any
		// logger that captures the error chain.
		return errors.New("config: REDIS_URL is malformed")
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
