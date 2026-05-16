// Package auth provides JWT-based authentication middleware and helpers.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

// Issuer is the iss claim value Selkie embeds in every session token it mints.
const Issuer = "selkie"

// Audience values accepted on Selkie session tokens.
const (
	AudienceAdmin  = "admin"
	AudienceMobile = "mobile"
)

// JWTLeeway is the clock skew tolerance applied when verifying session JWTs.
const JWTLeeway = 30 * time.Second

// rejectAuditLimit caps how many reject-audit rows a single peer IP can mint
// per minute. The reject path runs BEFORE JWT verification succeeds, so
// without this cap an unauthenticated burst of `Authorization: Bearer x`
// becomes one audit_events INSERT per request — a DoS amplifier and an
// audit-table poisoning vector. The cap is generous enough that legitimate
// token-expiry retries always fit but tight enough that a credential-stuffing
// flood degrades to "first N per minute, then dropped" rather than saturating
// Postgres writes.
const (
	rejectAuditLimit  = 30
	rejectAuditWindow = time.Minute
	// rejectAuditTimeout bounds the audit write so a Postgres stall on the
	// reject path cannot pile up goroutines proportional to the attack rate.
	rejectAuditTimeout = 2 * time.Second
	// maxAuditUserAgent caps the User-Agent length copied into the audit
	// row. Go's default MaxHeaderBytes is 1MiB; without truncation a
	// crafted UA can bloat the audit table by ~1MB/row at the attack rate.
	maxAuditUserAgent = 512
)

// Claims holds the authenticated user identity extracted from a JWT.
type Claims struct {
	Sub      string
	IsSuper  bool
	Audience []string
}

// HasAudience reports whether the claims include the given audience value.
func (c Claims) HasAudience(audience string) bool {
	for _, a := range c.Audience {
		if a == audience {
			return true
		}
	}
	return false
}

type contextKey string

const claimsContextKey contextKey = "auth.claims"

type sessionClaims struct {
	IsSuper bool `json:"is_super"`
	jwt.RegisteredClaims
}

// Middleware returns an HTTP middleware that validates Bearer JWTs and
// injects Claims into context. When auditor is non-nil, every rejected
// request emits an "auth.middleware.reject" audit row with the failure
// reason so forensic queries can distinguish credential-stuffing from
// expired tokens. When limiter is non-nil, reject-audit writes are gated
// behind a per-peer-IP token bucket so an unauthenticated flood cannot
// amplify into one DB write per request.
func Middleware(cfg config.Config, auditor *audit.Logger, limiter ratelimit.Limiter) func(http.Handler) http.Handler {
	secret := []byte(cfg.InternalSessionSecret)
	trusted := cfg.TrustedProxyCIDRs

	reject := func(w http.ResponseWriter, r *http.Request, reason string) {
		if auditor != nil {
			ip := audit.ClientIP(r, trusted)
			if shouldAuditReject(r.Context(), limiter, ip) {
				ua := r.UserAgent()
				if len(ua) > maxAuditUserAgent {
					// Truncate on a byte boundary then strip any partial
					// multi-byte rune at the tail. Without this, a UA that
					// happens to straddle a UTF-8 boundary at offset 512
					// becomes invalid UTF-8 and Postgres rejects the audit
					// INSERT — the very write the truncation was meant to
					// keep cheap.
					ua = strings.ToValidUTF8(ua[:maxAuditUserAgent], "")
				}
				// Detach from r.Context() so a client TCP-RST mid-write
				// (typical credential-stuffer signature) cannot suppress
				// the audit row — the most suspicious callers must still
				// leave a forensic trail. Bound the write so a Postgres
				// stall cannot pile up goroutines.
				auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), rejectAuditTimeout)
				defer cancel()
				_ = auditor.Log(auditCtx, audit.Event{
					Action:    "auth.middleware.reject",
					Outcome:   "deny",
					RemoteIP:  ip,
					UserAgent: ua,
					Metadata:  map[string]any{"reason": reason},
				})
			}
		}
		writeUnauthorized(w)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			if authorization == "" {
				reject(w, r, "missing_authorization")
				return
			}

			tokenString := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
			if tokenString == authorization || tokenString == "" {
				reject(w, r, "missing_bearer_scheme")
				return
			}

			parsedClaims := &sessionClaims{}
			token, err := jwt.ParseWithClaims(tokenString, parsedClaims, func(token *jwt.Token) (any, error) {
				if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, jwt.ErrTokenSignatureInvalid
				}

				return secret, nil
			},
				jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
				jwt.WithIssuer(Issuer),
				jwt.WithExpirationRequired(),
				jwt.WithLeeway(JWTLeeway),
			)
			if err != nil || !token.Valid || parsedClaims.Subject == "" {
				reject(w, r, "invalid_token")
				return
			}

			claims := Claims{
				Sub:      parsedClaims.Subject,
				IsSuper:  parsedClaims.IsSuper,
				Audience: []string(parsedClaims.Audience),
			}
			if !claims.HasAudience(AudienceAdmin) && !claims.HasAudience(AudienceMobile) {
				reject(w, r, "unrecognized_audience")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// shouldAuditReject consults the rate limiter to decide whether the current
// reject should produce an audit row. When the limiter is nil (dev mode
// without Redis and without the memory fallback) or the resolved IP is empty
// (unparseable peer — already a red flag) we always audit. Limiter errors
// are treated as "always audit" rather than "always drop": a working audit
// trail during a Redis outage beats silent attacker activity.
func shouldAuditReject(ctx context.Context, limiter ratelimit.Limiter, ip string) bool {
	if limiter == nil || ip == "" {
		return true
	}
	decision, err := limiter.Allow(ctx, ratelimit.Key("auth", "reject", "ip", audit.RateLimitIP(ip)), rejectAuditLimit, rejectAuditWindow)
	if err != nil {
		return true
	}
	return decision.Allowed
}

// RequireAudience returns a middleware that rejects requests whose Claims do
// not include the given audience value. It must be mounted after Middleware.
func RequireAudience(audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !claims.HasAudience(audience) {
				writeUnauthorized(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFromContext retrieves the authenticated Claims from the request context.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(Claims)
	return claims, ok
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}) //nolint:errcheck // best-effort write to HTTP response
}
