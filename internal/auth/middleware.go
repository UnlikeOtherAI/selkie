// Package auth provides JWT-based authentication middleware and helpers.
package auth

import (
	"context"
	"encoding/json"
	"errors"
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
	// jwtIATSkew caps how far into the future an iat ("issued at") claim is
	// allowed to drift. golang-jwt's default leeway is applied symmetrically
	// to nbf/exp but iat is otherwise unchecked — a token minted with a far-
	// future iat would parse successfully even though something is clearly
	// wrong with the issuer's clock or the token itself.
	jwtIATSkew = JWTLeeway
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
				ua := audit.TruncateUserAgent(r.UserAgent())
				// Detach from r.Context() so a client TCP-RST mid-write
				// (typical credential-stuffer signature) cannot suppress
				// the audit row — the most suspicious callers must still
				// leave a forensic trail. Bound the write so a Postgres
				// stall cannot pile up goroutines.
				auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), rejectAuditTimeout)
				defer cancel()
				_ = auditor.Log(auditCtx, audit.Event{ //nolint:errcheck // reject-path audit is best-effort and must not block the 401
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
			claims, reason := authenticateBearer(r.Header.Get("Authorization"), secret)
			if reason != "" {
				reject(w, r, reason)
				return
			}
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authenticateBearer parses and validates the Authorization header. It returns
// the resolved Claims on success, or a non-empty reason string identifying the
// failure mode for audit logging. Splitting this out of Middleware keeps the
// request handler short and its cognitive complexity bounded.
func authenticateBearer(authorization string, secret []byte) (Claims, string) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return Claims{}, "missing_authorization"
	}
	tokenString := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if tokenString == authorization || tokenString == "" {
		return Claims{}, "missing_bearer_scheme"
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
		return Claims{}, "invalid_token"
	}
	// Reject tokens whose iat is implausibly in the future. jwt/v5 applies
	// leeway to nbf/exp but does not constrain iat, so a token minted with
	// iat = now + 10y would otherwise be honored for its full exp window.
	// Treat a missing iat as iat=0 (epoch), which trivially passes — only
	// future drift is interesting.
	if iat := parsedClaims.IssuedAt; iat != nil && iat.After(time.Now().Add(jwtIATSkew)) {
		return Claims{}, "iat_in_future"
	}

	claims := Claims{
		Sub:      parsedClaims.Subject,
		IsSuper:  parsedClaims.IsSuper,
		Audience: []string(parsedClaims.Audience),
	}
	if !claims.HasAudience(AudienceAdmin) && !claims.HasAudience(AudienceMobile) {
		return Claims{}, "unrecognized_audience"
	}
	return claims, ""
}

// shouldAuditReject consults the rate limiter to decide whether the current
// reject should produce an audit row.
//
// Decision tree:
//   - limiter is nil (dev mode without Redis and without the memory fallback)
//     or the resolved IP is empty (unparseable peer — already a red flag):
//     always audit; the configuration is "no rate limiting available", which
//     is fine because the volume in that mode is small.
//   - limiter returns ErrMemoryLimiterOverloaded: drop the audit row. The
//     limiter is at its bucket cap, meaning the working-set of distinct
//     attacker IPs has already saturated it. Fail-open here would let that
//     attacker keep amplifying into one audit INSERT per request, defeating
//     the entire purpose of the cap.
//   - any other limiter error (Redis transient outage, context deadline):
//     audit. A working audit trail during a Redis blip beats silent attacker
//     activity, and these errors are bounded in volume by Redis health.
func shouldAuditReject(ctx context.Context, limiter ratelimit.Limiter, ip string) bool {
	if limiter == nil || ip == "" {
		return true
	}
	decision, err := limiter.Allow(ctx, ratelimit.Key("auth", "reject", "ip", audit.RateLimitIP(ip)), rejectAuditLimit, rejectAuditWindow)
	if err != nil {
		// Fail-closed only when the in-memory limiter signals overload;
		// every other error (Redis blip, context deadline) falls back to
		// audit-on so the trail survives transient infrastructure issues.
		return !errors.Is(err, ratelimit.ErrMemoryLimiterOverloaded)
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
