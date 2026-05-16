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
// expired tokens.
func Middleware(cfg config.Config, auditor *audit.Logger) func(http.Handler) http.Handler {
	secret := []byte(cfg.InternalSessionSecret)
	trusted := cfg.TrustedProxyCIDRs

	reject := func(w http.ResponseWriter, r *http.Request, reason string) {
		if auditor != nil {
			_ = auditor.Log(r.Context(), audit.Event{
				Action:    "auth.middleware.reject",
				Outcome:   "deny",
				RemoteIP:  audit.ClientIP(r, trusted),
				UserAgent: r.UserAgent(),
				Metadata:  map[string]any{"reason": reason},
			})
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
