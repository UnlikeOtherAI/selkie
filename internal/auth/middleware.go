// Package auth provides JWT-based authentication middleware and helpers.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/silkie/internal/config"
)

// Claims holds the authenticated user identity extracted from a JWT.
type Claims struct {
	Sub     string
	IsSuper bool
}

type contextKey string

const claimsContextKey contextKey = "auth.claims"

type sessionClaims struct {
	IsSuper bool `json:"is_super"`
	jwt.RegisteredClaims
}

// Middleware returns an HTTP middleware that validates Bearer JWTs and injects Claims into context.
func Middleware(cfg config.Config) func(http.Handler) http.Handler {
	secret := []byte(cfg.InternalSessionSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			if authorization == "" {
				writeUnauthorized(w)
				return
			}

			tokenString := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
			if tokenString == authorization || tokenString == "" {
				writeUnauthorized(w)
				return
			}

			parsedClaims := &sessionClaims{}
			token, err := jwt.ParseWithClaims(tokenString, parsedClaims, func(token *jwt.Token) (any, error) {
				if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, jwt.ErrTokenSignatureInvalid
				}

				return secret, nil
			}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
			if err != nil || !token.Valid || parsedClaims.Subject == "" {
				writeUnauthorized(w)
				return
			}

			claims := Claims{
				Sub:     parsedClaims.Subject,
				IsSuper: parsedClaims.IsSuper,
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
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
