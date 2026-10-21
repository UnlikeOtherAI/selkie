package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mintSessionToken preserves mobile bearer transport without copying profiles.
func (h *CallbackHandler) mintSessionToken(userID string, isSuper bool, sessionID string, audience []string) (string, error) {
	return h.mintSessionTokenUntil(userID, isSuper, sessionID, audience, time.Now().Add(sessionTokenTTL))
}

func (h *CallbackHandler) mintSessionTokenUntil(userID string, isSuper bool, sessionID string, audience []string, expiresAt time.Time) (string, error) {
	if sessionID == "" || len(audience) == 0 {
		return "", errors.New("session reference and audience are required")
	}
	now := time.Now()
	claims := sessionClaims{IsSuper: isSuper, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: Issuer, Subject: userID, ID: sessionID, Audience: jwt.ClaimStrings(audience), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expiresAt),
	}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(h.cfg.InternalSessionSecret))
}
