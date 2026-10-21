package direct_test

import (
	"context"

	"github.com/unlikeotherai/selkie/internal/auth"
)

// Product resource tests use explicit authority; UOA admission has its own integration gate.
func fixtureSessionValidator() auth.SessionValidator {
	return auth.SessionValidatorFunc(func(_ context.Context, claims auth.Claims) (auth.Claims, error) { return claims, nil })
}
