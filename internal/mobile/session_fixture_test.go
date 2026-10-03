//nolint:testpackage // Fixtures serve endpoint unit tests in this package.
package mobile

import (
	"context"

	"github.com/unlikeotherai/selkie/internal/auth"
)

// fixtureSessionValidator isolates business handlers from the tested UOA transport.
func fixtureSessionValidator() auth.SessionValidator {
	return auth.SessionValidatorFunc(func(_ context.Context, claims auth.Claims) (auth.Claims, error) { return claims, nil })
}
