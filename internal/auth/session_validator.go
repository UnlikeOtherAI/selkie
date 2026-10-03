package auth

import "context"

// SessionValidator checks a live relying-party capability after JWT verification.
type SessionValidator interface {
	Validate(context.Context, Claims) (Claims, error)
}

// SessionValidatorFunc adapts a session validator for dependency injection.
type SessionValidatorFunc func(context.Context, Claims) (Claims, error)

func (f SessionValidatorFunc) Validate(ctx context.Context, claims Claims) (Claims, error) {
	return f(ctx, claims)
}

func (m *SessionManager) Validate(ctx context.Context, claims Claims) (Claims, error) {
	_, isSuper, err := m.resolve(ctx, claims.SessionID, claims.Sub)
	if err != nil {
		return Claims{}, err
	}
	claims.IsSuper = isSuper
	return claims, nil
}

func validateSession(ctx context.Context, claims Claims, validators []SessionValidator) (Claims, error) {
	if len(validators) == 0 || validators[0] == nil {
		return Claims{}, errSessionExpired
	}
	return validators[0].Validate(ctx, claims)
}
