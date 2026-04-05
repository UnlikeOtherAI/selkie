package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/unlikeotherai/silkie/internal/audit"
	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/store"
)

// CallbackHandler handles the OAuth callback from UOA, upserting the user and issuing a session JWT.
type CallbackHandler struct {
	db     *store.DB
	cfg    config.Config
	audit  *audit.Logger
	logger *zap.Logger
}

// NewCallbackHandler creates a CallbackHandler with the given database, config, and audit logger.
func NewCallbackHandler(db *store.DB, cfg config.Config, auditor *audit.Logger, logger *zap.Logger) *CallbackHandler {
	return &CallbackHandler{db: db, cfg: cfg, audit: auditor, logger: logger}
}

// Mount registers the auth routes on the given router.
func (h *CallbackHandler) Mount(r chi.Router) {
	r.Get("/auth/login", h.ServeLogin)
	r.Get("/auth/callback", h.ServeCallback)
}

// ServeLogin redirects the user to the UOA authorization URL.
func (*CallbackHandler) ServeLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, BuildAuthURL(), http.StatusFound)
}

// ServeCallback processes the OAuth callback, exchanges the code, upserts the user, and redirects with a JWT.
func (h *CallbackHandler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	uoaClaims, err := ExchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "auth failed", http.StatusUnauthorized)
		return
	}

	userID, isSuper, err := h.upsertUser(r.Context(), uoaClaims)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if h.audit != nil {
		if auditErr := h.audit.Log(r.Context(), audit.Event{
			ActorUserID: &userID,
			Action:      "user.login",
			Outcome:     "success",
			TargetTable: "users",
			TargetID:    &userID,
			RemoteIP:    audit.RemoteAddr(r),
			UserAgent:   r.UserAgent(),
		}); auditErr != nil {
			h.logger.Error("audit user.login", zap.Error(auditErr))
		}
	}

	token, err := h.mintToken(userID, isSuper)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin#token="+token, http.StatusFound)
}

func (h *CallbackHandler) upsertUser(ctx context.Context, claims *UOAClaims) (string, bool, error) {
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	// Check if this is the very first user.
	var count int
	if countErr := tx.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count); countErr != nil {
		return "", false, countErr
	}
	firstUser := count == 0

	email := claims.Email
	displayName := claims.DisplayName
	if displayName == "" {
		displayName = email
	}

	var userID string
	var isSuper bool
	err = tx.QueryRow(ctx, `
		INSERT INTO users (external_id, email, display_name, is_super, last_login_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (external_id) DO UPDATE
			SET email = EXCLUDED.email,
			    display_name = EXCLUDED.display_name,
			    last_login_at = now(),
			    updated_at = now()
		RETURNING id, is_super
	`, claims.Subject, email, displayName, firstUser).Scan(&userID, &isSuper)
	if err != nil {
		return "", false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return userID, isSuper || firstUser, nil
}

type jwtClaims struct {
	Sub     string `json:"sub"`
	IsSuper bool   `json:"is_super"`
	jwt.RegisteredClaims
}

func (h *CallbackHandler) mintToken(userID string, isSuper bool) (string, error) {
	now := time.Now()
	c := jwtClaims{
		Sub:     userID,
		IsSuper: isSuper,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "silkie",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).
		SignedString([]byte(h.cfg.InternalSessionSecret))
}
