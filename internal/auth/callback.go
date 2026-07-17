package auth

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
)

const (
	mobileHandoffTTL            = 60 * time.Second
	mobileHandoffExchangeLimit  = 10
	mobileHandoffExchangeWindow = time.Minute
	mobileHandoffFailureLimit   = 10
	mobileHandoffFailureWindow  = time.Minute

	// loginFlowCookieTTL bounds how long a started login (PKCE verifier cookie)
	// remains valid before the user must restart the flow.
	loginFlowCookieTTL = 10 * time.Minute

	// pkceVerifierCookieName holds the PKCE code_verifier across the UOA
	// round-trip. It is HttpOnly + SameSite=Lax so it survives the top-level
	// GET redirect back from UOA but is never readable by scripts. UOA does
	// not echo an OAuth `state` parameter, so this cookie + PKCE is the CSRF
	// binding for the callback.
	pkceVerifierCookieName = "selkie_pkce_verifier"

	// sessionTokenTTL is the lifetime of every session JWT mintToken issues.
	// Extracted so the mobile handoff exchange and the internal mint-session
	// broker report an expiry that always tracks the signed token's exp.
	sessionTokenTTL = 24 * time.Hour
)

// CallbackHandler handles the OAuth callback from UOA, upserting the user and issuing a session JWT.
type CallbackHandler struct {
	db      *store.DB
	cfg     config.Config
	audit   *audit.Logger
	logger  *zap.Logger
	limiter ratelimit.Limiter
	// upsertUserFn indirects the user-upsert step so the internal S2S
	// mint-session handler can be exercised without a live database. In
	// production it points at h.upsertUser — the EXACT path a browser or
	// mobile login uses — so the user row a brokered session produces is
	// identical to a normal login (first user becomes super, etc.).
	upsertUserFn func(ctx context.Context, claims *UOAClaims) (string, bool, error)
}

// NewCallbackHandler creates a CallbackHandler with the given database, config, and audit logger.
func NewCallbackHandler(db *store.DB, cfg config.Config, auditor *audit.Logger, logger *zap.Logger, limiter ratelimit.Limiter) *CallbackHandler {
	h := &CallbackHandler{db: db, cfg: cfg, audit: auditor, logger: logger, limiter: limiter}
	h.upsertUserFn = h.upsertUser
	return h
}

// Mount registers the auth routes on the given router.
func (h *CallbackHandler) Mount(r chi.Router) {
	r.Get("/auth/uoa-config", h.ServeUOAConfig)
	r.Get("/.well-known/jwks.json", h.ServeJWKS)
	r.Get("/auth/login", h.ServeLogin)
	r.Get("/auth/callback", h.ServeCallback)
	r.Get("/auth/mobile/callback", h.ServeMobileCallback)
	r.Post("/api/v1/mobile/handoff/exchange", h.ServeMobileHandoffExchange)
	// Service-to-service session broker. Trusted host-local callers (the Coder
	// API) exchange a UOA sub for a selkie mobile session JWT. Authenticated by
	// a shared service key, NOT a browser session — so it lives outside any
	// session-guarded group, like the other /api paths.
	r.Post("/api/v1/internal/mint-session", h.ServeInternalMintSession)
	r.Get("/auth/dev-status", h.ServeDevStatus)
	r.Get("/auth/dev-login", h.ServeDevLogin)
}

// ServeLogin issues a fresh PKCE verifier cookie and redirects to the UOA
// authorization URL carrying the S256 challenge. UOA does not echo an OAuth
// `state` query parameter back to the callback (it redirects to the exact
// registered redirect_url with only `?code=…`), so CSRF protection is bound to
// the HttpOnly verifier cookie + PKCE rather than a round-tripped state value.
func (h *CallbackHandler) ServeLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := newPKCE()
	if err != nil {
		if h.logger != nil {
			h.logger.Error("generate pkce", zap.Error(err))
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setPKCEVerifierCookie(w, r, verifier)
	http.Redirect(w, r, BuildAuthURL(challenge), http.StatusFound)
}

// ServeCallback processes the OAuth callback, exchanges the code, upserts the user, and redirects with a JWT.
func (h *CallbackHandler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	verifier := pkceVerifierFromCookie(r)
	// Clear the verifier immediately so a failed upstream exchange cannot leave
	// a replayable cookie for the rest of the TTL window. Its presence is the
	// CSRF binding: a callback in a browser that never started a login here
	// carries no verifier, and an injected code cannot match it (PKCE).
	clearPKCEVerifierCookie(w, r)
	if verifier == "" {
		http.Error(w, "missing or expired login session", http.StatusBadRequest)
		return
	}

	userID, isSuper, uoaClaims, err := h.exchangeAndUpsertUser(r.Context(), r.URL.Query().Get("code"), h.cfg.UOARedirectURL, verifier)
	if err != nil {
		writeExchangeError(w, err)
		return
	}

	h.auditLogin(r.Context(), r, userID)

	email := uoaClaims.Email
	displayName := uoaClaims.DisplayName
	if displayName == "" {
		displayName = email
	}
	token, err := h.mintToken(userID, isSuper, email, displayName, "", []string{AudienceAdmin})
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	//nolint:gosec // G710: redirect target is the fixed internal path "/admin"; token is our own freshly-minted session JWT placed in the fragment, not an attacker-controlled URL.
	http.Redirect(w, r, "/admin#token="+token, http.StatusFound)
}

// ServeMobileCallback exchanges the upstream auth code and redirects with a short-lived one-time handoff code.
func (h *CallbackHandler) ServeMobileCallback(w http.ResponseWriter, r *http.Request) {
	verifier := pkceVerifierFromCookie(r)
	clearPKCEVerifierCookie(w, r)
	if verifier == "" {
		http.Error(w, "missing or expired login session", http.StatusBadRequest)
		return
	}
	userID, _, _, err := h.exchangeAndUpsertUser(r.Context(), r.URL.Query().Get("code"), h.cfg.UOAMobileRedirectURL, verifier)
	if err != nil {
		writeExchangeError(w, err)
		return
	}

	h.auditLogin(r.Context(), r, userID)

	handoffCode, err := h.createMobileHandoffCode(r.Context(), userID)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("create mobile handoff code", zap.Error(err), zap.String("user_id", userID))
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirectURL, err := mobileRedirectURL(h.cfg.MobileRedirectURL, handoffCode, "")
	if err != nil {
		if h.logger != nil {
			h.logger.Error("build mobile redirect url", zap.Error(err))
		}
		http.Error(w, "mobile redirect is misconfigured", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ServeMobileHandoffExchange consumes a one-time handoff code and returns a Selkie session token.
func (h *CallbackHandler) ServeMobileHandoffExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HandoffCode string `json:"handoff_code"`
	}
	if err := decodeSingleJSONObject(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	handoffCode := strings.TrimSpace(req.HandoffCode)
	if handoffCode == "" {
		writeJSONError(w, http.StatusBadRequest, "handoff_code is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	// Cache the resolved peer IP for the whole handler. audit.ClientIP walks
	// the X-Forwarded-For chain on every call; on a hot exchange path the
	// limiter key, the failure key, and the audit row would each recompute
	// the same value, multiplying allocation cost under attack load.
	sourceIP := audit.ClientIP(r, h.cfg.TrustedProxyCIDRs)
	// Bucket the exchange limit by source IP only. Including the handoff
	// code in the key would give an attacker spamming many distinct codes
	// a fresh bucket per attempt — effectively disabling the per-IP cap on
	// exchange volume. The per-code failure counter (recordMobileHandoffFailure)
	// already enforces "this specific code may not be probed forever".
	if !h.allowRateLimit(ctx, w, ratelimit.Key("mobile", "handoff", "exchange", audit.RateLimitIP(sourceIP)), mobileHandoffExchangeLimit, mobileHandoffExchangeWindow) {
		cancel()
		return
	}
	defer cancel()

	if h.db == nil || h.db.Pool == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to start handoff exchange")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	var userID, email, displayName string
	var isSuper bool
	err = tx.QueryRow(ctx, `
UPDATE mobile_handoff_codes mh
SET consumed_at = now()
FROM users u
WHERE mh.code_hash = sha256($1::bytea)
  AND mh.user_id = u.id
  AND mh.consumed_at IS NULL
  AND mh.expires_at > now()
RETURNING u.id, u.email, u.display_name, u.is_super
`, handoffCode).Scan(&userID, &email, &displayName, &isSuper)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			h.handleInvalidMobileHandoff(ctx, w, sourceIP, handoffCode)
		default:
			if h.logger != nil {
				h.logger.Error("consume mobile handoff code", zap.Error(err))
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to exchange mobile handoff code")
		}
		return
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to finalize mobile handoff exchange")
		return
	}

	token, err := h.mintToken(userID, isSuper, email, displayName, "", []string{AudienceMobile})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to mint session token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(sessionTokenTTL.Seconds()),
	})
}

func (h *CallbackHandler) checkRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (ratelimit.Decision, error) {
	if h.limiter == nil {
		return ratelimit.Decision{}, errors.New("rate limiter unavailable")
	}
	decision, err := h.limiter.Allow(ctx, key, limit, window)
	if err != nil && h.logger != nil {
		h.logger.Error("rate limit check failed", zap.Error(err), zap.String("key", key))
	}
	return decision, err
}

func (h *CallbackHandler) allowRateLimit(ctx context.Context, w http.ResponseWriter, key string, limit int64, window time.Duration) bool {
	decision, err := h.checkRateLimit(ctx, key, limit, window)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return false
	}
	if decision.Allowed {
		return true
	}
	writeRateLimitError(w, decision.RetryAfter)
	return false
}

func (h *CallbackHandler) recordMobileHandoffFailure(ctx context.Context, sourceIP, handoffCode string) (bool, error) {
	keys := []string{
		ratelimit.Key("mobile", "handoff", "failure", "ip", audit.RateLimitIP(sourceIP)),
		ratelimit.Key("mobile", "handoff", "failure", "code", ratelimit.HashToken(handoffCode)),
	}
	for _, key := range keys {
		decision, err := h.checkRateLimit(ctx, key, mobileHandoffFailureLimit, mobileHandoffFailureWindow)
		if err != nil {
			return false, err
		}
		if !decision.Allowed {
			return false, nil
		}
	}
	return true, nil
}

func (h *CallbackHandler) handleInvalidMobileHandoff(ctx context.Context, w http.ResponseWriter, sourceIP, handoffCode string) {
	allowed, rateErr := h.recordMobileHandoffFailure(ctx, sourceIP, handoffCode)
	if rateErr != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
		return
	}
	if !allowed {
		writeRateLimitError(w, mobileHandoffFailureWindow)
		return
	}
	writeJSONError(w, http.StatusUnauthorized, "invalid mobile handoff code")
}

func (h *CallbackHandler) exchangeAndUpsertUser(ctx context.Context, code, redirectURL, codeVerifier string) (string, bool, *UOAClaims, error) {
	if strings.TrimSpace(code) == "" {
		return "", false, nil, errMissingCode
	}

	uoaClaims, err := ExchangeCode(ctx, code, redirectURL, codeVerifier)
	if err != nil {
		// Surface the upstream cause (UOA status + sanitized body, PKCE/decode
		// failures) so a failing login is diagnosable; the client still only
		// sees the opaque "auth failed".
		if h.logger != nil {
			h.logger.Warn("uoa code exchange failed", zap.Error(err))
		}
		return "", false, nil, errAuthFailed
	}

	userID, isSuper, err := h.upsertUser(ctx, uoaClaims)
	if err != nil {
		return "", false, nil, errInternal
	}

	return userID, isSuper, uoaClaims, nil
}

func (h *CallbackHandler) createMobileHandoffCode(ctx context.Context, userID string) (string, error) {
	if h.db == nil || h.db.Pool == nil {
		return "", errors.New("database is required")
	}

	for range 5 {
		code, err := randomMobileHandoffCode(32)
		if err != nil {
			return "", err
		}

		_, err = h.db.Pool.Exec(ctx, `
INSERT INTO mobile_handoff_codes (code_hash, user_id, expires_at)
VALUES (sha256($1::bytea), $2, $3)
`, code, userID, time.Now().UTC().Add(mobileHandoffTTL))
		if err == nil {
			return code, nil
		}
	}

	return "", errors.New("failed to persist mobile handoff code")
}

func (h *CallbackHandler) auditLogin(ctx context.Context, r *http.Request, userID string) {
	if h.audit == nil {
		return
	}
	if auditErr := h.audit.Log(ctx, audit.Event{
		ActorUserID: &userID,
		Action:      "user.login",
		Outcome:     "success",
		TargetTable: "users",
		TargetID:    &userID,
		RemoteIP:    audit.ClientIP(r, h.cfg.TrustedProxyCIDRs),
		UserAgent:   audit.TruncateUserAgent(r.UserAgent()),
	}); auditErr != nil && h.logger != nil {
		h.logger.Error("audit user.login", zap.Error(auditErr))
	}
}

func writeExchangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errMissingCode):
		http.Error(w, "missing code", http.StatusBadRequest)
	case errors.Is(err, errAuthFailed):
		http.Error(w, "auth failed", http.StatusUnauthorized)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *CallbackHandler) upsertUser(ctx context.Context, claims *UOAClaims) (string, bool, error) {
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

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
	Sub         string `json:"sub"`
	IsSuper     bool   `json:"is_super"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}

// TODO(replay-defense): tokens here are bearer-only with a 24h expiry. A stolen
// JWT is valid until exp. Mitigating this requires a server-side session table
// keyed on `jti` with a per-request lookup in auth.Middleware (or an explicit
// revocation list). Tracked separately; not a regression introduced here.
func (h *CallbackHandler) mintToken(userID string, isSuper bool, email, displayName, picture string, audience []string) (string, error) {
	if len(audience) == 0 {
		return "", errors.New("audience is required")
	}
	now := time.Now()
	c := jwtClaims{
		Sub:         userID,
		IsSuper:     isSuper,
		Email:       email,
		DisplayName: displayName,
		Picture:     picture,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTokenTTL)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).
		SignedString([]byte(h.cfg.InternalSessionSecret))
}

var (
	errMissingCode = errors.New("missing code")
	errAuthFailed  = errors.New("auth failed")
	errInternal    = errors.New("internal error")
)

func decodeSingleJSONObject(r *http.Request, dst any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain a single JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func randomMobileHandoffCode(length int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	chars := make([]byte, length)
	bound := big.NewInt(int64(len(alphabet)))
	for i := range chars {
		n, err := crand.Int(crand.Reader, bound)
		if err != nil {
			return "", err
		}
		chars[i] = alphabet[n.Int64()]
	}

	return string(chars), nil
}

func setPKCEVerifierCookie(w http.ResponseWriter, r *http.Request, verifier string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set per-request via isHTTPS(r); HttpOnly + SameSite=Lax are always set.
		Name:     pkceVerifierCookieName,
		Value:    verifier,
		Path:     "/",
		Expires:  time.Now().Add(loginFlowCookieTTL),
		MaxAge:   int(loginFlowCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearPKCEVerifierCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set per-request via isHTTPS(r); HttpOnly + SameSite=Lax are always set.
		Name:     pkceVerifierCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func pkceVerifierFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(pkceVerifierCookieName)
	if err != nil || cookie == nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}

func mobileRedirectURL(baseURL, handoffCode, state string) (string, error) {
	if strings.TrimSpace(baseURL) == "" {
		return "", errors.New("mobile redirect url is required")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	query.Set("handoff_code", handoffCode)
	if strings.TrimSpace(state) != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
