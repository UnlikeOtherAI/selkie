package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

var debugCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (h *CallbackHandler) limitDebug(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	return h.allowRateLimit(r.Context(), w, ratelimit.Key("auth", "debug-login", "ip", audit.RateLimitIP(audit.ClientIP(r, h.cfg.TrustedProxyCIDRs))), 20)
}

func (h *CallbackHandler) ServeDebugIssue(w http.ResponseWriter, r *http.Request) {
	if !h.limitDebug(w, r) {
		return
	}
	var body struct {
		PreviousToken string `json:"previous_token,omitempty"`
	}
	if err := decodeSingleJSONObject(r, &body); err != nil || (!validPreviousDebugCode(body.PreviousToken)) {
		writeJSONError(w, http.StatusBadRequest, "invalid login code request")
		return
	}
	claims, ok := h.sessionAuth(w, r)
	if !ok {
		return
	}
	if !claims.HasAudience(AudienceAdmin) {
		writeJSONError(w, http.StatusForbidden, "admin session required")
		return
	}
	manager := h.sessions
	if _, _, err := manager.resolve(r.Context(), claims.SessionID, claims.Sub); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session temporarily unavailable")
		return
	}
	tx, err := h.db.Pool.Begin(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "login code temporarily unavailable")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // read-lock transaction only
	var sealed []byte
	if err = tx.QueryRow(r.Context(), `SELECT sealed_capability FROM uoa_sessions WHERE id::text=$1 AND user_id::text=$2 AND NOT closing AND expires_at>now() AND capability_kind='refresh' FOR UPDATE`, claims.SessionID, claims.Sub).Scan(&sealed); err != nil {
		writeUnauthorized(w)
		return
	}
	refresh, err := manager.open(sealed)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "login code temporarily unavailable")
		return
	}
	request := map[string]string{fieldRefreshToken: refresh}
	if body.PreviousToken != "" {
		request["previous_token"] = body.PreviousToken
	}
	var result struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err = uoaRequest(r.Context(), h.cfg, http.MethodPost, "/auth/debug-login/issue", request, &result); err != nil || !debugCodePattern.MatchString(result.Token) || result.ExpiresIn != 1800 {
		writeJSONError(w, http.StatusServiceUnavailable, "login code temporarily unavailable")
		return
	}
	origin, err := h.debugOrigin()
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "login URL unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": origin, fieldToken: result.Token})
}

func (h *CallbackHandler) debugOrigin() (string, error) {
	parsed, err := url.Parse(h.cfg.UOARedirectURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", errors.New("invalid callback origin")
	}
	return parsed.Scheme + "://" + parsed.Host + "/", nil
}

func (h *CallbackHandler) ServeDebugRedeem(w http.ResponseWriter, r *http.Request) {
	if !h.limitDebug(w, r) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeSingleJSONObject(r, &body); err != nil || !debugCodePattern.MatchString(body.Token) {
		writeJSONError(w, http.StatusBadRequest, "paste a valid login code")
		return
	}
	var tokens tokenExchangeResponse
	if err := uoaRequest(r.Context(), h.cfg, http.MethodPost, "/auth/debug-login/redeem", body, &tokens); err != nil {
		if errors.Is(err, errUOARefused) {
			writeJSONError(w, http.StatusUnauthorized, "login code expired or already used")
		} else {
			writeJSONError(w, http.StatusServiceUnavailable, "login temporarily unavailable; retry")
		}
		return
	}
	claims, err := decodeUOAToken(tokens.AccessToken)
	if err != nil || tokens.RefreshToken == "" || tokens.RefreshTokenExpiresIn <= 0 {
		writeJSONError(w, http.StatusServiceUnavailable, "invalid UOA session response")
		return
	}
	// On local admission failure, revoke the independent family UOA just minted.
	admitted := false
	defer func(ctx context.Context) {
		if !admitted {
			h.discardFamily(ctx, tokens.RefreshToken)
		}
	}(r.Context())
	profile, err := currentUOAProfile(r.Context(), h.cfg, claims.Subject)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "profile temporarily unavailable")
		return
	}
	claims.Email = profile.Email
	claims.DisplayName = profile.DisplayName
	claims.RefreshToken = tokens.RefreshToken
	claims.RefreshExpiresIn = tokens.RefreshTokenExpiresIn
	userID, isSuper, err := h.upsertUser(r.Context(), claims)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session temporarily unavailable")
		return
	}
	sessionID, err := h.sessions.create(r.Context(), userID, claims)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session temporarily unavailable")
		return
	}
	token, err := h.mintSessionToken(userID, isSuper, sessionID, []string{AudienceAdmin})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session temporarily unavailable")
		return
	}
	admitted = true
	writeJSON(w, http.StatusOK, map[string]string{fieldToken: token})
}

func validPreviousDebugCode(token string) bool {
	return token == "" || debugCodePattern.MatchString(token)
}

func (h *CallbackHandler) discardFamily(ctx context.Context, refresh string) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := uoaRequest(cleanup, h.cfg, http.MethodPost, "/auth/revoke", map[string]string{fieldRefreshToken: refresh, "scope": revokeScopeFamily}, nil); err != nil && h.logger != nil {
		h.logger.Warn("failed to revoke rejected session family")
	}
}
