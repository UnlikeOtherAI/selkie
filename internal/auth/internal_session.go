package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

const (
	// internalMintSessionLimit / Window bound how many brokered sessions a
	// single peer IP can mint per minute. The caller is the trusted host-local
	// Coder API doing roughly one call per user login, so the cap is generous;
	// it exists so a looping or compromised caller cannot hammer the user
	// upsert path unbounded.
	internalMintSessionLimit  = 60
	internalMintSessionWindow = time.Minute
)

// internalMintSessionRequest is the service-to-service body. The keys are
// camelCase to match the cross-service contract the Coder API sends (mirroring
// the Ledger ProxyToken provisioning pattern), rather than selkie's snake_case
// browser/mobile JSON.
type internalMintSessionRequest struct {
	UOASub      string `json:"uoaSub"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}

// ServeInternalMintSession is the service-to-service session broker. A trusted
// host-local caller (the Coder API) presents a shared service key and a UOA
// sub; selkie upserts the matching user via the EXACT path a normal login uses
// and returns a freshly minted mobile-audience session JWT the caller can hand
// to the app for POST /api/v1/mobile/enroll.
//
// Response codes:
//   - 503 when SELKIE_INTERNAL_SERVICE_KEY is unset (feature disabled)
//   - 401 when the Authorization bearer key is missing or wrong
//   - 400 on a malformed body or missing uoaSub/email
//   - 200 with {"token": ..., "expires_at": <RFC3339>} on success
func (h *CallbackHandler) ServeInternalMintSession(w http.ResponseWriter, r *http.Request) {
	serviceKey := strings.TrimSpace(h.cfg.InternalServiceKey)
	if serviceKey == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "internal session broker not configured")
		return
	}

	if !validInternalServiceKey(r.Header.Get("Authorization"), serviceKey) {
		writeUnauthorized(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	sourceIP := audit.ClientIP(r, h.cfg.TrustedProxyCIDRs)
	if !h.allowRateLimit(ctx, w, ratelimit.Key("internal", "mint-session", "ip", audit.RateLimitIP(sourceIP)), internalMintSessionLimit, internalMintSessionWindow) {
		return
	}

	var req internalMintSessionRequest
	if err := decodeSingleJSONObject(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	uoaSub := strings.TrimSpace(req.UOASub)
	email := strings.TrimSpace(req.Email)
	if uoaSub == "" {
		writeJSONError(w, http.StatusBadRequest, "uoaSub is required")
		return
	}
	if email == "" {
		writeJSONError(w, http.StatusBadRequest, "email is required")
		return
	}

	claims := &UOAClaims{Email: email, DisplayName: strings.TrimSpace(req.DisplayName)}
	claims.Subject = uoaSub

	userID, isSuper, err := h.upsertUserFn(ctx, claims)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("internal mint-session upsert", zap.Error(err))
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to provision user")
		return
	}

	displayName := claims.DisplayName
	if displayName == "" {
		displayName = email
	}
	token, err := h.mintToken(userID, isSuper, email, displayName, "", []string{AudienceMobile})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to mint session token")
		return
	}

	h.auditInternalMintSession(ctx, r, userID)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": time.Now().UTC().Add(sessionTokenTTL).Format(time.RFC3339),
	})
}

// validInternalServiceKey extracts the bearer token from an Authorization
// header and compares it against the configured service key in constant time.
func validInternalServiceKey(authorization, serviceKey string) bool {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if provided == authorization || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(serviceKey)) == 1
}

func (h *CallbackHandler) auditInternalMintSession(ctx context.Context, r *http.Request, userID string) {
	if h.audit == nil {
		return
	}
	if auditErr := h.audit.Log(ctx, audit.Event{
		ActorUserID: &userID,
		Action:      "internal.mint_session",
		Outcome:     "success",
		TargetTable: "users",
		TargetID:    &userID,
		RemoteIP:    audit.ClientIP(r, h.cfg.TrustedProxyCIDRs),
		UserAgent:   audit.TruncateUserAgent(r.UserAgent()),
	}); auditErr != nil && h.logger != nil {
		h.logger.Error("audit internal.mint_session", zap.Error(auditErr))
	}
}
