package auth

import (
	"context"
	"crypto/subtle"
	"errors"
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
	UOASub     string `json:"uoaSub"` //nolint:tagliatelle // Coder service contract uses camelCase.
	Capability string `json:"capability"`
}

// ServeInternalMintSession is the service-to-service session broker. A trusted
// host-local caller presents a service key and a UOA-issued exact-audience
// session:broker capability. UOA validates its live subject authority. Selkie
// returns a mobile handle whose lifetime cannot exceed the capability expiry.
//
// Response codes:
//   - 503 when SELKIE_INTERNAL_SERVICE_KEY is unset (feature disabled)
//   - 401 when the Authorization bearer key is missing or wrong
//   - 400 on a malformed body or missing uoaSub/capability
//   - 200 with {fieldToken: ..., fieldExpiresAt: <RFC3339>} on success
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
	if !h.allowRateLimit(ctx, w, ratelimit.Key("internal", "mint-session", "ip", audit.RateLimitIP(sourceIP)), internalMintSessionLimit) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var req internalMintSessionRequest
	if err := decodeSingleJSONObject(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	uoaSub := strings.TrimSpace(req.UOASub)
	if uoaSub == "" || strings.TrimSpace(req.Capability) == "" {
		writeJSONError(w, http.StatusBadRequest, "uoaSub and capability are required")
		return
	}
	validation, err := validateBrokerCapability(ctx, h.cfg, req.Capability)
	if err != nil {
		if errors.Is(err, errUOARefused) {
			writeUnauthorized(w)
		} else {
			writeJSONError(w, http.StatusServiceUnavailable, "broker authority temporarily unavailable")
		}
		return
	}
	if validation.Sub != uoaSub {
		writeUnauthorized(w)
		return
	}
	profile, err := currentUOAProfile(ctx, h.cfg, validation.Sub)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "profile temporarily unavailable")
		return
	}
	userID, isSuper, err := h.upsertUserFn(ctx, profile)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "failed to provision user")
		return
	}
	sessionID, err := h.createBrokerFn(ctx, userID, req.Capability, validation)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "failed to create broker session")
		return
	}
	token, err := h.mintSessionTokenUntil(userID, isSuper, sessionID, []string{AudienceMobile}, validation.ExpiresAt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to mint session token")
		return
	}

	h.auditInternalMintSession(ctx, r, userID)

	writeJSON(w, http.StatusOK, map[string]any{
		fieldToken:     token,
		fieldExpiresAt: validation.ExpiresAt.UTC().Format(time.RFC3339),
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
		Outcome:     auditOutcomeSuccess,
		TargetTable: auditTargetUsers,
		TargetID:    &userID,
		RemoteIP:    audit.ClientIP(r, h.cfg.TrustedProxyCIDRs),
		UserAgent:   audit.TruncateUserAgent(r.UserAgent()),
	}); auditErr != nil && h.logger != nil {
		h.logger.Error("audit internal.mint_session", zap.Error(auditErr))
	}
}
