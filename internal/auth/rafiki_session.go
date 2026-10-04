package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

// ServeRafikiSession trusts only the separately configured Rafiki service key.
// Rafiki binds the UOA subject and home id to its authenticated product session;
// neither value may be accepted from an untrusted native request body there.
func (h *CallbackHandler) ServeRafikiSession(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(h.cfg.RafikiServiceKey)
	if key == "" || h.cfg.RafikiHomeDeviceID == "" {
		writeJSONError(w, 503, "Rafiki connector not configured")
		return
	}
	if !validInternalServiceKey(r.Header.Get("Authorization"), key) {
		writeUnauthorized(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if !h.allowRateLimit(ctx, w, ratelimit.Key("internal", "rafiki-session"), internalMintSessionLimit, internalMintSessionWindow) {
		return
	}
	var req struct {
		UOASub                 string `json:"uoaSub"`                 //nolint:tagliatelle // Matches Rafiki S2S contract.
		AuthorizationExpiresAt string `json:"authorizationExpiresAt"` //nolint:tagliatelle // Trusted assertion contract.
		HomeDeviceID           string `json:"homeDeviceId"`           //nolint:tagliatelle // Matches Rafiki S2S contract.
	}
	if err := decodeSingleJSONObject(r, &req); err != nil || strings.TrimSpace(req.UOASub) == "" || strings.TrimSpace(req.HomeDeviceID) == "" {
		writeJSONError(w, 400, "UOA subject and home device required")
		return
	}
	if req.HomeDeviceID != h.cfg.RafikiHomeDeviceID {
		writeJSONError(w, 403, "home device outside connector scope")
		return
	}
	var authorized bool
	if err := h.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND status='active' AND direct_home_port IS NOT NULL)`, req.HomeDeviceID).Scan(&authorized); err != nil || !authorized {
		writeJSONError(w, 404, "home device unavailable")
		return
	}
	claims := &UOAClaims{}
	claims.Subject = strings.TrimSpace(req.UOASub)
	userID, _, err := h.upsertUserFn(ctx, claims)
	if err != nil {
		writeJSONError(w, 503, "UOA reference unavailable")
		return
	}
	now := time.Now()
	expiresAt, expiryErr := time.Parse(time.RFC3339, req.AuthorizationExpiresAt)
	if expiryErr != nil || !expiresAt.After(now) {
		writeJSONError(w, 400, "current authorization expiry required")
		return
	}
	if limit := now.Add(5 * time.Minute); expiresAt.After(limit) {
		expiresAt = limit
	}
	scoped := sessionClaims{DirectHomeID: req.HomeDeviceID, RegisteredClaims: jwt.RegisteredClaims{Issuer: Issuer, Subject: userID, Audience: jwt.ClaimStrings{AudienceMobile}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expiresAt)}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, scoped).SignedString([]byte(h.cfg.InternalSessionSecret))
	if err != nil {
		writeJSONError(w, 503, "session unavailable")
		return
	}
	h.auditInternalMintSession(ctx, r, userID)
	writeJSON(w, 200, map[string]any{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339)})
}
