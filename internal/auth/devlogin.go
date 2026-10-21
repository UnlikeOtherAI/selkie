package auth

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/unlikeotherai/selkie/internal/audit"
)

// Dev user constants — deterministic so tests and dev sessions always get the same user.
const (
	DevUserExternalID  = "dev-agent-smith"
	DevUserEmail       = "agent.smith@dev.local"
	DevUserDisplayName = "Agent Smith"
	DevUserPicture     = "https://api.dicebear.com/9.x/bottts/svg?seed=AgentSmith"
)

// ServeDevStatus returns whether dev-mode login is enabled.
func (h *CallbackHandler) ServeDevStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{fieldEnabled: h.cfg.DevMode && h.cfg.UOAConfigURL == ""}) //nolint:errcheck // best-effort write to HTTP response
}

// ServeDevLogin upserts a hardcoded dev user and issues a session JWT.
// Returns 404 when DevMode is false.
func (h *CallbackHandler) ServeDevLogin(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.DevMode || h.cfg.UOAConfigURL != "" {
		http.NotFound(w, r)
		return
	}

	claims := &UOAClaims{}
	claims.Subject = DevUserExternalID
	claims.Email = DevUserEmail
	claims.DisplayName = DevUserDisplayName

	userID, isSuper, err := h.upsertUser(r.Context(), claims)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("dev-login upsert", zap.Error(err))
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if h.audit != nil {
		if auditErr := h.audit.Log(r.Context(), audit.Event{
			ActorUserID: &userID,
			Action:      "user.login",
			Outcome:     auditOutcomeSuccess,
			TargetTable: auditTargetUsers,
			TargetID:    &userID,
			RemoteIP:    audit.ClientIP(r, h.cfg.TrustedProxyCIDRs),
			UserAgent:   audit.TruncateUserAgent(r.UserAgent()),
		}); auditErr != nil {
			h.logger.Error("audit dev-login", zap.Error(auditErr))
		}
	}

	// Dev-login intentionally mints both audiences so e2e tests can hit admin and mobile routes with one token; production paths mint a single audience.
	sessionID, err := h.sessions.createDevelopment(r.Context(), userID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	token, err := h.mintSessionToken(userID, isSuper, sessionID, []string{AudienceAdmin, AudienceMobile})
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin#token="+token, http.StatusFound)
}
