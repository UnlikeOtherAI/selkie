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
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": h.cfg.DevMode})
}

// ServeDevLogin upserts a hardcoded dev user and issues a session JWT.
// Returns 404 when DevMode is false.
func (h *CallbackHandler) ServeDevLogin(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.DevMode {
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
			Outcome:     "success",
			TargetTable: "users",
			TargetID:    &userID,
			RemoteIP:    audit.RemoteAddr(r),
			UserAgent:   r.UserAgent(),
		}); auditErr != nil {
			h.logger.Error("audit dev-login", zap.Error(auditErr))
		}
	}

	token, err := h.mintToken(userID, isSuper, DevUserEmail, DevUserDisplayName, DevUserPicture)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin#token="+token, http.StatusFound)
}
