package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fieldEnabled is the shared "enabled" JSON key used across the UOA config
// payload and the dev-status response.
const fieldEnabled = "enabled"

func uoaConfigRedirectURLs(cfg CallbackHandler) []string {
	seen := make(map[string]struct{}, 2)
	redirectURLs := make([]string, 0, 2)
	for _, candidate := range []string{
		strings.TrimSpace(cfg.cfg.UOARedirectURL),
		strings.TrimSpace(cfg.cfg.UOAMobileRedirectURL),
	} {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		redirectURLs = append(redirectURLs, candidate)
	}
	return redirectURLs
}

func uoaDefaultTheme() map[string]any {
	return map[string]any{
		"colors": map[string]string{
			"bg":           "#0f172a",
			"surface":      "#111827",
			"text":         "#e2e8f0",
			"muted":        "#94a3b8",
			"primary":      "#0f766e",
			"primary_text": "#f0fdfa",
			"border":       "#334155",
			"danger":       "#dc2626",
			"danger_text":  "#fef2f2",
		},
		"radii": map[string]string{
			"card":   "20px",
			"button": "12px",
			"input":  "12px",
		},
		"density": "comfortable",
		"button": map[string]string{
			"style": "solid",
		},
		"card": map[string]string{
			"style": "bordered",
		},
		"typography": map[string]any{
			"font_family":    "sans",
			"base_text_size": "md",
		},
		"logo": map[string]any{
			"url":  "",
			"alt":  "Selkie logo",
			"text": "Selkie",
		},
	}
}

func uoaAllowedSocialProviders(methods []string) []string {
	providers := make([]string, 0, 2)
	for _, method := range methods {
		switch method {
		case "google", "apple", "facebook", "github", "linkedin":
			providers = append(providers, method)
		}
	}
	return providers
}

// uoaJWKSURL derives the JWKS URL UOA fetches to verify the config JWT. Its
// host must equal the `domain` claim, so it is built from the config URL host.
func uoaJWKSURL(configURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(configURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("UOA_CONFIG_URL must be absolute")
	}
	return parsed.Scheme + "://" + parsed.Host + "/.well-known/jwks.json", nil
}

// ServeUOAConfig returns the RS256-signed client configuration JWT consumed by
// UOA. It is signed with the RSA key published at /.well-known/jwks.json and
// carries the onboarding fields (jwks_url, contact_email) UOA needs to
// auto-discover and approve this integration.
func (h *CallbackHandler) ServeUOAConfig(w http.ResponseWriter, _ *http.Request) {
	domain, err := uoaConfigDomain(h.cfg)
	redirectURLs := uoaConfigRedirectURLs(*h)
	jwksURL, jwksErr := uoaJWKSURL(h.cfg.UOAConfigURL)
	contactEmail := strings.TrimSpace(h.cfg.UOAContactEmail)
	if err != nil || jwksErr != nil || strings.TrimSpace(h.cfg.UOAConfigURL) == "" ||
		len(redirectURLs) == 0 || strings.TrimSpace(h.cfg.UOAConfigSigningKeyPEM) == "" ||
		contactEmail == "" {
		http.Error(w, "uoa config is incomplete", http.StatusInternalServerError)
		return
	}

	authMethods := []string{"email_password", "google"}
	now := time.Now()
	claims := jwt.MapClaims{
		"domain":                   domain,
		"jwks_url":                 jwksURL,
		"contact_email":            contactEmail,
		"redirect_urls":            redirectURLs,
		"enabled_auth_methods":     authMethods,
		"allowed_social_providers": uoaAllowedSocialProviders(authMethods),
		"user_scope":               "global",
		"ui_theme":                 uoaDefaultTheme(),
		"language_config":          "en",
		"2fa_enabled":              false,
		"debug_enabled":            false,
		"allow_registration":       true,
		"registration_mode":        "password_required",
		"access_requests": map[string]any{
			fieldEnabled:       false,
			"notify_org_roles": []string{"owner", "admin"},
		},
		"session": map[string]any{
			"remember_me_enabled":           true,
			"remember_me_default":           true,
			"short_refresh_token_ttl_hours": 1,
			"long_refresh_token_ttl_days":   30,
		},
		// Selkie is a single-user / single-tenant control plane; it does not
		// consume UOA org or team membership (upsertUser only reads sub/email).
		// Disable org features so first-login skips org/team bootstrapping,
		// which 500s on UOA when no org auto-create path is configured.
		"org_features": map[string]any{
			fieldEnabled: false,
		},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	token, err := signConfigJWT(claims, h.cfg.UOAConfigSigningKeyPEM, h.configSigningKID())
	if err != nil {
		http.Error(w, "failed to sign config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(token))
}
