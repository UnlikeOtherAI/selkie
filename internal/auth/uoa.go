package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/unlikeotherai/selkie/internal/config"
)

// UOAClaims represents the identity claims returned from the UOA token exchange.
type UOAClaims struct {
	CapabilityFingerprint string `json:"-"`
	Picture               string `json:"picture,omitempty"`
	Active                *struct {
		OrgID  string `json:"orgId"`  //nolint:tagliatelle // Exact UOA contract.
		TeamID string `json:"teamId"` //nolint:tagliatelle // Exact UOA contract.
	} `json:"active,omitempty"`
	SessionID        string `json:"-"`
	RefreshToken     string `json:"-"`
	RefreshExpiresIn int64  `json:"-"`
	ActiveOrgID      string `json:"-"`
	ActiveTeamID     string `json:"-"`
	Email            string `json:"email,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	Name             string `json:"name,omitempty"`
	jwt.RegisteredClaims
}

type tokenExchangeResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

// BuildAuthURL constructs the UOA auth URL (browser flow) from the current
// config, carrying the PKCE S256 challenge UOA requires.
func BuildAuthURL(codeChallenge string) string {
	cfg := config.Load()
	return buildUOAAuthURL(cfg.UOABaseURL, cfg.UOAConfigURL, cfg.UOARedirectURL, codeChallenge)
}

func buildUOAAuthURL(baseURL, configURL, redirectURL, codeChallenge string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	query := url.Values{}
	if configURL = strings.TrimSpace(configURL); configURL != "" {
		query.Set("config_url", configURL)
	}
	if redirectURL = strings.TrimSpace(redirectURL); redirectURL != "" {
		query.Set("redirect_url", redirectURL)
	}
	if codeChallenge = strings.TrimSpace(codeChallenge); codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", "S256")
	}
	if encoded := query.Encode(); encoded != "" {
		return baseURL + "/auth?" + encoded
	}
	return baseURL + "/auth"
}

func uoaConfigDomain(cfg config.Config) (string, error) {
	configURL := strings.TrimSpace(cfg.UOAConfigURL)
	if configURL != "" {
		parsed, err := url.Parse(configURL)
		if err != nil {
			return "", fmt.Errorf("parse UOA_CONFIG_URL: %w", err)
		}
		host := strings.TrimSpace(parsed.Hostname())
		if host == "" {
			return "", errors.New("UOA_CONFIG_URL must include a hostname")
		}
		return host, nil
	}

	domain := strings.TrimSpace(cfg.UOADomain)
	if domain == "" {
		return "", errors.New("UOA_CONFIG_URL or UOA_DOMAIN is required")
	}
	return domain, nil
}

// ExchangeCode exchanges an authorization code for UOA identity claims. Per
// the UOA contract the request must carry the same redirect_url used in the
// authorize step and the PKCE code_verifier, authenticated with the per-domain
// client-hash bearer.
func ExchangeCode(ctx context.Context, code, redirectURL, codeVerifier string) (*UOAClaims, error) {
	cfg := config.Load()
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("code is required")
	}

	tokenResponse, err := exchangeUOATokens(ctx, cfg, map[string]string{
		"code": code, "redirect_url": redirectURL, "code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, err
	}

	claims, err := decodeUOAToken(tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("decode access token: %w", err)
	}
	claims.RefreshToken = tokenResponse.RefreshToken
	claims.RefreshExpiresIn = tokenResponse.RefreshTokenExpiresIn
	if claims.DisplayName == "" {
		claims.DisplayName = claims.Name
	}

	if claims.Active != nil {
		claims.ActiveOrgID = claims.Active.OrgID
		claims.ActiveTeamID = claims.Active.TeamID
	}
	return claims, nil
}

// decodeUOAToken extracts identity claims from the UOA access token WITHOUT
// verifying its signature. Per the UOA contract the access token is HS256
// signed with UOA's deployment-wide secret, which relying parties neither hold
// nor should verify; trust is established by the channel (the authenticated,
// PKCE-validated server-to-server /auth/token call over HTTPS). We still
// reject an expired token defensively.
func decodeUOAToken(tokenString string) (*UOAClaims, error) {
	claims := &UOAClaims{}
	parser := jwt.NewParser()
	if _, _, err := parser.ParseUnverified(tokenString, claims); err != nil {
		return nil, err
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, errors.New("access token has no subject claim")
	}
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || !exp.After(time.Now()) {
		return nil, errors.New("access token is expired")
	}
	if claims.Active != nil {
		claims.ActiveOrgID = claims.Active.OrgID
		claims.ActiveTeamID = claims.Active.TeamID
	}
	return claims, nil
}

func uoaAuthorizationToken(domain string, secret string) string {
	sum := sha256.Sum256([]byte(domain + secret))
	return hex.EncodeToString(sum[:])
}
