package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/unlikeotherai/selkie/internal/config"
)

// UOAClaims represents the identity claims returned from the UOA token exchange.
type UOAClaims struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Name        string `json:"name,omitempty"`
	jwt.RegisteredClaims
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
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

func uoaTokenEndpoint(cfg config.Config) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.UOABaseURL), "/")
	if baseURL == "" {
		return "", errors.New("UOA_BASE_URL is required")
	}
	configURL := strings.TrimSpace(cfg.UOAConfigURL)
	if configURL == "" {
		return "", errors.New("UOA_CONFIG_URL is required")
	}
	query := url.Values{}
	query.Set("config_url", configURL)
	return baseURL + "/auth/token?" + query.Encode(), nil
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

	payload, err := json.Marshal(map[string]string{
		"code":          code,
		"redirect_url":  redirectURL,
		"code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal code exchange payload: %w", err)
	}

	domain, err := uoaConfigDomain(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve UOA domain: %w", err)
	}
	endpoint, err := uoaTokenEndpoint(cfg)
	if err != nil {
		return nil, fmt.Errorf("build UOA token endpoint: %w", err)
	}

	authorization := uoaAuthorizationToken(domain, cfg.UOASharedSecret)
	client := &http.Client{Timeout: 10 * time.Second}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build token exchange request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+authorization)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("exchange code at %s: %w", endpoint, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read token exchange response from %s: %w", endpoint, err)
	}
	if response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return nil, fmt.Errorf("token exchange failed at %s: status %d: %s", endpoint, response.StatusCode, message)
	}

	var tokenResponse tokenExchangeResponse
	if unmarshalErr := json.Unmarshal(body, &tokenResponse); unmarshalErr != nil {
		return nil, fmt.Errorf("decode token exchange response from %s: %w", endpoint, unmarshalErr)
	}
	if tokenResponse.AccessToken == "" {
		return nil, fmt.Errorf("token exchange at %s returned no access token", endpoint)
	}

	claims, err := decodeUOAToken(tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("decode access token from %s: %w", endpoint, err)
	}
	if claims.DisplayName == "" {
		claims.DisplayName = claims.Name
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
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil && exp.Before(time.Now()) {
		return nil, errors.New("access token is expired")
	}
	return claims, nil
}

func uoaAuthorizationToken(domain string, secret string) string {
	sum := sha256.Sum256([]byte(domain + secret))
	return hex.EncodeToString(sum[:])
}
