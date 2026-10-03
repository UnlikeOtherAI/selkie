package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/unlikeotherai/selkie/internal/config"
)

var errUOARefused = errors.New("UOA refused capability")

const (
	fieldScope          = "scope"
	fieldError          = "error"
	capabilityRefresh   = "refresh"
	maxUOAResponseBytes = 65536
	fieldToken          = "token"
	fieldExpiresIn      = "expires_in"
	fieldRefreshToken   = "refresh_token"
	revokeScopeFamily   = "family"
	fieldEmail          = "email"
	fieldExpiresAt      = "expires_at"
	fieldSubject        = "sub"
)

// uoaRequest authenticates confidential requests and never follows redirects.
func uoaRequest(ctx context.Context, cfg config.Config, method, path string, payload any, target any) error {
	domain, err := uoaConfigDomain(cfg)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(cfg.UOABaseURL, "/") + path
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return errors.New("invalid UOA endpoint")
	}
	query := parsed.Query()
	if method == http.MethodPost {
		query.Set("config_url", cfg.UOAConfigURL)
	}
	parsed.RawQuery = query.Encode()
	var body io.Reader
	if payload != nil {
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return errors.New("invalid UOA request")
	}
	request.Header.Set("Authorization", "Bearer "+uoaAuthorizationToken(domain, cfg.UOASharedSecret))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("UOA temporarily unavailable")
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxUOAResponseBytes+1))
	if err != nil || len(encoded) > maxUOAResponseBytes {
		return errors.New("invalid UOA response")
	}
	if err := checkUOAStatus(response.StatusCode); err != nil {
		return err
	}
	if target == nil {
		return nil
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return errors.New("invalid UOA response")
	}
	return nil
}

func exchangeUOATokens(ctx context.Context, cfg config.Config, body any) (tokenExchangeResponse, error) {
	var tokens tokenExchangeResponse
	if err := uoaRequest(ctx, cfg, http.MethodPost, "/auth/token", body, &tokens); err != nil {
		return tokens, err
	}
	if tokens.AccessToken == "" {
		return tokens, errors.New("UOA returned no access token")
	}
	return tokens, nil
}

// currentUOAProfile resolves one exact subject; identity profiles are memory-only.
func currentUOAProfile(ctx context.Context, cfg config.Config, subject string) (*UOAClaims, error) {
	domain, err := uoaConfigDomain(cfg)
	if err != nil {
		return nil, err
	}
	query := url.Values{"domain": {domain}, "user_id": {subject}}
	var result struct {
		Users []struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		} `json:"users"`
	}
	if err := uoaRequest(ctx, cfg, http.MethodGet, "/domain/users?"+query.Encode(), nil, &result); err != nil {
		return nil, err
	}
	if len(result.Users) != 1 || result.Users[0].ID != subject {
		return nil, errors.New("UOA subject unavailable")
	}
	claims := &UOAClaims{Email: result.Users[0].Email, DisplayName: result.Users[0].Name, Picture: result.Users[0].AvatarURL}
	claims.Subject = subject
	return claims, nil
}

func checkUOAStatus(status int) error {
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return nil
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusGone:
		return fmt.Errorf("%w: status %d", errUOARefused, status)
	default:
		return fmt.Errorf("UOA unavailable: status %d", status)
	}
}
