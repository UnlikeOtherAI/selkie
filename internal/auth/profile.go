package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const profileTTL = 30 * time.Second

type userProfile struct {
	Email       string `json:"email,omitempty"`
	Picture     string `json:"picture,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type cachedProfile struct {
	value   userProfile
	expires time.Time
}

type profileCache struct {
	mu     sync.Mutex
	values map[string]cachedProfile
}

// ServeReferenceSession replaces legacy browser tokens without extending their
// authorization deadline. Persisted session material contains no copied profile.
func (h *CallbackHandler) ServeReferenceSession(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	now := time.Now()
	reference := sessionClaims{IsSuper: claims.IsSuper, RegisteredClaims: jwt.RegisteredClaims{Issuer: Issuer, Subject: claims.Sub, Audience: jwt.ClaimStrings(claims.Audience), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt)}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, reference).SignedString([]byte(h.cfg.InternalSessionSecret))
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{responseTokenField: token})
}

// ServeProfile reads only the authenticated subject's current UOA profile.
// Display data is cached briefly in bounded memory, never in sessions or SQL.
func (h *CallbackHandler) ServeProfile(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var reference string
	if err := h.db.Pool.QueryRow(ctx, `SELECT external_id FROM users WHERE id=$1 AND status='active'`, claims.Sub).Scan(&reference); err != nil {
		writeJSONError(w, http.StatusNotFound, "UOA reference unavailable")
		return
	}
	value, err := h.profile(ctx, reference)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "UOA profile unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, value)
}

func (h *CallbackHandler) profile(ctx context.Context, reference string) (userProfile, error) {
	h.profiles.mu.Lock()
	cached, exists := h.profiles.values[reference]
	if exists && !cached.expires.After(time.Now()) {
		delete(h.profiles.values, reference)
	}
	h.profiles.mu.Unlock()
	if exists && cached.expires.After(time.Now()) {
		return cached.value, nil
	}
	value, err := h.fetchProfile(ctx, reference)
	if err != nil {
		return userProfile{}, err
	}
	h.profiles.mu.Lock()
	defer h.profiles.mu.Unlock()
	if h.profiles.values == nil {
		h.profiles.values = make(map[string]cachedProfile)
	}
	now := time.Now()
	for key, item := range h.profiles.values {
		if !item.expires.After(now) {
			delete(h.profiles.values, key)
		}
	}
	if len(h.profiles.values) >= 256 {
		clear(h.profiles.values)
	}
	h.profiles.values[reference] = cachedProfile{value: value, expires: now.Add(profileTTL)}
	return value, nil
}

func (h *CallbackHandler) fetchProfile(ctx context.Context, reference string) (userProfile, error) {
	domain, err := uoaConfigDomain(h.cfg)
	endpoint, parseErr := url.Parse(strings.TrimRight(h.cfg.UOABaseURL, "/") + "/domain/users")
	if err != nil || parseErr != nil || endpoint.Host == "" || endpoint.User != nil || (endpoint.Scheme != "https" && !h.cfg.DevMode) || h.cfg.UOASharedSecret == "" {
		return userProfile{}, errors.New("UOA profile configuration unavailable")
	}
	query := url.Values{"domain": {domain}, "user_id": {reference}}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return userProfile{}, err
	}
	request.Header.Set("Authorization", "Bearer "+uoaAuthorizationToken(domain, h.cfg.UOASharedSecret))
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return userProfile{}, errors.New("UOA profile request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return userProfile{}, errors.New("UOA profile request refused")
	}
	var data struct {
		Users []struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		} `json:"users"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&data); err != nil {
		return userProfile{}, errors.New("UOA profile response invalid")
	}
	if len(data.Users) != 1 || data.Users[0].ID != reference {
		return userProfile{}, errors.New("UOA profile subject mismatch")
	}
	return userProfile{Email: data.Users[0].Email, DisplayName: data.Users[0].Name, Picture: data.Users[0].AvatarURL}, nil
}
