package auth

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func decodeSingleJSONObject(r *http.Request, dst any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain a single JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{fieldError: message})
}

func writeRateLimitError(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func randomMobileHandoffCode(length int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	chars := make([]byte, length)
	bound := big.NewInt(int64(len(alphabet)))
	for i := range chars {
		n, err := crand.Int(crand.Reader, bound)
		if err != nil {
			return "", err
		}
		chars[i] = alphabet[n.Int64()]
	}

	return string(chars), nil
}

func setPKCEVerifierCookie(w http.ResponseWriter, r *http.Request, verifier string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set per-request via isHTTPS(r); HttpOnly + SameSite=Lax are always set.
		Name:     pkceVerifierCookieName,
		Value:    verifier,
		Path:     "/",
		Expires:  time.Now().Add(loginFlowCookieTTL),
		MaxAge:   int(loginFlowCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearPKCEVerifierCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set per-request via isHTTPS(r); HttpOnly + SameSite=Lax are always set.
		Name:     pkceVerifierCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func pkceVerifierFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(pkceVerifierCookieName)
	if err != nil || cookie == nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}

func mobileRedirectURL(baseURL, handoffCode, state string) (string, error) {
	if strings.TrimSpace(baseURL) == "" {
		return "", errors.New("mobile redirect url is required")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	query.Set("handoff_code", handoffCode)
	if strings.TrimSpace(state) != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
