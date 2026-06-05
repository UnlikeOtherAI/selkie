package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// UOA requires the client config JWT to be signed with RS256 and verified
// against a JWKS the client publishes at GET /.well-known/jwks.json (whose
// host must equal the config `domain`). This file owns the RSA key handling,
// the JWKS document, and the PKCE helpers the auth flow needs. See
// https://authentication.unlikeotherai.com/llm.

var (
	configKeyOnce sync.Once
	configKey     *rsa.PrivateKey
	errConfigKey  error
	configKeyPEM  string
)

// parseConfigSigningKey parses (and caches) the RSA private key used to sign
// the UOA config JWT. Accepts PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE
// KEY") PEM. The cache is keyed on the PEM string so a changed env value is
// re-parsed rather than serving a stale key.
func parseConfigSigningKey(pemStr string) (*rsa.PrivateKey, error) {
	pemStr = strings.TrimSpace(pemStr)
	if pemStr == "" {
		return nil, errors.New("UOA_CONFIG_SIGNING_KEY is not set")
	}
	configKeyOnce.Do(func() {
		configKeyPEM = pemStr
		configKey, errConfigKey = decodeRSAPrivateKey(pemStr)
	})
	if configKeyPEM != pemStr {
		// Env changed since first parse (tests / hot reload): bypass the cache.
		return decodeRSAPrivateKey(pemStr)
	}
	return configKey, errConfigKey
}

func decodeRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	// Accept either a raw PEM (multi-line) or a base64-encoded PEM on a single
	// line, since docker-compose env_file values cannot span multiple lines.
	if !strings.Contains(pemStr, "BEGIN") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pemStr)); err == nil {
			pemStr = string(decoded)
		}
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("UOA_CONFIG_SIGNING_KEY is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("UOA_CONFIG_SIGNING_KEY is not an RSA key")
	}
	return rsaKey, nil
}

// signConfigJWT signs the config claims with RS256 and the given kid in the
// protected header, as UOA's auto-discovery and signature checks require.
func signConfigJWT(claims jwt.MapClaims, keyPEM, kid string) (string, error) {
	key, err := parseConfigSigningKey(keyPEM)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

// base64url encodes a big-endian byte slice without padding (JWK encoding).
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// publicJWK builds the public RSA JWK for the configured signing key.
func publicJWK(keyPEM, kid string) (map[string]any, error) {
	key, err := parseConfigSigningKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("config signing key is not RSA")
	}
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   b64url(pub.N.Bytes()),
		"e":   b64url(eBytes),
	}, nil
}

// ServeJWKS publishes the RSA public key so UOA can verify the config JWT.
// The hostname of this endpoint must equal the `domain` claim in the config
// JWT (UOA enforces INTEGRATION_JWKS_HOST_MISMATCH otherwise).
func (h *CallbackHandler) ServeJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk, err := publicJWK(h.cfg.UOAConfigSigningKeyPEM, h.configSigningKID())
	if err != nil {
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{jwk}})
}

func (h *CallbackHandler) configSigningKID() string {
	if kid := strings.TrimSpace(h.cfg.UOAConfigSigningKID); kid != "" {
		return kid
	}
	return "selkie-config"
}

// newPKCE returns a fresh PKCE (verifier, S256 challenge) pair. The verifier is
// a 43-char base64url string (32 random bytes); the challenge is
// base64url(SHA256(verifier)).
func newPKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
