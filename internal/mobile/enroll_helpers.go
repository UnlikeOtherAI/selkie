package mobile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxHostnameLen    = 253
	maxDNSLabelLen    = 63
	maxOSArchLen      = 64
	maxAppVersionLen  = 64
	wgPublicKeyRawLen = 32
)

// wgPublicKeyPattern enforces the OpenAPI contract for WireGuard public keys:
// exactly 43 base64 chars (no `-`/`_` URL-safe variants, no whitespace) plus
// the single trailing `=` pad. Standard library base64 decoding is too lenient
// (e.g. accepts unpadded variants) for storage as a stable join key.
var wgPublicKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// lowOrderWGKeys is the canonical set of Curve25519 small-subgroup / low-order
// public-key representatives. Any peer presenting one of these has order 1, 2,
// 4, or 8 and breaks the hub's WireGuard semantics: an attacker can also
// pre-register a low-order key to globally block other users from claiming it
// (devices.wg_public_key is globally UNIQUE today).
//
// The 13 entries cover the order-1/2/4/8 points plus the high-bit-set variants
// — RFC 7748 §5 says X25519 decoders SHOULD ignore the high bit, so we reject
// both bit patterns rather than masking first. Sourced from the libsodium
// crypto_scalarmult has_small_order() table (ref10/x25519_ref10.c) and the
// canonical cr.yp.to enumeration.
var lowOrderWGKeys = map[[wgPublicKeyRawLen]byte]struct{}{
	// 0 (identity, order 1)
	{}: {},
	// 1 (order 2)
	{0x01}: {},
	// 1 with the (RFC 7748-ignored) high bit set
	{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}: {},
	// order-8 point #1
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00}: {},
	// order-8 point #1 with high bit
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80}: {},
	// order-8 point #2
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57}: {},
	// order-8 point #2 with high bit
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7}: {},
	// p-1 (order 2)
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}: {},
	// p-1 with high bit
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}: {},
	// p   (=0, order 1)
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}: {},
	// p   with high bit
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}: {},
	// p+1 (=1, order 2)
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}: {},
	// p+1 with high bit
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}: {},
}

// enrollValidationError indicates a specific field of the enrollment request
// failed validation. The bad value is intentionally not exposed.
type enrollValidationError struct {
	Field  string
	Reason string
}

func (e *enrollValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason)
}

func parseEnrollRequest(w http.ResponseWriter, r *http.Request) (enrollRequest, bool) {
	var req enrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return enrollRequest{}, false
	}
	if err := validateEnrollRequest(req); err != nil {
		writeEnrollValidationError(w, err)
		return enrollRequest{}, false
	}
	// Canonicalize fields after validation so downstream callers (DB upsert,
	// hub join keys) always see the trimmed, lowercased values.
	req.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	req.OSPlatform = strings.TrimSpace(req.OSPlatform)
	req.OSArch = strings.TrimSpace(req.OSArch)
	req.AppVersion = strings.TrimSpace(req.AppVersion)
	req.WGPublicKey = strings.TrimSpace(req.WGPublicKey)
	return req, true
}

func writeEnrollValidationError(w http.ResponseWriter, err error) {
	var verr *enrollValidationError
	if errors.As(err, &verr) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid request",
			"field":  verr.Field,
			"reason": verr.Reason,
		})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func validateEnrollRequest(req enrollRequest) error {
	if err := validateHostname(req.Hostname); err != nil {
		return err
	}
	platform := strings.TrimSpace(req.OSPlatform)
	if platform != "ios" && platform != "android" {
		return &enrollValidationError{Field: "os_platform", Reason: "must be 'ios' or 'android'"}
	}
	if err := validateBoundedField("os_arch", req.OSArch, maxOSArchLen); err != nil {
		return err
	}
	if err := validateBoundedField("app_version", req.AppVersion, maxAppVersionLen); err != nil {
		return err
	}
	return validateWGPublicKey(req.WGPublicKey)
}

func validateHostname(raw string) error {
	trimmed := strings.TrimSpace(raw)
	// Reject non-ASCII before lowercasing: `strings.ToLower` performs Unicode
	// case-folding that collapses chars like Turkish dotted-I (U+0130), Kelvin
	// (U+212A), and Angstrom (U+212B) to ASCII letters, which would homograph-
	// collide with real ASCII hostnames downstream.
	for _, r := range trimmed {
		if r > unicode.MaxASCII {
			return &enrollValidationError{Field: "hostname", Reason: "must be ASCII"}
		}
	}
	hostname := strings.ToLower(trimmed)
	switch {
	case hostname == "":
		return &enrollValidationError{Field: "hostname", Reason: "required"}
	case len(hostname) > maxHostnameLen:
		return &enrollValidationError{Field: "hostname", Reason: "too long"}
	case !isValidDNSName(hostname):
		return &enrollValidationError{Field: "hostname", Reason: "must be a valid DNS name"}
	}
	return nil
}

func validateBoundedField(field, raw string, maxLen int) error {
	v := strings.TrimSpace(raw)
	switch {
	case v == "":
		return &enrollValidationError{Field: field, Reason: "required"}
	case len(v) > maxLen:
		return &enrollValidationError{Field: field, Reason: "too long"}
	case containsControlChar(v):
		return &enrollValidationError{Field: field, Reason: "must not contain control characters"}
	}
	return nil
}

func validateWGPublicKey(raw string) error {
	wgKey := strings.TrimSpace(raw)
	if wgKey == "" {
		return &enrollValidationError{Field: "wg_public_key", Reason: "required"}
	}
	if !wgPublicKeyPattern.MatchString(wgKey) {
		return &enrollValidationError{Field: "wg_public_key", Reason: "must be base64-encoded 32 bytes"}
	}
	decoded, err := base64.StdEncoding.DecodeString(wgKey)
	if err != nil || len(decoded) != wgPublicKeyRawLen {
		return &enrollValidationError{Field: "wg_public_key", Reason: "must be base64-encoded 32 bytes"}
	}
	var fixed [wgPublicKeyRawLen]byte
	copy(fixed[:], decoded)
	if _, isLowOrder := lowOrderWGKeys[fixed]; isLowOrder {
		return &enrollValidationError{Field: "wg_public_key", Reason: "is a low-order curve25519 point"}
	}
	return nil
}

// isValidDNSName checks that s is a valid RFC 1035 / 1123 DNS name: one or
// more `.`-separated labels, each 1-63 chars of `[a-z0-9-]`, with no leading
// or trailing hyphen. The caller is responsible for lowercasing s first.
func isValidDNSName(s string) bool {
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !isValidDNSLabel(label) {
			return false
		}
	}
	return true
}

func isValidDNSLabel(label string) bool {
	n := len(label)
	if n == 0 || n > maxDNSLabelLen {
		return false
	}
	if label[0] == '-' || label[n-1] == '-' {
		return false
	}
	for i := 0; i < n; i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

func containsControlChar(s string) bool {
	// IsControl only matches Cc (C0/C1); IsPrint additionally rejects Cf
	// format chars like ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), BOM
	// (U+FEFF), and other non-printable runes that would otherwise sneak
	// into audit logs and DB rows.
	for _, r := range s {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

func (h *Handler) ensureEnrollReady(ctx context.Context, w http.ResponseWriter, userID string) bool {
	if !h.allowRateLimit(ctx, w, ratelimit.Key("mobile", "enroll", "user", userID), mobileEnrollLimit, mobileEnrollWindow) {
		return false
	}
	if h.db == nil || h.db.Pool == nil {
		writeError(w, http.StatusInternalServerError, "database unavailable")
		return false
	}
	if h.cfg.WGServerPublicKey == "" || h.cfg.WGServerEndpoint == "" || h.cfg.WGOverlayCIDR == "" {
		writeError(w, http.StatusServiceUnavailable, "wireguard server not configured")
		return false
	}
	return true
}

func (h *Handler) enrollMobileDevice(ctx context.Context, userID string, req enrollRequest) (string, *string, error) {
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	deviceID, overlayIP, err := upsertMobileDevice(ctx, tx, userID, req)
	if err != nil {
		return "", nil, err
	}
	if keyErr := upsertMobileDeviceKey(ctx, tx, deviceID, req.WGPublicKey); keyErr != nil {
		return "", nil, keyErr
	}
	if overlayIP == nil && h.overlay != nil {
		ip, allocErr := h.overlay.AllocateTx(ctx, tx, deviceID)
		if allocErr != nil {
			return "", nil, allocErr
		}
		value := ip.String()
		overlayIP = &value
	}
	if commitErr := tx.Commit(ctx); commitErr != nil {
		return "", nil, commitErr
	}
	if h.hub != nil {
		if syncErr := h.hub.SyncDevice(ctx, deviceID); syncErr != nil {
			h.logger.Error("sync mobile wireguard peer", zap.Error(syncErr), zap.String("device_id", deviceID))
		}
	}
	return deviceID, overlayIP, nil
}

func (h *Handler) auditMobileEnroll(ctx context.Context, r *http.Request, userID, deviceID string) {
	if h.audit == nil {
		return
	}
	if auditErr := h.audit.Log(ctx, audit.Event{
		ActorUserID: &userID,
		Action:      "device.mobile_enroll",
		Outcome:     "success",
		TargetTable: "devices",
		TargetID:    &deviceID,
		RemoteIP:    audit.RemoteAddr(r),
		UserAgent:   r.UserAgent(),
	}); auditErr != nil {
		h.logger.Error("audit mobile enroll", zap.Error(auditErr))
	}
}

func upsertMobileDevice(ctx context.Context, tx pgx.Tx, userID string, req enrollRequest) (string, *string, error) {
	var deviceID string
	var overlayIP *string
	err := tx.QueryRow(ctx, `
SELECT id, host(overlay_ip)
FROM devices
WHERE owner_user_id = $1 AND hostname = $2
LIMIT 1
`, userID, req.Hostname).Scan(&deviceID, &overlayIP)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		credential, credErr := randomCredential()
		if credErr != nil {
			return "", nil, credErr
		}
		credentialHash, hashErr := bcrypt.GenerateFromPassword([]byte(credential), bcrypt.DefaultCost)
		if hashErr != nil {
			return "", nil, hashErr
		}

		err = tx.QueryRow(ctx, `
INSERT INTO devices (
    owner_user_id,
    hostname,
    status,
    credential_hash,
    agent_version,
    os_platform,
    os_arch,
    os_version,
    kernel_version,
    cpu_model,
    cpu_cores,
    total_memory_bytes,
    disk_total_bytes,
    disk_free_bytes,
    last_seen_at,
    updated_at
) VALUES ($1, $2, 'active', $3, $4, $5, $6, '', '', '', 1, 0, 0, 0, now(), now())
RETURNING id, host(overlay_ip)
`, userID, req.Hostname, string(credentialHash), req.AppVersion, req.OSPlatform, req.OSArch).Scan(&deviceID, &overlayIP)
		return deviceID, overlayIP, err
	}

	err = tx.QueryRow(ctx, `
UPDATE devices
SET status = 'active',
    hostname = $2,
    agent_version = $3,
    os_platform = $4,
    os_arch = $5,
    last_seen_at = now(),
    updated_at = now(),
    revoked_at = NULL,
    overlay_ip_reclaim_after = NULL
WHERE id = $1
RETURNING host(overlay_ip)
`, deviceID, req.Hostname, req.AppVersion, req.OSPlatform, req.OSArch).Scan(&overlayIP)
	return deviceID, overlayIP, err
}

func upsertMobileDeviceKey(ctx context.Context, tx pgx.Tx, deviceID, publicKey string) error {
	var keyID string
	var currentKey string
	var version int
	err := tx.QueryRow(ctx, `
SELECT id, wg_public_key, key_version
FROM device_keys
WHERE device_id = $1 AND state = 'active'
LIMIT 1
`, deviceID).Scan(&keyID, &currentKey, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_, insertErr := tx.Exec(ctx, `
INSERT INTO device_keys (device_id, key_version, wg_public_key, state)
VALUES ($1, 1, $2, 'active')
`, deviceID, publicKey)
			return insertErr
		}
		return err
	}
	if currentKey == publicKey {
		return nil
	}
	if _, execErr := tx.Exec(ctx, `
UPDATE device_keys
SET state = 'retired', retired_at = now()
WHERE id = $1
`, keyID); execErr != nil {
		return execErr
	}
	_, insertErr := tx.Exec(ctx, `
INSERT INTO device_keys (device_id, key_version, wg_public_key, state, rotated_from_key_id)
VALUES ($1, $2, $3, 'active', $4)
`, deviceID, version+1, publicKey, keyID)
	return insertErr
}
