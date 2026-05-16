package audit_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/unlikeotherai/selkie/internal/audit"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func TestClientIP_TrustedPeerHonorsXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "203.0.113.7" {
		t.Fatalf("trusted peer should honor leftmost XFF; got %q", got)
	}
}

func TestClientIP_UntrustedPeerIgnoresXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "8.8.8.8" {
		t.Fatalf("untrusted peer must return peer IP; got %q", got)
	}
}

func TestClientIP_TrustedPeerMalformedXFFFallsBack(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "not-an-ip")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "127.0.0.1" {
		t.Fatalf("malformed XFF should fall back to peer IP; got %q", got)
	}
}

func TestClientIP_EmptyTrustedListIgnoresXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	got := audit.ClientIP(req, nil)
	if got != "127.0.0.1" {
		t.Fatalf("empty trusted list must ignore XFF even for loopback; got %q", got)
	}
}

func TestClientIP_NoXFFReturnsPeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "127.0.0.1" {
		t.Fatalf("missing XFF must return peer IP; got %q", got)
	}
}

func TestClientIP_TrustedPeerEmptyXFFValueFallsBack(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", ", 198.51.100.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "127.0.0.1" {
		t.Fatalf("empty leftmost XFF should fall back to peer IP; got %q", got)
	}
}

func TestClientIP_UnparseableRemoteAddrReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "garbage"

	if got := audit.ClientIP(req, nil); got != "" {
		t.Fatalf("unparseable RemoteAddr should return empty; got %q", got)
	}
}

func TestClientIP_TrustedIPv6Peer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	got := audit.ClientIP(req, mustPrefixes(t, "::1/128"))
	if got != "203.0.113.7" {
		t.Fatalf("IPv6 trusted peer should honor XFF; got %q", got)
	}
}
