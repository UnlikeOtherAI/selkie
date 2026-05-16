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

func TestClientIP_TrustedPeerReturnsRightmostNonTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	// Only the loopback hop is trusted, so both XFF entries are non-trusted;
	// the rightmost non-trusted (198.51.100.1) wins.
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "198.51.100.1" {
		t.Fatalf("trusted peer should return rightmost non-trusted XFF; got %q", got)
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

func TestClientIP_TrustedPeerEmptyLeftmostHopReturnsRightmostNonTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", ", 198.51.100.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "198.51.100.1" {
		t.Fatalf("rightmost non-trusted XFF should be returned even when leftmost hop is empty; got %q", got)
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

// TestClientIP_CaddyAppendedXFF guards against the BLOCKER addressed in this
// patch: Caddy's default reverse_proxy *appends* the immediate peer to any
// client-supplied X-Forwarded-For. An attacker sending
// `X-Forwarded-For: 1.2.3.4` from the public edge therefore causes the Go
// server to observe `X-Forwarded-For: 1.2.3.4, <real-client-ip>` with the
// peer being trusted Caddy on loopback. The rightmost-non-trusted walk
// must surface the real client IP, never the attacker-controlled value.
func TestClientIP_CaddyAppendedXFFRejectsSpoofedLeftmost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	// 1.2.3.4 is the attacker-supplied value; 198.51.100.42 is what Caddy
	// appended (the true edge client).
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.42")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got == "1.2.3.4" {
		t.Fatalf("rightmost-non-trusted must NOT return attacker-controlled leftmost XFF; got %q", got)
	}
	if got != "198.51.100.42" {
		t.Fatalf("expected real client IP 198.51.100.42; got %q", got)
	}
}

// TestClientIP_ChainedTrustedProxies covers two trusted hops (e.g. an
// internal LB at 10.0.0.5 forwarding to Caddy on 127.0.0.1). The real
// client (203.0.113.9) sits leftmost; both hops to its right are trusted
// and must be skipped.
func TestClientIP_ChainedTrustedProxies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.5, 127.0.0.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got != "203.0.113.9" {
		t.Fatalf("chained trusted proxies should resolve to real client; got %q", got)
	}
}

// TestClientIP_ChainedTrustedProxiesWithSpoofedLeftmost combines an
// attacker-supplied leftmost value with chained trusted hops to its right.
// The leftmost non-trusted entry is the spoofed value, but it sits to the
// left of a trusted hop, so the walk must return the rightmost-non-trusted
// real hop instead.
func TestClientIP_ChainedTrustedProxiesWithSpoofedLeftmost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	// attacker, real-client, internal-LB, caddy
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9, 10.0.0.5, 127.0.0.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got != "203.0.113.9" {
		t.Fatalf("rightmost-non-trusted should be the real client, not the spoofed leftmost; got %q", got)
	}
}

// TestClientIP_FullyTrustedChainReturnsPeer asserts the documented
// fallback when every XFF entry sits inside a trusted prefix.
func TestClientIP_FullyTrustedChainReturnsPeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 127.0.0.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got != "127.0.0.1" {
		t.Fatalf("fully trusted chain must fall back to peer; got %q", got)
	}
}

// TestClientIP_MultipleXFFHeadersJoined verifies the Header.Values policy:
// Header.Add produces multiple X-Forwarded-For lines and Go's Header.Get
// returns only the first. ClientIP must aggregate all instances and apply
// the right-to-left walk across the concatenated list.
func TestClientIP_MultipleXFFHeadersJoined(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	// First Add: attacker-controlled leftmost. Second Add: real client +
	// trusted LB. With Header.Get this would return the first header only
	// ("1.2.3.4"); with Header.Values we see the full chain and the
	// rightmost-non-trusted (203.0.113.50) wins.
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	req.Header.Add("X-Forwarded-For", "203.0.113.50, 10.0.0.7")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got != "203.0.113.50" {
		t.Fatalf("multiple XFF headers must be joined and right-walked; got %q", got)
	}
}
