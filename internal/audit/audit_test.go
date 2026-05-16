package audit_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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

// TestClientIP_IPv4MappedBypassRejected guards against an attacker who
// terminates an IPv4-mapped IPv6 form (::ffff:10.0.0.5) at the leftmost
// non-trusted slot. netip.Prefix.Contains is family-strict, so without
// Unmap the trust check returns false and the attacker-controlled value
// would be returned. The walk must Unmap the parsed entry before testing
// containment so the 4in6 form is recognized as trusted and skipped, and
// the chain falls back to the trusted peer.
func TestClientIP_IPv4MappedBypassRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "::ffff:10.0.0.5, 10.0.0.5, 127.0.0.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got == "::ffff:10.0.0.5" {
		t.Fatalf("IPv4-mapped IPv6 form must not bypass IPv4 trusted prefix; got %q", got)
	}
	// With Unmap applied, the entire chain is trusted (::ffff:10.0.0.5 →
	// 10.0.0.5 ∈ 10.0.0.0/8). Fully-trusted-chain semantics fall back to
	// the peer.
	if got != "127.0.0.1" {
		t.Fatalf("expected fully-trusted-chain fallback to peer 127.0.0.1; got %q", got)
	}
}

// TestClientIP_IPv4MappedAttackerLeftmost is the tighter variant: the
// attacker-controlled value is a 4in6 form of an address NOT in any
// trusted prefix, with a real trusted hop to its right. After Unmap the
// rightmost-non-trusted walk must surface the unmapped attacker value at
// the leftmost slot (it's the only non-trusted entry) — but critically
// never as the raw `::ffff:` form, so downstream rate-limit keys cannot
// be split via the 4in6 representation.
func TestClientIP_IPv4MappedAttackerLeftmostUnmapped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "::ffff:1.2.3.4, 127.0.0.1")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if strings.HasPrefix(got, "::ffff:") {
		t.Fatalf("returned IP must be normalized to v4 form, never 4in6; got %q", got)
	}
	if got != "1.2.3.4" {
		t.Fatalf("expected unmapped 1.2.3.4; got %q", got)
	}
}

// TestClientIP_ZonedIPv6Stripped covers two invariants simultaneously:
//  1. Zone stripping: "%eth0" is removed before any downstream processing.
//  2. Address-class rejection: after stripping, fe80::1 is link-local unicast
//     and cannot be a real client address. It must be rejected and fall back to
//     the peer rather than being returned — even though it is "parseable" — to
//     prevent link-local injection into rate-limit buckets or audit rows.
//
// The returned value must therefore be the peer IP, not fe80::1.
func TestClientIP_ZonedIPv6Stripped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "fe80::1%eth0")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if strings.Contains(got, "%") {
		t.Fatalf("returned address must not retain zone suffix; got %q", got)
	}
	// fe80::1 is link-local and must be rejected; fallback is the peer.
	if got != "127.0.0.1" {
		t.Fatalf("link-local zoned XFF must fall back to peer 127.0.0.1; got %q", got)
	}
}

// TestClientIP_4in6PeerNormalized covers the peer-fallback path: an IPv4-
// mapped peer (e.g. [::ffff:127.0.0.1]:1234) must be recognized as trusted
// against a v4 prefix, and the returned address must be the unmapped form
// so the persisted remote_ip never carries a 4in6 representation.
func TestClientIP_4in6PeerNormalized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::ffff:127.0.0.1]:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got != "203.0.113.7" {
		t.Fatalf("4in6 peer should be trusted and XFF honored; got %q", got)
	}
}

// TestClientIP_4in6TrustedPrefixHonored verifies that a trusted-proxy list
// containing a 4in6 prefix that has been parser-normalized to its canonical
// IPv4 form still trusts a peer whose address is the corresponding v4 address
// and honors X-Forwarded-For for that peer.
//
// The config parser normalizes "::ffff:127.0.0.1/128" → "127.0.0.1/32" before
// storing it. This test exercises the resulting prefix directly, simulating the
// post-normalization state.
func TestClientIP_4in6TrustedPrefixHonored(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	// Simulate what parseTrustedProxyCIDRs produces after normalizing
	// "::ffff:127.0.0.1/128": the canonical IPv4 prefix 127.0.0.1/32.
	trusted := mustPrefixes(t, "127.0.0.1/32")
	got := audit.ClientIP(req, trusted)
	if got != "203.0.113.7" {
		t.Fatalf("4in6-normalized trusted prefix should trust peer 127.0.0.1 and honor XFF; got %q", got)
	}
}

// TestClientIP_RejectsBogusAddressClasses is a table-driven test asserting that
// addresses which cannot belong to a real client (unspecified, multicast,
// link-local unicast, and the IPv4 limited broadcast) are treated like an
// unparseable hop and cause a fallback to the peer address, never returned
// directly regardless of trust chain position.
func TestClientIP_RejectsBogusAddressClasses(t *testing.T) {
	cases := []struct {
		name    string
		xffAddr string
	}{
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"link-local unicast v4", "169.254.1.1"},
		{"link-local unicast v6", "fe80::1"},
		{"limited broadcast", "255.255.255.255"},
	}
	trusted := mustPrefixes(t, "127.0.0.0/8")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set("X-Forwarded-For", tc.xffAddr)

			got := audit.ClientIP(req, trusted)
			if got == tc.xffAddr {
				t.Fatalf("bogus address %q must not be returned; expected peer fallback 127.0.0.1, got %q", tc.xffAddr, got)
			}
			if got != "127.0.0.1" {
				t.Fatalf("bogus address class in XFF should fall back to peer 127.0.0.1; got %q", got)
			}
		})
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
