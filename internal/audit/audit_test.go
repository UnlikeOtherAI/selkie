package audit_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

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

// TestClientIP_ZonedIPv6Stripped verifies that a zone suffix ("%eth0") in an
// XFF address is stripped before the address is evaluated or returned. The
// previous version of this test used fe80::1%eth0, which is correctly
// rejected by the link-local class check before zone-strip semantics are
// observable. This revision uses a documentation-range address (2001:db8::1)
// that passes all class checks. The peer (127.0.0.1) is trusted so XFF is
// honored; 2001:db8::1 is not in any trusted prefix so it is returned as the
// rightmost-non-trusted entry. The returned string must be "2001:db8::1"
// with no "%" suffix, confirming that zone-strip runs before the address is
// returned.
func TestClientIP_ZonedIPv6Stripped(t *testing.T) {
	// Only trust loopback — 2001:db8::1 is not trusted and will be returned.
	trusted := mustPrefixes(t, "127.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "2001:db8::1%eth0")

	got := audit.ClientIP(req, trusted)
	if got != "2001:db8::1" {
		t.Fatalf("zone not stripped: got %q", got)
	}
	if strings.Contains(got, "%") {
		t.Fatalf("got contains zone suffix: %q", got)
	}
}

// TestClientIP_PeerZonedStripped verifies zone stripping on the peer side.
// When RemoteAddr contains a zoned IPv6 address (e.g. [fe80::1%eth0]:1234)
// and no trusted prefixes are configured, the function falls back to the peer.
// The returned peer string must have the zone suffix stripped even though
// fe80::1 would also be class-rejected on the XFF path.
func TestClientIP_PeerZonedStripped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[fe80::1%eth0]:1234"

	got := audit.ClientIP(req, nil)
	if strings.Contains(got, "%") {
		t.Fatalf("peer zone suffix must be stripped; got %q", got)
	}
	if got != "fe80::1" {
		t.Fatalf("expected zone-stripped peer fe80::1; got %q", got)
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
// link-local unicast, and the IPv4 limited broadcast) are skipped during the
// walk, never returned directly regardless of trust chain position. When the
// bogus entry is the only hop the walk falls back to the trusted peer.
// The 4in6 forms ::ffff:0.0.0.0 and ::ffff:255.255.255.255 are included to
// cover the Unmap-before-class-check fix (Fix 2).
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
		{"site-local v6", "fec0::1"},
		{"4in6 unspecified", "::ffff:0.0.0.0"},
		{"4in6 broadcast", "::ffff:255.255.255.255"},
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

// TestClientIP_BogusClassEntryDoesNotShortCircuitWalk is a regression test for
// the HIGH fix: a class-rejected entry (fec0::1, site-local) in the middle of
// a chain must be skipped — not cause an early return of the peer — so the walk
// continues leftward and surfaces the real client IP.
//
// Trusted: 127.0.0.0/8, 10.0.0.0/8. Peer: 127.0.0.1:54321 (trusted).
// XFF: "203.0.113.42, fec0::1, 10.0.0.5"
//   - 10.0.0.5 is trusted → skip.
//   - fec0::1 is site-local (bogus class) → skip (not return peer).
//   - 203.0.113.42 is the first non-trusted entry → return it.
func TestClientIP_BogusClassEntryDoesNotShortCircuitWalk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.42, fec0::1, 10.0.0.5")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8", "10.0.0.0/8"))
	if got == "127.0.0.1" {
		t.Fatalf("class-rejected hop must not short-circuit the walk to peer; got %q (want 203.0.113.42)", got)
	}
	if got != "203.0.113.42" {
		t.Fatalf("expected 203.0.113.42 after skipping bogus-class hop; got %q", got)
	}
}

// TestClientIP_BogusClassEntryAtRightmostSkipped is a second regression test
// for the HIGH fix covering the ordering where the bogus entry sits between the
// real hops.
//
// Trusted: 10.0.0.0/8. Peer: 10.0.0.1:443 (trusted).
// XFF: "203.0.113.42, fec0::1, 10.0.0.5"
//   - 10.0.0.5 is trusted → skip.
//   - fec0::1 is site-local (bogus class) → skip.
//   - 203.0.113.42 is non-trusted → return it.
func TestClientIP_BogusClassEntryAtRightmostSkipped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.42, fec0::1, 10.0.0.5")

	got := audit.ClientIP(req, mustPrefixes(t, "10.0.0.0/8"))
	if got != "203.0.113.42" {
		t.Fatalf("expected 203.0.113.42 after skipping bogus-class and trusted hops; got %q", got)
	}
}

// TestClientIP_4in6UnspecifiedRejected is a regression test for the MEDIUM fix:
// the 4in6 form ::ffff:0.0.0.0 must be caught by the class check after Unmap
// and skipped, not surfaced as "0.0.0.0".
//
// When it is the only XFF hop the walk exhausts the chain and falls back to peer.
func TestClientIP_4in6UnspecifiedRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "::ffff:0.0.0.0")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got == "0.0.0.0" || got == "::ffff:0.0.0.0" {
		t.Fatalf("4in6 unspecified must not be returned; got %q", got)
	}
	if got != "127.0.0.1" {
		t.Fatalf("expected peer fallback 127.0.0.1 after skipping 4in6 unspecified; got %q", got)
	}
}

// TestClientIP_4in6BroadcastRejected is a regression test for the MEDIUM fix:
// the 4in6 form ::ffff:255.255.255.255 must be caught by the broadcast check
// after Unmap and skipped, not surfaced as "255.255.255.255".
//
// When it is the only XFF hop the walk exhausts the chain and falls back to peer.
func TestClientIP_4in6BroadcastRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "::ffff:255.255.255.255")

	got := audit.ClientIP(req, mustPrefixes(t, "127.0.0.0/8"))
	if got == "255.255.255.255" || got == "::ffff:255.255.255.255" {
		t.Fatalf("4in6 broadcast must not be returned; got %q", got)
	}
	if got != "127.0.0.1" {
		t.Fatalf("expected peer fallback 127.0.0.1 after skipping 4in6 broadcast; got %q", got)
	}
}

func TestRateLimitIP_EmptyInput(t *testing.T) {
	if got := audit.RateLimitIP(""); got != "" {
		t.Fatalf("empty input must return empty string; got %q", got)
	}
}

func TestRateLimitIP_UnparseableReturnsEmpty(t *testing.T) {
	// Junk inputs must not become a rate-limit key — otherwise an attacker
	// that controls r.RemoteAddr (or an upstream XFF) can choose the bucket
	// every other caller is pinned onto.
	cases := []string{
		"not-an-ip",
		"127.0.0.1; DROP TABLE users",
		"\x00\x01",
		"   ",
	}
	for _, c := range cases {
		if got := audit.RateLimitIP(c); got != "" {
			t.Fatalf("unparseable input %q must return empty; got %q", c, got)
		}
	}
}

func TestRateLimitIP_IPv4Unchanged(t *testing.T) {
	if got := audit.RateLimitIP("198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("IPv4 must be returned unchanged; got %q", got)
	}
}

func TestRateLimitIP_IPv6CollapsedToSlash64(t *testing.T) {
	cases := map[string]string{
		"2001:db8::1":          "2001:db8::/64",
		"2001:db8::abcd:ef01":  "2001:db8::/64",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"fe80::1":              "fe80::/64",
	}
	for in, want := range cases {
		got := audit.RateLimitIP(in)
		if got != want {
			t.Fatalf("RateLimitIP(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestRateLimitIP_4in6CollapsesToIPv4(t *testing.T) {
	// An IPv4-mapped IPv6 address must aggregate onto the IPv4 bucket, not
	// onto a fresh /64. Otherwise the same caller arriving as ::ffff:a.b.c.d
	// vs a.b.c.d would land on two different limiter buckets.
	got := audit.RateLimitIP("::ffff:192.0.2.1")
	if got != "192.0.2.1" {
		t.Fatalf("4in6 must unmap to IPv4 bucket; got %q", got)
	}
}

func TestTruncateUserAgent_ShortPassesThrough(t *testing.T) {
	ua := "Mozilla/5.0"
	if got := audit.TruncateUserAgent(ua); got != ua {
		t.Fatalf("short UA must pass through unchanged; got %q", got)
	}
}

func TestTruncateUserAgent_BoundsLongInput(t *testing.T) {
	huge := strings.Repeat("a", 5000)
	got := audit.TruncateUserAgent(huge)
	if len(got) > audit.MaxUserAgentBytes {
		t.Fatalf("truncation must cap at MaxUserAgentBytes=%d; got len=%d", audit.MaxUserAgentBytes, len(got))
	}
}

func TestTruncateUserAgent_StripsPartialUTF8AtBoundary(t *testing.T) {
	// Build a UA where the truncation boundary falls inside a 3-byte rune.
	// MaxUserAgentBytes is 512. Pad with ASCII to 511 bytes, then place a
	// 3-byte rune (\u20AC = 0xE2 0x82 0xAC) that straddles the boundary.
	prefix := strings.Repeat("a", audit.MaxUserAgentBytes-1)
	straddling := prefix + "\u20AC" + "tail"
	got := audit.TruncateUserAgent(straddling)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated UA must be valid UTF-8; got %q", got)
	}
	if len(got) > audit.MaxUserAgentBytes {
		t.Fatalf("truncated UA exceeded cap; got len=%d", len(got))
	}
}
