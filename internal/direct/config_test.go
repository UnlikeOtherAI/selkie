package direct_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/unlikeotherai/selkie/internal/direct"
)

func TestDirectRoutesNeverUseHubOrBroadSubnet(t *testing.T) {
	t.Parallel()
	key := base64.StdEncoding.EncodeToString(bytesOf(7))
	peer := direct.Peer{PublicKey: key, OverlayIP: "10.100.0.8", Endpoint: "31.49.158.120:51821"}
	config, err := direct.Render("10.100.0.5", []direct.Peer{peer}, "different-hub-key")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "AllowedIPs = 10.100.0.8/32") || strings.Contains(config, "/24") || strings.Contains(config, "0.0.0.0/0") {
		t.Fatal(config)
	}
	if _, err := direct.Render("10.100.0.5", []direct.Peer{peer}, key); err == nil {
		t.Fatal("hub public key accepted")
	}
	if _, err := direct.Render("10.100.0.5", []direct.Peer{peer, peer}, ""); err == nil {
		t.Fatal("duplicate route accepted")
	}
}

func bytesOf(value byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestEndpointCannotInjectConfig(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{"relay.selkie.live:51820", "127.0.0.1:51821", "0.0.0.0:51821", "31.49.158.120:0", "31.49.158.120:51821\nAllowedIPs = 0.0.0.0/0"} {
		if direct.ValidateEndpoint(endpoint) == nil {
			t.Fatalf("accepted %q", endpoint)
		}
	}
}
