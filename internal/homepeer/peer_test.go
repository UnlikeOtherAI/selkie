package homepeer_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/unlikeotherai/selkie/internal/direct"
	"github.com/unlikeotherai/selkie/internal/homepeer"
	"golang.org/x/crypto/curve25519"
)

func keyPair(t *testing.T) (string, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(public)
}

func TestDirectEncryptedServiceAndRevocation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	homeKey, homePublic := keyPair(t)
	mobileKey, mobilePublic := keyPair(t)
	home, err := homepeer.New(homeKey, "10.100.2.2", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	mobile, err := homepeer.New(mobileKey, "10.100.2.3", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()
	runtime, err := home.Device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(runtime, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("no WireGuard UDP socket")
	}
	if err := home.Apply(direct.Snapshot{OverlayIP: "10.100.2.2", Peers: []direct.Peer{{PublicKey: mobilePublic, OverlayIP: "10.100.2.3"}}}); err != nil {
		t.Fatal(err)
	}
	if err := mobile.Apply(direct.Snapshot{OverlayIP: "10.100.2.3", Peers: []direct.Peer{{PublicKey: homePublic, OverlayIP: "10.100.2.2", Endpoint: "127.0.0.1:" + port}}}); err == nil {
		t.Fatal("unicast endpoint validator accepted loopback public endpoint")
	}
	// A private LAN endpoint works without a public hub. Select a real LAN
	// interface so the production endpoint validator remains strict.
	probe, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := net.JoinHostPort(probe.LocalAddr().(*net.UDPAddr).IP.String(), port)
	_ = probe.Close()
	if err := mobile.Apply(direct.Snapshot{OverlayIP: "10.100.2.3", Peers: []direct.Peer{{PublicKey: homePublic, OverlayIP: "10.100.2.2", Endpoint: endpoint}}}); err != nil {
		t.Fatal(err)
	}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() {
		client, err := local.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = io.Copy(client, client)
	}()
	go func() { _ = home.Serve(ctx, 8790, local.Addr().String()) }()
	var remote net.Conn
	for ctx.Err() == nil {
		attempt, stop := context.WithTimeout(ctx, 200*time.Millisecond)
		remote, err = mobile.Network.DialContextTCPAddrPort(attempt, netip.MustParseAddrPort("10.100.2.2:8790"))
		stop()
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if err := remote.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("home media bytes through encrypted direct peer")
	if _, err := remote.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(remote, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatal("direct bytes changed")
	}
	// Lease renewal and an unrelated peer arriving retain this TCP stream.
	expires := time.Now().Add(3 * time.Second)
	_, thirdPublic := keyPair(t)
	renewedPeers := []direct.Peer{{PublicKey: mobilePublic, OverlayIP: "10.100.2.3", ValidUntil: &expires}, {PublicKey: thirdPublic, OverlayIP: "10.100.2.4"}}
	if applyErr := home.Apply(direct.Snapshot{OverlayIP: "10.100.2.2", Peers: renewedPeers}); applyErr != nil {
		t.Fatal(applyErr)
	}
	if _, writeErr := remote.Write(payload); writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, readErr := io.ReadFull(remote, received); readErr != nil {
		t.Fatalf("renewal interrupted TCP: %v", readErr)
	}
	// With no further control messages, the local lease timer removes the key.
	expires = time.Now().Add(300 * time.Millisecond)
	renewedPeers[0].ValidUntil = &expires
	if applyErr := home.Apply(direct.Snapshot{OverlayIP: "10.100.2.2", Peers: renewedPeers}); applyErr != nil {
		t.Fatal(applyErr)
	}
	time.Sleep(400 * time.Millisecond)
	_, _ = remote.Write(payload)
	if _, readErr := remote.Read(received); readErr == nil {
		t.Fatal("blackholed control socket allowed expired peer")
	}
	if err := home.Apply(direct.Snapshot{OverlayIP: "10.100.2.2", Peers: []direct.Peer{}}); err != nil {
		t.Fatal(err)
	}
	_, _ = remote.Write(payload)
	if _, err := remote.Read(received); err == nil {
		t.Fatal("revoked peer retained TCP service")
	}
}
