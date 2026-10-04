// home-peer exposes a single local service over direct WireGuard. The public
// control server carries only authenticated peer metadata over a WebSocket.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/unlikeotherai/selkie/internal/direct"
	"github.com/unlikeotherai/selkie/internal/homepeer"
	"golang.org/x/crypto/curve25519"
)

type state struct {
	Credential string `json:"credential"`
	DeviceID   string `json:"device_id"`
	OverlayIP  string `json:"overlay_ip"`
	PrivateKey string `json:"private_key"`
}

type client struct {
	base, token string
	http        *http.Client
}

func (c client) post(ctx context.Context, path string, body, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control request failed (%d)", resp.StatusCode)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result)
	}
	return nil
}

func (c client) enroll(ctx context.Context, path string) (state, error) {
	var existing state
	//nolint:gosec // Operator-selected private state file, never a network-supplied path.
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &existing)
		return existing, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return state{}, err
	}
	raw := make([]byte, 32)
	if _, checkedErr0 := rand.Read(raw); checkedErr0 != nil {
		return state{}, checkedErr0
	}
	public, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return state{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return state{}, err
	}
	var pair struct {
		Code string `json:"code"`
	}
	err = c.post(ctx, "/api/v1/auth/pair/start", map[string]string{"wg_public_key": base64.StdEncoding.EncodeToString(public), "hostname": hostname, "os_platform": runtime.GOOS, "os_arch": runtime.GOARCH, "agent_version": "direct-home-1"}, &pair)
	if err != nil {
		return state{}, err
	}
	err = c.post(ctx, "/api/v1/auth/pair/claim", map[string]string{"code": pair.Code, "device_name": hostname}, &existing)
	if err != nil {
		return state{}, err
	}
	existing.PrivateKey = base64.StdEncoding.EncodeToString(raw)
	//nolint:gosec // Device private key is deliberately saved to the protected local state file only.
	data, err = json.Marshal(existing)
	if err != nil {
		return state{}, err
	}
	// A new enrollment cannot overwrite an existing identity/key file.
	//nolint:gosec // Operator-selected state path is created exclusively with owner permissions.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return state{}, err
	}
	_, err = file.Write(data)
	closeErr := file.Close()
	if err != nil {
		return state{}, err
	}
	return existing, closeErr
}

func run() error {
	base := flag.String("server", "https://api.selkie.live", "HTTPS control server")
	tokenFile := flag.String("token-file", "", "file containing current Selkie admin session token")
	stateFile := flag.String("state", "selkie-home.json", "private device state file (0600)")
	endpoint := flag.String("endpoint", "", "reachable literal IP:UDP-port at this home machine")
	udpPort := flag.Int("listen-port", 51821, "local WireGuard UDP port")
	servicePort := flag.Int("service-port", 8790, "single overlay TCP port")
	target := flag.String("target", "127.0.0.1:8790", "single loopback TCP service")
	flag.Parse()
	serverURL, err := url.Parse(*base)
	if err != nil || serverURL.Scheme != "https" || serverURL.Host == "" || serverURL.User != nil || serverURL.RawQuery != "" {
		return errors.New("HTTPS control server required")
	}

	var token []byte
	if *tokenFile != "" {
		token, err = os.ReadFile(*tokenFile)
		if err != nil {
			return errors.New("token-file unreadable")
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	control := client{base: strings.TrimRight(*base, "/"), token: strings.TrimSpace(string(token)), http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	identity, err := control.enroll(ctx, *stateFile)
	if err != nil {
		return err
	}
	if identity.Credential == "" {
		return errors.New("device credential missing; enroll with a current token")
	}
	control.token = identity.Credential
	if *endpoint == "" {
		mapping, mapErr := homepeer.MapUDP(ctx, *udpPort)
		if mapErr != nil {
			return mapErr
		}
		defer mapping.Close()
		*endpoint = mapping.Endpoint
		go func() {
			failures := mapping.Maintain(ctx)
			if failures != nil {
				cancel()
			}
		}()
	}
	if checkedErr1 := direct.ValidateEndpoint(*endpoint); checkedErr1 != nil {
		return checkedErr1
	}
	if checkedErr2 := control.post(ctx, "/api/v1/direct/home/"+identity.DeviceID+"/register", map[string]any{"endpoint": *endpoint, "service_port": *servicePort}, nil); checkedErr2 != nil {
		return checkedErr2
	}
	delay := time.Second
	for ctx.Err() == nil {
		sessionErr := runSession(ctx, control, identity, *udpPort, *servicePort, *target)
		if ctx.Err() != nil {
			return nil
		}
		if sessionErr != nil {
			fmt.Fprintln(os.Stderr, "Direct home connection ended; reconnecting with service closed")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
	return nil
}

func runSession(ctx context.Context, control client, identity state, udpPort, servicePort int, target string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	socketURL, err := url.Parse(control.base)
	if err != nil {
		return err
	}
	socketURL.Scheme = "wss"
	socketURL.Path = "/api/v1/direct/home/" + identity.DeviceID + "/peers"
	socket, response, err := websocket.Dial(ctx, socketURL.String(), &websocket.DialOptions{HTTPClient: control.http, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + control.token}}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return errors.New("authenticated peer stream unavailable")
	}
	defer socket.CloseNow() //nolint:errcheck // Best effort socket cleanup.
	socket.SetReadLimit(1 << 20)
	peer, err := homepeer.New(identity.PrivateKey, identity.OverlayIP, udpPort)
	if err != nil {
		return err
	}
	defer peer.Close()
	firstCtx, stopFirst := context.WithTimeout(ctx, 15*time.Second)
	var first direct.Snapshot
	err = wsjson.Read(firstCtx, socket, &first)
	stopFirst()
	if err != nil {
		return errors.New("no authorized peer snapshot")
	}
	if applyErr := peer.Apply(first); applyErr != nil {
		return applyErr
	}
	fmt.Printf("Home peer overlay %s, local encrypted UDP %d, direct service TCP %d\n", identity.OverlayIP, udpPort, servicePort)
	failures := make(chan error, 3)
	go func() { failures <- peer.Serve(ctx, servicePort, target) }()
	go func() {
		for {
			var snapshot direct.Snapshot
			if readErr := wsjson.Read(ctx, socket, &snapshot); readErr != nil {
				failures <- errors.New("peer authorization stream ended")
				return
			}
			if applyErr := peer.Apply(snapshot); applyErr != nil {
				failures <- applyErr
				return
			}
		}
	}()
	go func() { failures <- keepAlive(ctx, socket) }()
	select {
	case <-ctx.Done():
		return nil
	case failure := <-failures:
		return failure
	}
}

func keepAlive(ctx context.Context, socket *websocket.Conn) error {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := socket.Ping(pingCtx)
			cancel()
			if err != nil {
				return errors.New("authenticated control stream lost liveness")
			}
		}
	}
}

func main() {
	if checkedErr7 := run(); checkedErr7 != nil {
		fmt.Fprintln(os.Stderr, checkedErr7)
		os.Exit(1)
	}
}
