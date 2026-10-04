package homepeer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/httpu"
	"github.com/huin/goupnp/soap"
	"github.com/huin/goupnp/ssdp"
)

const mappingDescription = "Selkie encrypted direct home"
const mappingLease = 1200

type gateway interface {
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
	GetSpecificPortMappingEntryCtx(context.Context, string, uint16, string) (uint16, string, bool, string, uint32, error)
}

// Mapping owns only its single leased UDP mapping, never a media TCP port.
type Mapping struct {
	Endpoint string
	gateway  gateway
	port     uint16
	local    string
}

// MapUDP discovers a LAN gateway and creates one renewable UDP mapping. SSDP
// responses, redirects, root descriptions and control URLs stay on the LAN.
func MapUDP(ctx context.Context, port int) (*Mapping, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid UDP listen port")
	}
	probe, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err != nil {
		return nil, err
	}
	local := probe.LocalAddr().(*net.UDPAddr).IP.String()
	_ = probe.Close()
	udp, err := httpu.NewHTTPUClient()
	if err != nil {
		return nil, err
	}
	defer udp.Close() //nolint:errcheck // ephemeral discovery socket
	discoveryCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	responses, err := ssdp.SSDPRawSearchCtx(discoveryCtx, udp, "urn:schemas-upnp-org:device:InternetGatewayDevice:2", 2, 2)
	if err != nil {
		return nil, err
	}
	// The library uses this transport for description downloads; each request
	// is constrained before it can leave the machine, including redirects.
	goupnp.HTTPClientDefault = &http.Client{Timeout: 5 * time.Second, Transport: lanTransport{local: local}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("gateway redirects forbidden") }}
	for _, response := range responses {
		location, err := url.Parse(response.Header.Get("Location"))
		if err != nil || !localURL(location, local) {
			continue
		}
		clients, err := internetgateway2.NewWANIPConnection2ClientsByURLCtx(discoveryCtx, location)
		if err != nil {
			continue
		}
		for _, candidate := range clients {
			if !localURL(&candidate.SOAPClient.EndpointURL, local) || candidate.SOAPClient.EndpointURL.Hostname() != location.Hostname() {
				continue
			}
			candidate.SOAPClient.HTTPClient = *goupnp.HTTPClientDefault
			mapping := &Mapping{gateway: candidate, port: uint16(port), local: local}
			if err := mapping.create(discoveryCtx); err != nil {
				continue
			}
			return mapping, nil
		}
	}
	return nil, errors.New("no usable direct UDP mapping; configure an explicit reachable WireGuard endpoint (relay is disabled)")
}

type lanTransport struct{ local string }

func (l lanTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !localURL(r.URL, l.local) {
		return nil, errors.New("gateway URL outside local subnet")
	}
	return http.DefaultTransport.RoundTrip(r)
}

func localURL(u *url.URL, local string) bool {
	if u == nil || u.Scheme != "http" || u.User != nil {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsPrivate() {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, network := range interfaces {
		addresses, err := network.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().String() == local && prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (m *Mapping) create(ctx context.Context) error {
	// An occupied port belonging to another application is never overwritten.
	internal, client, _, description, _, err := m.gateway.GetSpecificPortMappingEntryCtx(ctx, "", m.port, "UDP")
	if err == nil && (internal != m.port || client != m.local || description != mappingDescription) {
		return errors.New("UDP port mapping already owned by another application")
	}
	if err != nil {
		var fault *soap.SOAPFaultError
		if !errors.As(err, &fault) || fault.Detail.UPnPError.Errorcode != 714 {
			return errors.New("cannot verify ownership of UDP mapping")
		}
	}
	external, err := m.gateway.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(external)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return errors.New("gateway has no public IPv4 endpoint")
	}
	if err := m.gateway.AddPortMappingCtx(ctx, "", m.port, "UDP", m.port, m.local, true, mappingDescription, mappingLease); err != nil {
		return err
	}
	m.Endpoint = net.JoinHostPort(external, strconv.Itoa(int(m.port)))
	return nil
}

// Maintain renews before lease expiry. Losing the endpoint ends the direct
// service, rather than silently routing through a public relay.
func (m *Mapping) Maintain(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			previous := m.Endpoint
			attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := m.create(attempt)
			cancel()
			if err != nil {
				return err
			}
			if previous != m.Endpoint {
				return errors.New("public endpoint changed; reconnect direct service")
			}
		}
	}
}

// Close removes the mapping only if it still belongs to this instance.
func (m *Mapping) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	internal, client, _, description, _, err := m.gateway.GetSpecificPortMappingEntryCtx(ctx, "", m.port, "UDP")
	if err == nil && internal == m.port && client == m.local && description == mappingDescription {
		if err := m.gateway.DeletePortMappingCtx(ctx, "", m.port, "UDP"); err != nil {
			fmt.Println("Selkie UDP mapping cleanup failed; lease will expire")
		}
	}
}
