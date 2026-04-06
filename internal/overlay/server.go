package overlay

import (
	"fmt"
	"net"
)

// ServerOverlayIP returns the stable server overlay IP for the configured CIDR.
// The server uses the first usable host address in the subnet.
func ServerOverlayIP(cidrStr string) (string, error) {
	ip, _, err := serverAddress(cidrStr)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}

// ServerInterfaceAddress returns the server interface address in CIDR notation,
// using the first usable host address in the configured subnet.
func ServerInterfaceAddress(cidrStr string) (string, error) {
	ip, network, err := serverAddress(cidrStr)
	if err != nil {
		return "", err
	}

	ones, _ := network.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones), nil
}

func serverAddress(cidrStr string) (net.IP, *net.IPNet, error) {
	baseIP, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse overlay cidr: %w", err)
	}

	ip4 := baseIP.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("overlay cidr must be IPv4: %s", cidrStr)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 || bits-ones < 2 {
		return nil, nil, fmt.Errorf("overlay cidr must provide at least 2 host bits: %s", cidrStr)
	}

	serverIP := append(net.IP(nil), ip4...)
	for i := len(serverIP) - 1; i >= 0; i-- {
		serverIP[i]++
		if serverIP[i] != 0 {
			break
		}
	}

	if !network.Contains(serverIP) {
		return nil, nil, fmt.Errorf("server overlay ip is outside cidr: %s", cidrStr)
	}

	return serverIP, network, nil
}
