package overlay

import "fmt"

// PeerConfig holds the WireGuard configuration fragments needed by both sides
// of the hub-and-spoke overlay tunnel.
type PeerConfig struct {
	// DeviceSide is the [Peer] stanza the device agent applies to reach the server hub.
	DeviceSide string `json:"device_side_config"`
	// ServerSide is the [Peer] stanza the server adds to its wg interface for this device.
	ServerSide string `json:"server_side_config"`
	// OverlayIP is the device's assigned overlay address.
	OverlayIP string `json:"overlay_ip"`
}

// GeneratePeerConfig produces WireGuard config fragments for a device in the
// hub-and-spoke topology. The device peers only with the server; the server
// routes between devices.
func GeneratePeerConfig(
	serverPublicKey string,
	serverEndpoint string,
	serverWGPort int,
	overlayCIDR string,
	devicePublicKey string,
	deviceOverlayIP string,
) PeerConfig {
	deviceSide := fmt.Sprintf(`[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = %s
PersistentKeepalive = 25
`, serverPublicKey, serverEndpoint, serverWGPort, overlayCIDR)

	serverSide := fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, devicePublicKey, deviceOverlayIP)

	return PeerConfig{
		DeviceSide: deviceSide,
		ServerSide: serverSide,
		OverlayIP:  deviceOverlayIP,
	}
}
