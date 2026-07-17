import Foundation
import WireGuardKit

/// Errors raised while translating a parsed wg-quick config into a WireGuardKit
/// `TunnelConfiguration`.
///
/// This translation layer is intentionally free of any product-specific (Selkie)
/// logic so it can be reused verbatim by sibling products (e.g. Coding Homie) that
/// drive the same packet-tunnel extension.
enum WireGuardTunnelConfigurationError: LocalizedError {
    case missingPrivateKey
    case invalidPrivateKey
    case missingPeerPublicKey
    case invalidPeerPublicKey
    case invalidPresharedKey
    case invalidInterfaceAddress(String)
    case invalidAllowedIP(String)
    case invalidEndpoint(String)

    var errorDescription: String? {
        switch self {
        case .missingPrivateKey:
            return "The WireGuard config is missing an interface PrivateKey."
        case .invalidPrivateKey:
            return "The WireGuard interface PrivateKey is not a valid base64 key."
        case .missingPeerPublicKey:
            return "The WireGuard config is missing a peer PublicKey."
        case .invalidPeerPublicKey:
            return "The WireGuard peer PublicKey is not a valid base64 key."
        case .invalidPresharedKey:
            return "The WireGuard peer PresharedKey is not a valid base64 key."
        case let .invalidInterfaceAddress(value):
            return "The WireGuard interface address is invalid: \(value)"
        case let .invalidAllowedIP(value):
            return "The WireGuard AllowedIPs entry is invalid: \(value)"
        case let .invalidEndpoint(value):
            return "The WireGuard peer endpoint is invalid: \(value)"
        }
    }
}

extension TunnelConfiguration {
    /// Builds a WireGuardKit `TunnelConfiguration` from a parsed wg-quick config.
    ///
    /// The single-peer hub-and-spoke topology used by Selkie maps onto exactly one
    /// `PeerConfiguration`. The interface `PrivateKey` must already be present in the
    /// config (the app injects the on-device key via `WireGuardConfig.settingPrivateKey`).
    convenience init(from config: WireGuardConfig, name: String?) throws {
        let interface = try Self.makeInterface(from: config)
        let peer = try Self.makePeer(from: config)
        self.init(name: name, interface: interface, peers: [peer])
    }

    private static func makeInterface(from config: WireGuardConfig) throws -> InterfaceConfiguration {
        guard let privateKeyBase64 = config.privateKey, !privateKeyBase64.isEmpty else {
            throw WireGuardTunnelConfigurationError.missingPrivateKey
        }
        guard let privateKey = PrivateKey(base64Key: privateKeyBase64) else {
            throw WireGuardTunnelConfigurationError.invalidPrivateKey
        }

        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try config.interfaceAddresses.map { cidr in
            try Self.ipRange(cidr, error: .invalidInterfaceAddress(cidr.stringRepresentation))
        }
        interface.dns = config.dnsServers.compactMap { DNSServer(from: $0) }
        if let mtu = config.mtu {
            interface.mtu = UInt16(exactly: mtu)
        }
        return interface
    }

    private static func makePeer(from config: WireGuardConfig) throws -> PeerConfiguration {
        guard let peerPublicKeyBase64 = config.peerPublicKey, !peerPublicKeyBase64.isEmpty else {
            throw WireGuardTunnelConfigurationError.missingPeerPublicKey
        }
        guard let peerPublicKey = PublicKey(base64Key: peerPublicKeyBase64) else {
            throw WireGuardTunnelConfigurationError.invalidPeerPublicKey
        }

        var peer = PeerConfiguration(publicKey: peerPublicKey)
        peer.allowedIPs = try config.allowedIPs.map { cidr in
            try Self.ipRange(cidr, error: .invalidAllowedIP(cidr.stringRepresentation))
        }
        if let endpointString = config.endpoint {
            guard let endpoint = Endpoint(from: endpointString) else {
                throw WireGuardTunnelConfigurationError.invalidEndpoint(endpointString)
            }
            peer.endpoint = endpoint
        }
        if let keepalive = config.persistentKeepalive {
            peer.persistentKeepAlive = UInt16(exactly: keepalive)
        }
        if let presharedKeyBase64 = config.presharedKey, !presharedKeyBase64.isEmpty {
            guard let presharedKey = PreSharedKey(base64Key: presharedKeyBase64) else {
                throw WireGuardTunnelConfigurationError.invalidPresharedKey
            }
            peer.preSharedKey = presharedKey
        }
        return peer
    }

    private static func ipRange(
        _ cidr: CIDRAddress,
        error: @autoclosure () -> WireGuardTunnelConfigurationError
    ) throws -> IPAddressRange {
        guard let range = IPAddressRange(from: cidr.stringRepresentation) else {
            throw error()
        }
        return range
    }
}
