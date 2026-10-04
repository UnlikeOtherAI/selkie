import Foundation
import NetworkExtension
import Security
import CryptoKit

public enum SelkieVPNError: LocalizedError {
    case unavailable
    case keyStore
    public var errorDescription: String? {
        switch self {
        case .unavailable: return "Direct home VPN could not connect."
        case .keyStore: return "The home VPN device key could not be stored securely."
        }
    }
}

/// Product apps supply their existing authenticated, home-scoped Selkie grant.
/// No browser authentication, copied profile, or second login is involved.
@MainActor
public final class SelkieVPNConnector {
    private var manager: NETunnelProviderManager?
    private var enrolledDeviceID: String?
    public var isConnected: Bool { manager?.connection.status == .connected }
    public init() {}

    public func connect(token: String, apiBaseURL: URL, hostname: String,
                        platform: String, extensionBundleIdentifier: String,
                        identityNamespace: String? = nil) async throws {
        guard apiBaseURL.scheme == "https", apiBaseURL.host != nil,
              ["ios", "tvos"].contains(platform) else { throw SelkieVPNError.unavailable }
        let identityHash = identityNamespace.map { value in
            SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        let namespace = extensionBundleIdentifier + (identityHash.map { "." + $0 } ?? "")
        let key = try deviceKey(namespace: namespace)
        let rawName = hostname.lowercased().unicodeScalars.map { scalar -> String in
            CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789").contains(scalar)
                ? String(scalar) : "-"
        }.joined().split(separator: "-").joined(separator: "-")
        let enrollmentName = String(rawName.prefix(40)) + "-" + String(key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined().prefix(12))
        var request = URLRequest(url: apiBaseURL.appending(path: "/api/v1/mobile/enroll"))
        request.timeoutInterval = 15
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "hostname": enrollmentName, "os_platform": platform, "os_arch": "arm64",
            "app_version": "embedded-direct-1",
            "wg_public_key": key.publicKey.rawRepresentation.base64EncodedString()
        ])
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: SelkieControlSessionDelegate(),
                                 delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard data.count <= 1 << 20 else { throw SelkieVPNError.unavailable }
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let config = value["wg_config"] as? String,
              let id = value["device_id"] as? String else { throw SelkieVPNError.unavailable }
        let parsed = try WireGuardConfig(configString: config)
        enrolledDeviceID = id
        let effective = parsed.settingPrivateKey(key.rawRepresentation.base64EncodedString())
        let managers = try await loadManagers()
        let selected = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == extensionBundleIdentifier } ?? NETunnelProviderManager()
        let vpn = NETunnelProviderProtocol()
        vpn.providerBundleIdentifier = extensionBundleIdentifier
        vpn.serverAddress = "Direct home"
        var socketURL = URLComponents(url: apiBaseURL, resolvingAgainstBaseURL: false)!
        socketURL.scheme = "wss"
        socketURL.path = "/api/v1/direct/\(id)/peers"
        vpn.providerConfiguration = ["wgConfig": effective, "directToken": token,
                                     "directPeerURL": socketURL.url!.absoluteString, "directDeviceID": id]
        selected.protocolConfiguration = vpn
        selected.localizedDescription = "Rafiki home connection"
        selected.isEnabled = true
        try await save(selected)
        if selected.connection.status != .disconnected && selected.connection.status != .invalid {
            selected.connection.stopVPNTunnel()
            for _ in 0..<40 {
                if selected.connection.status == .disconnected { break }
                try await Task.sleep(for: .milliseconds(100))
            }
        }
        try selected.connection.startVPNTunnel()
        manager = selected
        for _ in 0..<80 {
            if selected.connection.status == .connected { return }
            if selected.connection.status == .invalid { break }
            try await Task.sleep(for: .milliseconds(250))
        }
        selected.connection.stopVPNTunnel()
        throw SelkieVPNError.unavailable
    }

    public func renewAuthorization(token: String) async throws {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status == .connected, let deviceID = enrolledDeviceID else { throw SelkieVPNError.unavailable }
        let payload = try JSONSerialization.data(withJSONObject: ["directToken": token, "directDeviceID": deviceID])
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            do {
                try session.sendProviderMessage(payload) { response in
                    if response == Data("ok".utf8) { continuation.resume() } else {
                        continuation.resume(throwing: SelkieVPNError.unavailable)
                    }
                }
            } catch { continuation.resume(throwing: error) }
        }
    }

    public func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    private func deviceKey(namespace: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespace + ".device-key", kSecAttrAccount as String: "wireguard"]
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
        }
        guard status == errSecItemNotFound else { throw SelkieVPNError.keyStore }
        let key = Curve25519.KeyAgreement.PrivateKey()
        var insertion = query
        insertion[kSecValueData as String] = key.rawRepresentation
        insertion[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(insertion as CFDictionary, nil) == errSecSuccess else { throw SelkieVPNError.keyStore }
        return key
    }

    private func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }
}
