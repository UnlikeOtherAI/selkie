import Foundation

enum WireGuardConfigError: LocalizedError {
    case missingInterfaceAddress
    case invalidAddress(String)

    var errorDescription: String? {
        switch self {
        case .missingInterfaceAddress:
            return "The WireGuard config does not include an interface address."
        case let .invalidAddress(value):
            return "The WireGuard config contains an invalid address: \(value)"
        }
    }
}

struct WireGuardConfig {
    static let defaultRelayHost = "relay.selkie.live"

    let original: String
    let interfaceAddresses: [CIDRAddress]
    let dnsServers: [String]
    let allowedIPs: [CIDRAddress]
    let mtu: Int?
    let endpointHost: String?

    /// Interface `PrivateKey` (base64) if present in the config. On Selkie the private
    /// key is generated on-device and injected via `settingPrivateKey(_:)` before the
    /// config reaches the tunnel, so a server-provided config may carry a placeholder.
    let privateKey: String?
    /// Peer `PublicKey` (base64) of the WireGuard hub.
    let peerPublicKey: String?
    /// Optional peer `PresharedKey` (base64).
    let presharedKey: String?
    /// Full peer `Endpoint` as `host:port`, preserved verbatim for the tunnel backend.
    let endpoint: String?
    /// Peer `PersistentKeepalive` in seconds, if configured.
    let persistentKeepalive: Int?

    init(configString: String) throws {
        original = configString

        var state = ParseState()
        var section = ""

        for rawLine in configString.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else {
                continue
            }

            if let nextSection = Self.sectionName(from: line) {
                section = nextSection
                continue
            }

            guard let entry = Self.entry(from: line) else {
                continue
            }

            try state.apply(entry: entry, in: section)
        }

        guard !state.interfaceAddresses.isEmpty else {
            throw WireGuardConfigError.missingInterfaceAddress
        }

        interfaceAddresses = state.interfaceAddresses
        dnsServers = state.dnsServers
        allowedIPs = state.allowedIPs
        mtu = state.mtu
        endpointHost = state.endpointHost
        privateKey = state.privateKey
        peerPublicKey = state.peerPublicKey
        presharedKey = state.presharedKey
        endpoint = state.endpoint
        persistentKeepalive = state.persistentKeepalive
    }

    var remoteAddress: String {
        endpointHost ?? Self.defaultRelayHost
    }

    /// Returns the config text with the `[Interface]` `PrivateKey` set to `privateKeyBase64`.
    ///
    /// The device keypair never leaves the phone, so the server-returned config carries a
    /// placeholder (or no) private key. The app injects the real private key here right
    /// before handing the wg-quick config to the tunnel. An existing `PrivateKey` line is
    /// replaced in place; otherwise the line is inserted at the top of the `[Interface]`
    /// section.
    func settingPrivateKey(_ privateKeyBase64: String) -> String {
        let newLine = "PrivateKey = \(privateKeyBase64)"
        var lines = original.components(separatedBy: "\n")
        var currentSection = ""
        var interfaceHeaderIndex: Int?

        for index in lines.indices {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                currentSection = trimmed.lowercased()
                if currentSection == "[interface]" {
                    interfaceHeaderIndex = index
                }
                continue
            }
            if currentSection == "[interface]",
               trimmed.lowercased().replacingOccurrences(of: " ", with: "").hasPrefix("privatekey=") {
                lines[index] = newLine
                return lines.joined(separator: "\n")
            }
        }

        if let headerIndex = interfaceHeaderIndex {
            lines.insert(newLine, at: headerIndex + 1)
            return lines.joined(separator: "\n")
        }

        // No [Interface] section at all: prepend one.
        return "[Interface]\n\(newLine)\n\(original)"
    }

    var firstIPv4Address: CIDRAddress? {
        interfaceAddresses.first(where: \.isIPv4)
    }

    var firstIPv6Address: CIDRAddress? {
        interfaceAddresses.first(where: { !$0.isIPv4 })
    }

    var ipv4AllowedIPs: [CIDRAddress] {
        allowedIPs.filter(\.isIPv4)
    }

    var ipv6AllowedIPs: [CIDRAddress] {
        allowedIPs.filter { !$0.isIPv4 }
    }

    private static func sectionName(from line: String) -> String? {
        guard line.hasPrefix("["), line.hasSuffix("]") else {
            return nil
        }
        return line.lowercased()
    }

    private static func entry(from line: String) -> (key: String, value: String)? {
        let parts = line
            .split(separator: "=", maxSplits: 1)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2 else {
            return nil
        }
        return (key: parts[0].lowercased(), value: parts[1])
    }

    private static func parseAddresses(_ value: String) throws -> [CIDRAddress] {
        try value.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .map(CIDRAddress.init)
    }

    private static func parseStrings(_ value: String) -> [String] {
        value.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private static func parseEndpointHost(_ endpoint: String) -> String {
        let trimmed = endpoint.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("[") {
            let host = trimmed
                .split(separator: "]", maxSplits: 1)
                .first?
                .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            return host ?? trimmed
        }
        return trimmed.split(separator: ":", maxSplits: 1).first.map(String.init) ?? trimmed
    }

    private struct ParseState {
        var interfaceAddresses: [CIDRAddress] = []
        var dnsServers: [String] = []
        var allowedIPs: [CIDRAddress] = []
        var mtu: Int?
        var endpointHost: String?
        var privateKey: String?
        var peerPublicKey: String?
        var presharedKey: String?
        var endpoint: String?
        var persistentKeepalive: Int?

        mutating func apply(entry: (key: String, value: String), in section: String) throws {
            switch (section, entry.key) {
            case ("[interface]", "address"):
                interfaceAddresses.append(contentsOf: try WireGuardConfig.parseAddresses(entry.value))
            case ("[interface]", "dns"):
                dnsServers.append(contentsOf: WireGuardConfig.parseStrings(entry.value))
            case ("[interface]", "mtu"):
                mtu = Int(entry.value)
            case ("[interface]", "privatekey"):
                privateKey = entry.value
            case ("[peer]", "publickey"):
                peerPublicKey = entry.value
            case ("[peer]", "presharedkey"):
                presharedKey = entry.value
            case ("[peer]", "allowedips"):
                allowedIPs.append(contentsOf: try WireGuardConfig.parseAddresses(entry.value))
            case ("[peer]", "endpoint"):
                endpoint = entry.value.trimmingCharacters(in: .whitespaces)
                endpointHost = WireGuardConfig.parseEndpointHost(entry.value)
            case ("[peer]", "persistentkeepalive"):
                persistentKeepalive = Int(entry.value)
            default:
                break
            }
        }
    }
}

struct CIDRAddress: Hashable {
    let address: String
    let prefixLength: Int

    init(_ rawValue: String) throws {
        let parts = rawValue.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefixLength = Int(parts[1]) else {
            throw WireGuardConfigError.invalidAddress(rawValue)
        }
        address = parts[0]
        self.prefixLength = prefixLength
    }

    var isIPv4: Bool {
        address.contains(".")
    }

    var stringRepresentation: String {
        "\(address)/\(prefixLength)"
    }

    var netmask: String {
        guard isIPv4 else {
            return "255.255.255.255"
        }
        let mask = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
        return [24, 16, 8, 0]
            .map { String((mask >> UInt32($0)) & 0xff) }
            .joined(separator: ".")
    }
}
