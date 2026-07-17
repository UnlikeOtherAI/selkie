import Foundation
import NetworkExtension
import os
import WireGuardKit

enum PacketTunnelProviderError: LocalizedError {
    case invalidTunnelConfig

    var errorDescription: String? {
        switch self {
        case .invalidTunnelConfig:
            return "The tunnel configuration is missing or invalid."
        }
    }
}

/// Packet Tunnel Provider that moves packets through the official WireGuard Go
/// backend via `WireGuardAdapter`.
///
/// The provider is deliberately product-agnostic: it consumes a wg-quick config
/// string from `providerConfiguration["wgConfig"]` and knows nothing about Selkie
/// enrollment, sessions, or APIs. This keeps it reusable by sibling products that
/// embed the same extension.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(
        subsystem: "com.unlikeotherai.selkie.ios.tunnel",
        category: "PacketTunnelProvider"
    )

    /// In-memory ring buffer of backend log lines, retrievable by the container app
    /// via `handleAppMessage` so tunnel diagnostics are readable without an app group.
    private let logRing = TunnelLogRing(capacity: 1000)

    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { [weak self] logLevel, message in
            guard let self else { return }
            switch logLevel {
            case .verbose:
                self.logger.debug("\(message, privacy: .public)")
            case .error:
                self.logger.error("\(message, privacy: .public)")
            }
            self.logRing.append("[\(logLevel.tag)] \(message)")
        }
    }()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        logRing.append("[app] startTunnel requested")

        let tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try makeTunnelConfiguration()
        } catch {
            logger.error("Invalid WireGuard config: \(error.localizedDescription, privacy: .public)")
            logRing.append("[app] invalid config: \(error.localizedDescription)")
            completionHandler(error)
            return
        }

        adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self else {
                completionHandler(adapterError)
                return
            }

            if let adapterError {
                self.logger.error(
                    "WireGuard adapter failed to start: \(adapterError.localizedDescription, privacy: .public)"
                )
                self.logRing.append("[app] adapter start failed: \(adapterError.localizedDescription)")
                completionHandler(adapterError)
                return
            }

            self.logger.info("WireGuard tunnel started")
            self.logRing.append("[app] tunnel started")
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.info("Stopping tunnel with reason: \(reason.rawValue, privacy: .public)")
        logRing.append("[app] stopTunnel reason=\(reason.rawValue)")

        adapter.stop { [weak self] error in
            if let error {
                self?.logger.error(
                    "WireGuard adapter failed to stop cleanly: \(error.localizedDescription, privacy: .public)"
                )
                self?.logRing.append("[app] adapter stop error: \(error.localizedDescription)")
            }

            completionHandler()
        }
    }

    /// App ↔ extension IPC. The container app sends a UTF-8 command and receives a
    /// reply. Supported commands:
    /// - `getruntimeconfiguration`: the live wg uapi/runtime configuration
    /// - `getlog`: buffered backend log lines
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let command = String(data: messageData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        else {
            completionHandler?(nil)
            return
        }

        switch command {
        case TunnelMessage.getRuntimeConfiguration:
            adapter.getRuntimeConfiguration { settings in
                completionHandler?(settings?.data(using: .utf8))
            }
        case TunnelMessage.getLog:
            completionHandler?(logRing.joined().data(using: .utf8))
        default:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // The backend keeps its own state; nothing to tear down for sleep.
        logRing.append("[app] sleep")
        completionHandler()
    }

    override func wake() {
        // `WireGuardAdapter` reacts to network path changes internally, so there is
        // nothing extra to do on wake beyond noting it.
        logRing.append("[app] wake")
    }

    // MARK: - Private

    private func makeTunnelConfiguration() throws -> TunnelConfiguration {
        guard let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = providerProtocol.providerConfiguration,
              let wgConfig = providerConfiguration["wgConfig"] as? String
        else {
            throw PacketTunnelProviderError.invalidTunnelConfig
        }

        let parsed = try WireGuardConfig(configString: wgConfig)
        return try TunnelConfiguration(from: parsed, name: providerProtocol.serverAddress)
    }
}

private extension WireGuardLogLevel {
    var tag: String {
        switch self {
        case .verbose: return "verbose"
        case .error: return "error"
        }
    }
}

/// Minimal thread-safe fixed-capacity log buffer.
private final class TunnelLogRing {
    private let capacity: Int
    private var lines: [String] = []
    private let queue = DispatchQueue(label: "com.unlikeotherai.selkie.tunnel.log")

    init(capacity: Int) {
        self.capacity = capacity
    }

    func append(_ line: String) {
        queue.sync {
            lines.append(line)
            if lines.count > capacity {
                lines.removeFirst(lines.count - capacity)
            }
        }
    }

    func joined() -> String {
        queue.sync { lines.joined(separator: "\n") }
    }
}
