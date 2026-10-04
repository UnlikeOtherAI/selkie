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
open class SelkiePacketTunnelProvider: NEPacketTunnelProvider {
    private var peerSocket: URLSessionWebSocketTask?
    private var peerTask: Task<Void, Never>?
    private var controlSession: URLSession?
    private var directPrivateKey: String?
    private var directPeerURL: URL?
    private var directGeneration = UUID()
    private var currentDirectConfig: String?

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

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        logRing.append("[app] startTunnel requested")

        if let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
           let values = providerProtocol.providerConfiguration,
           let token = values["directToken"] as? String,
           let urlString = values["directPeerURL"] as? String,
           let url = URL(string: urlString), url.scheme == "wss",
           let configString = values["wgConfig"] as? String,
           let parsed = try? WireGuardConfig(configString: configString),
           let privateKey = parsed.privateKey {
            directPrivateKey = privateKey
            directPeerURL = url
            startDirectPeers(url: url, token: token, completion: completionHandler)
            return
        }

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

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        peerTask?.cancel()
        peerSocket?.cancel(with: .goingAway, reason: nil)
        controlSession?.invalidateAndCancel()
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
    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        if let values = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           let token = values["directToken"], let url = directPeerURL {
            startDirectPeers(url: url, token: token, alreadyStarted: true) { error in
                completionHandler?(error == nil ? Data("ok".utf8) : nil)
            }
            return
        }
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

    public override func sleep(completionHandler: @escaping () -> Void) {
        // The backend keeps its own state; nothing to tear down for sleep.
        logRing.append("[app] sleep")
        completionHandler()
    }

    public override func wake() {
        // `WireGuardAdapter` reacts to network path changes internally, so there is
        // nothing extra to do on wake beyond noting it.
        logRing.append("[app] wake")
    }

    private func startDirectPeers(url: URL, token: String, alreadyStarted: Bool = false,
                                  completion: @escaping (Error?) -> Void) {
        let generation = UUID()
        directGeneration = generation
        peerTask?.cancel()
        peerSocket?.cancel(with: .goingAway, reason: nil)
        controlSession?.invalidateAndCancel()
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: SelkieControlSessionDelegate(),
                                 delegateQueue: nil)
        controlSession = session
        let socket = session.webSocketTask(with: request)
        peerSocket = socket
        socket.maximumMessageSize = 1 << 20
        socket.resume()
        peerTask = Task { [weak self] in
            guard let self else { return }
            var started = alreadyStarted
            var replied = false
            do {
                while !Task.isCancelled {
                    let message = try await socket.receive()
                    let data = try Self.messageData(message)
                    let snapshot = try JSONDecoder().decode(DirectSnapshot.self, from: data)
                    let parsed = try WireGuardConfig(configString: snapshot.wgConfig)
                    let effective = try WireGuardConfig(configString:
                        parsed.settingPrivateKey(self.directPrivateKey ?? ""))
                    let config = try TunnelConfiguration(from: effective, name: "Selkie direct home")
                    // A direct snapshot never includes the server hub or a blanket route.
                    guard config.peers.allSatisfy({ peer in
                        !peer.allowedIPs.isEmpty && peer.allowedIPs.allSatisfy { $0.networkPrefixLength == 32 }
                    }) else { throw PacketTunnelProviderError.invalidTunnelConfig }
                    if started {
                        if self.currentDirectConfig != snapshot.wgConfig {
                            try await self.updateAdapter(config)
                        }
                    } else {
                        try await self.startAdapter(config)
                        started = true
                    }
                    self.currentDirectConfig = snapshot.wgConfig
                    if !replied { completion(nil); replied = true }
                }
            } catch {
                guard self.directGeneration == generation else { return }
                socket.cancel(with: .goingAway, reason: nil)
                self.adapter.stop { _ in }
                if !replied { completion(error) } else { self.cancelTunnelWithError(error) }
            }
        }
    }

    private static func messageData(_ message: URLSessionWebSocketTask.Message) throws -> Data {
        switch message {
        case .data(let value): return value
        case .string(let value): return Data(value.utf8)
        @unknown default: throw PacketTunnelProviderError.invalidTunnelConfig
        }
    }

    private func startAdapter(_ config: TunnelConfiguration) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            adapter.start(tunnelConfiguration: config) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    private func updateAdapter(_ config: TunnelConfiguration) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            adapter.update(tunnelConfiguration: config) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
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

// Existing standalone extension name remains a thin adapter to the reusable runtime.
final class PacketTunnelProvider: SelkiePacketTunnelProvider {}

private struct DirectSnapshot: Decodable {
        let wgConfig: String
        enum CodingKeys: String, CodingKey { case wgConfig = "wg_config" }
    }
