import Foundation
import NetworkExtension

enum TunnelManagerError: LocalizedError {
    case connectionTimeout

    var errorDescription: String? {
        switch self {
        case .connectionTimeout:
            return "The VPN did not reach the expected state in time."
        }
    }
}

@MainActor
final class TunnelManager: TunnelManaging {
    private typealias ManagersContinuation = CheckedContinuation<[NETunnelProviderManager], Error>

    private var manager: NETunnelProviderManager?

    func currentStatus() async throws -> NEVPNStatus {
        let manager = try await loadManager()
        return manager.connection.status
    }

    func start(wgConfig: String, onDemand: Bool = false) async throws {
        let manager = try await saveTunnel(config: wgConfig, onDemand: onDemand)

        try await stopIfNeeded(manager: manager)
        try manager.connection.startVPNTunnel()
        try await wait(for: [.connected], on: manager.connection)
        self.manager = manager
    }

    /// Builds and persists the `NETunnelProviderManager` for the given wg-quick config.
    ///
    /// When `onDemand` is true the tunnel is configured to auto-connect on both Wi-Fi and
    /// cellular via `NEOnDemandRuleConnect`. Selkie keeps `onDemand` false (manual connect
    /// is the product default), but the capability is exposed here so sibling products such
    /// as Coding Homie can enable always-on remote access.
    @discardableResult
    func saveTunnel(config wgConfig: String, onDemand: Bool) async throws -> NETunnelProviderManager {
        let parsedConfig = try WireGuardConfig(configString: wgConfig)
        let manager = try await loadManager()

        let providerProtocol = NETunnelProviderProtocol()
        providerProtocol.providerBundleIdentifier = AppConfig.tunnelExtensionBundleIdentifier
        providerProtocol.serverAddress = parsedConfig.remoteAddress
        providerProtocol.providerConfiguration = ["wgConfig": wgConfig]

        manager.localizedDescription = "Selkie"
        manager.protocolConfiguration = providerProtocol
        manager.isEnabled = true

        if onDemand {
            manager.isOnDemandEnabled = true
            manager.onDemandRules = Self.onDemandRules()
        } else {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
        }

        try await save(manager: manager)
        self.manager = manager
        return manager
    }

    /// Connect-on-demand rules covering both Wi-Fi and cellular interfaces.
    ///
    /// Pure and side-effect free so it can be unit-tested without a tunnel host.
    nonisolated static func onDemandRules() -> [NEOnDemandRule] {
        let wifiRule = NEOnDemandRuleConnect()
        wifiRule.interfaceTypeMatch = .wiFi

        let cellularRule = NEOnDemandRuleConnect()
        cellularRule.interfaceTypeMatch = .cellular

        return [wifiRule, cellularRule]
    }

    func stop() async throws {
        let manager = try await loadManager()
        if manager.connection.status == .disconnected || manager.connection.status == .invalid {
            return
        }
        manager.connection.stopVPNTunnel()
        try await wait(for: [.disconnected, .invalid], on: manager.connection)
    }

    /// Retrieves the extension's buffered backend log lines, making tunnel diagnostics
    /// readable from the app. Returns nil if the tunnel is not currently reachable.
    func fetchTunnelLog() async -> String? {
        await sendProviderMessage(TunnelMessage.getLog)
    }

    /// Retrieves the live WireGuard runtime (uapi) configuration from the extension.
    func fetchRuntimeConfiguration() async -> String? {
        await sendProviderMessage(TunnelMessage.getRuntimeConfiguration)
    }

    private func sendProviderMessage(_ command: String) async -> String? {
        guard let manager = try? await loadManager(),
              let session = manager.connection as? NETunnelProviderSession,
              let payload = command.data(using: .utf8)
        else {
            return nil
        }

        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            do {
                try session.sendProviderMessage(payload) { response in
                    if let response {
                        continuation.resume(returning: String(data: response, encoding: .utf8))
                    } else {
                        continuation.resume(returning: nil)
                    }
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    private func loadManager() async throws -> NETunnelProviderManager {
        if let manager {
            return manager
        }

        let managers = try await loadAllManagers()
        if let existingManager = managers.first(where: matchesTunnelExtension) ?? managers.first {
            try await reload(manager: existingManager)
            manager = existingManager
            return existingManager
        }

        let newManager = NETunnelProviderManager()
        manager = newManager
        return newManager
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { (continuation: ManagersContinuation) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
    }

    private func reload(manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    private func save(manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }

        try await reload(manager: manager)
    }

    private func matchesTunnelExtension(_ manager: NETunnelProviderManager) -> Bool {
        let providerProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        return providerProtocol?.providerBundleIdentifier == AppConfig.tunnelExtensionBundleIdentifier
    }

    private func stopIfNeeded(manager: NETunnelProviderManager) async throws {
        let status = manager.connection.status
        guard status != .disconnected && status != .invalid else {
            return
        }

        manager.connection.stopVPNTunnel()
        try await wait(for: [.disconnected, .invalid], on: manager.connection)
    }

    private func wait(
        for expectedStatuses: Set<NEVPNStatus>,
        on connection: NEVPNConnection
    ) async throws {
        for _ in 0..<40 {
            if expectedStatuses.contains(connection.status) {
                return
            }
            try await Task.sleep(for: .milliseconds(250))
        }

        throw TunnelManagerError.connectionTimeout
    }
}
