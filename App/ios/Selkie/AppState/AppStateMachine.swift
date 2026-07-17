import Foundation
import NetworkExtension

@MainActor
final class AppStateMachine: ObservableObject {
    enum Phase: String {
        case loggedOut = "logged_out"
        case authenticating = "authenticating"
        case exchangingHandoff = "exchanging_handoff"
        case enrollingDevice = "enrolling_device"
        case startingVPN = "starting_vpn"
        case connected = "connected"
        case disconnecting = "disconnecting"
        case error = "error"
    }

    @Published private(set) var phase: Phase = .loggedOut
    @Published private(set) var servers: [MobileServer] = []
    @Published private(set) var errorMessage: String?

    private let sessionStore: SessionStoring
    private let authAPI: AuthAPIProtocol
    private let mobileAPI: MobileAPIProtocol
    private let authSession: AuthSessioning
    private let tunnelManager: TunnelManaging
    private let serverService: ServerServicing

    private var heartbeatTask: Task<Void, Never>?
    private var cachedToken: String?
    private var cachedDeviceID: UUID?
    private var cachedPrivateKey: String?
    private var hasBootstrapped = false

    static func live() -> AppStateMachine {
        let tokenStore = TokenStore()
        let sessionStore = SessionStore(tokenStore: tokenStore)
        let client = APIClient()
        let authAPI = AuthAPI(client: client)
        let mobileAPI = MobileAPI(client: client)
        return AppStateMachine(
            sessionStore: sessionStore,
            authAPI: authAPI,
            mobileAPI: mobileAPI,
            authSession: UOAAuthSession(),
            tunnelManager: TunnelManager(),
            serverService: ServerService(mobileAPI: mobileAPI)
        )
    }

    init(
        sessionStore: SessionStoring,
        authAPI: AuthAPIProtocol,
        mobileAPI: MobileAPIProtocol,
        authSession: AuthSessioning,
        tunnelManager: TunnelManaging,
        serverService: ServerServicing
    ) {
        self.sessionStore = sessionStore
        self.authAPI = authAPI
        self.mobileAPI = mobileAPI
        self.authSession = authSession
        self.tunnelManager = tunnelManager
        self.serverService = serverService
    }

    func bootstrapIfNeeded() async {
        guard !hasBootstrapped else {
            return
        }
        hasBootstrapped = true
        await bootstrap()
    }

    func bootstrap() async {
        do {
            let snapshot = try sessionStore.load()
            cachedToken = snapshot.token
            cachedDeviceID = snapshot.deviceID
            cachedPrivateKey = snapshot.privateKey
            servers = []
            errorMessage = nil
            phase = .loggedOut
        } catch {
            await handleTerminalError(error, clearSession: true)
        }
    }

    func logIn() async {
        heartbeatTask?.cancel()
        errorMessage = nil
        phase = .authenticating

        do {
            let handoffCode = try await authSession.authorize()
            phase = .exchangingHandoff
            let response = try await authAPI.exchangeHandoffCode(handoffCode)
            try await restoreAuthenticatedSession(token: response.token, existingPrivateKey: cachedPrivateKey)
        } catch {
            await handleTerminalError(error, clearSession: false)
        }
    }

    func refreshServers() async {
        guard let token = cachedToken else {
            return
        }

        do {
            servers = try await serverService.fetchServers(token: token)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func appDidBecomeActive() async {
        guard phase == .connected else {
            return
        }

        startHeartbeatLoop()
        await refreshServers()
    }

    func appDidEnterBackground() {
        heartbeatTask?.cancel()
    }

    func disconnect() async {
        guard phase != .disconnecting else {
            return
        }

        phase = .disconnecting
        heartbeatTask?.cancel()

        if let token = cachedToken {
            try? await mobileAPI.disconnect(token: token)
        }

        await stopTunnelOnly()

        do {
            try sessionStore.clearSession()
        } catch {
            errorMessage = error.localizedDescription
        }

        clearCachedSessionState()
        errorMessage = nil
        phase = .loggedOut
    }

    private func restoreAuthenticatedSession(token: String, existingPrivateKey: String?) async throws {
        phase = .enrollingDevice

        let keyPair = try WireGuardKeyPair.loadOrCreate(existingPrivateKeyBase64: existingPrivateKey)
        let enrollResponse = try await mobileAPI.enroll(token: token, publicKey: keyPair.publicKeyBase64)
        let parsedConfig = try WireGuardConfig(configString: enrollResponse.wgConfig)

        try sessionStore.persistSession(
            token: token,
            deviceID: enrollResponse.deviceID,
            privateKey: keyPair.privateKeyBase64
        )

        cachedToken = token
        cachedDeviceID = enrollResponse.deviceID
        cachedPrivateKey = keyPair.privateKeyBase64

        // The on-device private key never leaves the phone, so the server-returned
        // config carries no usable PrivateKey. Inject the real key right before the
        // config is handed to the tunnel. Selkie uses manual connect, so on-demand is
        // off (the capability exists via TunnelManager.saveTunnel for sibling products).
        let effectiveConfig = parsedConfig.settingPrivateKey(keyPair.privateKeyBase64)

        phase = .startingVPN
        try await tunnelManager.start(wgConfig: effectiveConfig, onDemand: false)

        phase = .connected
        errorMessage = nil
        startHeartbeatLoop()
        servers = try await serverService.fetchServers(token: token)
    }

    private func startHeartbeatLoop() {
        heartbeatTask?.cancel()

        guard let token = cachedToken, let deviceID = cachedDeviceID else {
            return
        }

        heartbeatTask = Task {
            while !Task.isCancelled {
                do {
                    try await mobileAPI.heartbeat(token: token, deviceID: deviceID)
                } catch {
                    await MainActor.run {
                        self.errorMessage = error.localizedDescription
                    }
                }

                try? await Task.sleep(for: .seconds(30))
            }
        }
    }

    private func handleTerminalError(_ error: Error, clearSession: Bool) async {
        heartbeatTask?.cancel()
        errorMessage = error.localizedDescription
        phase = .error

        if clearSession {
            try? sessionStore.clearSession()
            clearCachedSessionState()
        }

        servers = []
        await stopTunnelOnly()
        phase = .loggedOut
    }

    private func clearCachedSessionState() {
        cachedToken = nil
        cachedDeviceID = nil
        cachedPrivateKey = nil
        servers = []
    }

    private func stopTunnelOnly() async {
        do {
            try await tunnelManager.stop()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
