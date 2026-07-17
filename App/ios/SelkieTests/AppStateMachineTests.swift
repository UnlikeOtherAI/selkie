import XCTest
import NetworkExtension
@testable import Selkie

@MainActor
final class AppStateMachineTests: XCTestCase {
    func testBootstrapWithoutTokenLeavesLaunchPassive() async {
        let tunnelManager = TunnelManagerMock(status: .connected)
        let sessionStore = SessionStoreMock(
            snapshot: SessionSnapshot(token: nil, deviceID: nil, privateKey: nil)
        )
        let mobileAPI = MobileAPIMock(
            enrollResponse: MobileEnrollResponse(
                deviceID: UUID(),
                overlayIP: nil,
                wgConfig: sampleConfig
            ),
            servers: []
        )
        let machine = AppStateMachine(
            sessionStore: sessionStore,
            authAPI: AuthAPIMock(
                response: MobileHandoffExchangeResponse(token: "unused", expiresIn: 3600)
            ),
            mobileAPI: mobileAPI,
            authSession: AuthSessionMock(handoffCode: "unused"),
            tunnelManager: tunnelManager,
            serverService: ServerServiceMock(servers: [])
        )

        await machine.bootstrap()

        XCTAssertEqual(machine.phase, .loggedOut)
        XCTAssertEqual(tunnelManager.currentStatusCallCount, 0)
        XCTAssertEqual(tunnelManager.stopCallCount, 0)
        XCTAssertEqual(mobileAPI.enrollCallCount, 0)
    }

    func testBootstrapWithStoredSessionStaysLoggedOutUntilUserActs() async {
        let deviceID = UUID()
        let tunnelManager = TunnelManagerMock(status: .connected)
        let mobileAPI = MobileAPIMock(
            enrollResponse: MobileEnrollResponse(
                deviceID: deviceID,
                overlayIP: nil,
                wgConfig: sampleConfig
            ),
            servers: []
        )
        let machine = AppStateMachine(
            sessionStore: SessionStoreMock(
                snapshot: SessionSnapshot(
                    token: "token-1",
                    deviceID: deviceID,
                    privateKey: "private-key"
                )
            ),
            authAPI: AuthAPIMock(
                response: MobileHandoffExchangeResponse(token: "unused", expiresIn: 3600)
            ),
            mobileAPI: mobileAPI,
            authSession: AuthSessionMock(handoffCode: "unused"),
            tunnelManager: tunnelManager,
            serverService: ServerServiceMock(servers: [])
        )

        await machine.bootstrap()

        XCTAssertEqual(machine.phase, .loggedOut)
        XCTAssertEqual(tunnelManager.currentStatusCallCount, 0)
        XCTAssertEqual(tunnelManager.stopCallCount, 0)
        XCTAssertEqual(mobileAPI.enrollCallCount, 0)
    }

    func testLogInEnrollsStartsTunnelAndLoadsServers() async throws {
        let deviceID = UUID()
        let server = MobileServer(
            deviceID: UUID(),
            hostname: "home-mac-mini",
            status: "active",
            overlayIP: "10.100.0.20",
            osPlatform: "darwin",
            osArch: "arm64"
        )
        let sessionStore = SessionStoreMock(
            snapshot: SessionSnapshot(token: nil, deviceID: nil, privateKey: nil)
        )
        let authAPI = AuthAPIMock(
            response: MobileHandoffExchangeResponse(token: "token-1", expiresIn: 3600)
        )
        let mobileAPI = MobileAPIMock(
            enrollResponse: MobileEnrollResponse(
                deviceID: deviceID,
                overlayIP: "10.100.0.7",
                wgConfig: sampleConfig
            ),
            servers: [server]
        )
        let authSession = AuthSessionMock(handoffCode: "handoff-1")
        let tunnelManager = TunnelManagerMock(status: .disconnected)
        let serverService = ServerServiceMock(servers: [server])
        let machine = AppStateMachine(
            sessionStore: sessionStore,
            authAPI: authAPI,
            mobileAPI: mobileAPI,
            authSession: authSession,
            tunnelManager: tunnelManager,
            serverService: serverService
        )

        await machine.logIn()

        XCTAssertEqual(machine.phase, .connected)
        XCTAssertEqual(sessionStore.persistedToken, "token-1")
        XCTAssertEqual(sessionStore.persistedDeviceID, deviceID)
        XCTAssertEqual(mobileAPI.enrollCallCount, 1)
        // The started config is the server config with the on-device private key injected,
        // so the placeholder PrivateKey is replaced while the rest is preserved verbatim.
        let startedConfig = try XCTUnwrap(tunnelManager.startedConfig)
        XCTAssertTrue(startedConfig.contains("Address = 10.100.0.7/32"))
        XCTAssertTrue(startedConfig.contains("Endpoint = relay.selkie.live:51820"))
        XCTAssertFalse(startedConfig.contains("PrivateKey = private"))
        XCTAssertTrue(startedConfig.contains("PrivateKey = "))
        XCTAssertEqual(tunnelManager.startedOnDemand, false)
        XCTAssertEqual(machine.servers, [server])
        XCTAssertEqual(serverService.fetchCallCount, 1)
    }

    func testDisconnectClearsSessionAndStopsTunnel() async {
        let deviceID = UUID()
        let sessionStore = SessionStoreMock(
            snapshot: SessionSnapshot(token: "token-1", deviceID: deviceID, privateKey: nil)
        )
        let tunnelManager = TunnelManagerMock(status: .connected)
        let mobileAPI = MobileAPIMock(
            enrollResponse: MobileEnrollResponse(
                deviceID: deviceID,
                overlayIP: nil,
                wgConfig: sampleConfig
            ),
            servers: []
        )
        let machine = AppStateMachine(
            sessionStore: sessionStore,
            authAPI: AuthAPIMock(
                response: MobileHandoffExchangeResponse(token: "unused", expiresIn: 3600)
            ),
            mobileAPI: mobileAPI,
            authSession: AuthSessionMock(handoffCode: "unused"),
            tunnelManager: tunnelManager,
            serverService: ServerServiceMock(servers: [])
        )

        await machine.bootstrap()
        await machine.disconnect()

        XCTAssertEqual(machine.phase, .loggedOut)
        XCTAssertTrue(sessionStore.didClearSession)
        XCTAssertEqual(tunnelManager.stopCallCount, 1)
        XCTAssertEqual(mobileAPI.disconnectCallCount, 1)
    }

    private let sampleConfig = """
    [Interface]
    PrivateKey = private
    Address = 10.100.0.7/32
    DNS = 10.100.0.1

    [Peer]
    PublicKey = peer
    AllowedIPs = 10.100.0.1/32
    Endpoint = relay.selkie.live:51820
    """
}

private final class SessionStoreMock: SessionStoring {
    var snapshot: SessionSnapshot
    var persistedToken: String?
    var persistedDeviceID: UUID?
    var persistedPrivateKey: String?
    var didClearSession = false

    init(snapshot: SessionSnapshot) {
        self.snapshot = snapshot
    }

    func load() throws -> SessionSnapshot {
        snapshot
    }

    func persistSession(token: String, deviceID: UUID, privateKey: String) throws {
        persistedToken = token
        persistedDeviceID = deviceID
        persistedPrivateKey = privateKey
    }

    func clearSession() throws {
        didClearSession = true
    }
}

private struct AuthAPIMock: AuthAPIProtocol {
    let response: MobileHandoffExchangeResponse

    func exchangeHandoffCode(_ handoffCode: String) async throws -> MobileHandoffExchangeResponse {
        response
    }
}

private final class MobileAPIMock: MobileAPIProtocol {
    let enrollResponse: MobileEnrollResponse
    let servers: [MobileServer]
    var enrollCallCount = 0
    var disconnectCallCount = 0

    init(enrollResponse: MobileEnrollResponse, servers: [MobileServer]) {
        self.enrollResponse = enrollResponse
        self.servers = servers
    }

    func enroll(token: String, publicKey: String) async throws -> MobileEnrollResponse {
        enrollCallCount += 1
        return enrollResponse
    }

    func listServers(token: String) async throws -> [MobileServer] {
        servers
    }

    func heartbeat(token: String, deviceID: UUID) async throws {}

    func disconnect(token: String) async throws {
        disconnectCallCount += 1
    }
}

private struct AuthSessionMock: AuthSessioning {
    let handoffCode: String

    func authorize() async throws -> String {
        handoffCode
    }
}

@MainActor
private final class TunnelManagerMock: TunnelManaging {
    var status: NEVPNStatus
    var startedConfig: String?
    var startedOnDemand: Bool?
    var stopCallCount = 0
    var currentStatusCallCount = 0

    init(status: NEVPNStatus) {
        self.status = status
    }

    func currentStatus() async throws -> NEVPNStatus {
        currentStatusCallCount += 1
        return status
    }

    func start(wgConfig: String, onDemand: Bool) async throws {
        startedConfig = wgConfig
        startedOnDemand = onDemand
        status = .connected
    }

    func stop() async throws {
        stopCallCount += 1
        status = .disconnected
    }
}

private final class ServerServiceMock: ServerServicing {
    let servers: [MobileServer]
    var fetchCallCount = 0

    init(servers: [MobileServer]) {
        self.servers = servers
    }

    func fetchServers(token: String) async throws -> [MobileServer] {
        fetchCallCount += 1
        return servers
    }
}
