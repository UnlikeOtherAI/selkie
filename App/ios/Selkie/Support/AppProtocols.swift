import Foundation
import NetworkExtension

protocol SessionStoring {
    func load() throws -> SessionSnapshot
    func persistSession(token: String, deviceID: UUID, privateKey: String) throws
    func clearSession() throws
}

protocol AuthAPIProtocol {
    func exchangeHandoffCode(_ handoffCode: String) async throws -> MobileHandoffExchangeResponse
}

protocol MobileAPIProtocol {
    func enroll(token: String, publicKey: String) async throws -> MobileEnrollResponse
    func listServers(token: String) async throws -> [MobileServer]
    func heartbeat(token: String, deviceID: UUID) async throws
    func disconnect(token: String) async throws
}

protocol AuthSessioning {
    func authorize() async throws -> String
}

@MainActor
protocol TunnelManaging {
    func currentStatus() async throws -> NEVPNStatus
    func start(wgConfig: String, onDemand: Bool) async throws
    func stop() async throws
}

protocol ServerServicing {
    func fetchServers(token: String) async throws -> [MobileServer]
}
