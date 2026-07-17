import Foundation
import UIKit

struct DeviceTelemetry {
    let diskFreeBytes: Int64?

    static func current() -> DeviceTelemetry {
        let homeDirectory = URL(fileURLWithPath: NSHomeDirectory())
        let values = try? homeDirectory.resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey]
        )
        let diskFreeBytes = values?.volumeAvailableCapacityForImportantUsage
            .flatMap(Int64.init)
        return DeviceTelemetry(diskFreeBytes: diskFreeBytes)
    }
}

final class MobileAPI: MobileAPIProtocol {
    private let client: APIClient

    init(client: APIClient) {
        self.client = client
    }

    func enroll(token: String, publicKey: String) async throws -> MobileEnrollResponse {
        let hostname = await MainActor.run { UIDevice.current.name }
        let request = MobileEnrollRequest(
            hostname: hostname,
            osPlatform: "ios",
            osArch: AppConfig.currentArchitecture,
            appVersion: AppConfig.appVersion,
            wgPublicKey: publicKey
        )
        return try await client.post(
            "/api/v1/mobile/enroll",
            token: token,
            body: request,
            responseType: MobileEnrollResponse.self
        )
    }

    func listServers(token: String) async throws -> [MobileServer] {
        try await client.get(
            "/api/v1/mobile/servers",
            token: token,
            responseType: [MobileServer].self
        )
    }

    func heartbeat(token: String, deviceID: UUID) async throws {
        let telemetry = DeviceTelemetry.current()
        let request = HeartbeatRequest(
            externalEndpointHost: nil,
            externalEndpointPort: nil,
            agentVersion: AppConfig.appVersion,
            diskFreeBytes: telemetry.diskFreeBytes
        )
        _ = try await client.post(
            "/api/v1/devices/\(deviceID.uuidString)/heartbeat",
            token: token,
            body: request,
            responseType: EmptyResponse.self
        )
    }

    func disconnect(token: String) async throws {
        try await client.postNoBody("/api/v1/mobile/disconnect", token: token)
    }
}
