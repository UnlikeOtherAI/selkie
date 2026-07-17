import Foundation

protocol EmptyPayloadResponse {
    init()
}

struct MobileHandoffExchangeRequest: Encodable {
    let handoffCode: String

    enum CodingKeys: String, CodingKey {
        case handoffCode = "handoff_code"
    }
}

struct MobileHandoffExchangeResponse: Decodable {
    let token: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case token
        case expiresIn = "expires_in"
    }
}

struct MobileEnrollRequest: Encodable {
    let hostname: String
    let osPlatform: String
    let osArch: String
    let appVersion: String
    let wgPublicKey: String

    enum CodingKeys: String, CodingKey {
        case hostname
        case osPlatform = "os_platform"
        case osArch = "os_arch"
        case appVersion = "app_version"
        case wgPublicKey = "wg_public_key"
    }
}

struct MobileEnrollResponse: Decodable {
    let deviceID: UUID
    let overlayIP: String?
    let wgConfig: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case overlayIP = "overlay_ip"
        case wgConfig = "wg_config"
    }
}

struct HeartbeatRequest: Encodable {
    let externalEndpointHost: String?
    let externalEndpointPort: Int?
    let agentVersion: String
    let diskFreeBytes: Int64?

    enum CodingKeys: String, CodingKey {
        case externalEndpointHost = "external_endpoint_host"
        case externalEndpointPort = "external_endpoint_port"
        case agentVersion = "agent_version"
        case diskFreeBytes = "disk_free_bytes"
    }
}

struct MobileServer: Decodable, Identifiable, Equatable {
    let deviceID: UUID
    let hostname: String
    let status: String
    let overlayIP: String?
    let osPlatform: String
    let osArch: String

    var id: UUID { deviceID }

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case hostname
        case status
        case overlayIP = "overlay_ip"
        case osPlatform = "os_platform"
        case osArch = "os_arch"
    }
}

struct EmptyResponse: Decodable, EmptyPayloadResponse {}

struct APIErrorPayload: Decodable {
    let error: String
}
