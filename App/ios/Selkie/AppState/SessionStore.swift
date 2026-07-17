import Foundation

struct SessionSnapshot {
    let token: String?
    let deviceID: UUID?
    let privateKey: String?
}

final class SessionStore: SessionStoring {
    private let tokenStore: TokenStore

    init(tokenStore: TokenStore) {
        self.tokenStore = tokenStore
    }

    func load() throws -> SessionSnapshot {
        SessionSnapshot(
            token: try tokenStore.loadSessionToken(),
            deviceID: try tokenStore.loadDeviceID(),
            privateKey: try tokenStore.loadPrivateKey()
        )
    }

    func persistSession(token: String, deviceID: UUID, privateKey: String) throws {
        try tokenStore.saveSessionToken(token)
        try tokenStore.saveDeviceID(deviceID)
        try tokenStore.savePrivateKey(privateKey)
    }

    func clearSession() throws {
        try tokenStore.clearSessionArtifacts()
    }
}
