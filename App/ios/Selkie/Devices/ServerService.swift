import Foundation

final class ServerService: ServerServicing {
    private let mobileAPI: MobileAPIProtocol

    init(mobileAPI: MobileAPIProtocol) {
        self.mobileAPI = mobileAPI
    }

    func fetchServers(token: String) async throws -> [MobileServer] {
        try await mobileAPI.listServers(token: token)
            .sorted { $0.hostname.localizedCaseInsensitiveCompare($1.hostname) == .orderedAscending }
    }
}
