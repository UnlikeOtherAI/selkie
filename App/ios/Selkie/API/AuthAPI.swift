import Foundation

final class AuthAPI: AuthAPIProtocol {
    private let client: APIClient

    init(client: APIClient) {
        self.client = client
    }

    func exchangeHandoffCode(_ handoffCode: String) async throws -> MobileHandoffExchangeResponse {
        try await client.post(
            "/api/v1/mobile/handoff/exchange",
            body: MobileHandoffExchangeRequest(handoffCode: handoffCode),
            responseType: MobileHandoffExchangeResponse.self
        )
    }
}
