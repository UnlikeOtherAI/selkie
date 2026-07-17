import Foundation

enum APIClientError: LocalizedError {
    case invalidResponse
    case server(statusCode: Int, message: String)
    case missingCallbackCode
    case invalidTunnelConfig

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "The server returned an invalid response."
        case let .server(statusCode, message):
            return "Server error (\(statusCode)): \(message)"
        case .missingCallbackCode:
            return "The mobile callback did not include a handoff code."
        case .invalidTunnelConfig:
            return "The server returned an invalid WireGuard configuration."
        }
    }
}

final class APIClient {
    private let baseURL: URL
    private let session: URLSession
    private let delegate: PinnedSessionDelegate?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(baseURL: URL = AppConfig.apiBaseURL, session: URLSession? = nil) {
        self.baseURL = baseURL
        if let session {
            self.session = session
            delegate = nil
        } else {
            let delegate = PinnedSessionDelegate(
                pinnedHosts: AppConfig.pinnedCertificateHashesByHost
            )
            let configuration = URLSessionConfiguration.ephemeral
            configuration.waitsForConnectivity = true
            self.session = URLSession(
                configuration: configuration,
                delegate: delegate,
                delegateQueue: nil
            )
            self.delegate = delegate
        }
    }

    func post<Request: Encodable, Response: Decodable>(
        _ path: String,
        token: String? = nil,
        body: Request,
        responseType: Response.Type
    ) async throws -> Response {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        return try decode(Response.self, from: data, response: response)
    }

    func postNoBody(_ path: String, token: String? = nil) async throws {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "POST"
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        try validate(
            data: data,
            response: response,
            expectedStatusCodes: [200, 202, 204]
        )
    }

    func get<Response: Decodable>(
        _ path: String,
        token: String? = nil,
        responseType: Response.Type
    ) async throws -> Response {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "GET"
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        return try decode(Response.self, from: data, response: response)
    }

    private func decode<Response: Decodable>(
        _ type: Response.Type,
        from data: Data,
        response: URLResponse
    ) throws -> Response {
        try validate(data: data, response: response, expectedStatusCodes: [200, 204])

        if data.isEmpty, let emptyResponse = makeEmptyResponse(Response.self) {
            return emptyResponse
        }

        do {
            return try decoder.decode(Response.self, from: data)
        } catch {
            throw APIClientError.invalidResponse
        }
    }

    private func makeEmptyResponse<Response: Decodable>(
        _ type: Response.Type
    ) -> Response? {
        guard let emptyType = type as? EmptyPayloadResponse.Type,
              let response = emptyType.init() as? Response
        else {
            return nil
        }
        return response
    }

    private func validate(
        data: Data,
        response: URLResponse,
        expectedStatusCodes: Set<Int>
    ) throws {
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard expectedStatusCodes.contains(http.statusCode) else {
            let message =
                (try? decoder.decode(APIErrorPayload.self, from: data).error) ??
                HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(statusCode: http.statusCode, message: message)
        }
    }
}
