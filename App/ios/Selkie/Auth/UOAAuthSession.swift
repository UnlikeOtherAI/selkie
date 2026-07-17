import AuthenticationServices
import UIKit

final class UOAAuthSession: NSObject, ASWebAuthenticationPresentationContextProviding, AuthSessioning {
    private var session: ASWebAuthenticationSession?

    func authorize() async throws -> String {
        let expectedState = UUID().uuidString

        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: AppConfig.authorizeURL(state: expectedState),
                callbackURLScheme: AppConfig.callbackScheme
            ) { callbackURL, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let callbackURL,
                      callbackURL.host == AppConfig.callbackHost,
                      let handoffCode = AppConfig.handoffCode(from: callbackURL)
                else {
                    continuation.resume(throwing: APIClientError.missingCallbackCode)
                    return
                }

                if let returnedState = AppConfig.state(from: callbackURL), returnedState != expectedState {
                    continuation.resume(throwing: APIClientError.missingCallbackCode)
                    return
                }

                continuation.resume(returning: handoffCode)
            }

            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            self.session = session
            session.start()
        }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }
}
