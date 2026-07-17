import CryptoKit
import Foundation
import Security

enum CertificatePinningError: LocalizedError {
    case missingPins(host: String)
    case trustEvaluationFailed(host: String)
    case pinMismatch(host: String)

    var errorDescription: String? {
        switch self {
        case let .missingPins(host):
            return "No certificate pins are configured for \(host)."
        case let .trustEvaluationFailed(host):
            return "TLS trust evaluation failed for \(host)."
        case let .pinMismatch(host):
            return "Certificate pin validation failed for \(host)."
        }
    }
}

final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    private let pinnedHosts: [String: Set<String>]

    init(pinnedHosts: [String: Set<String>]) {
        self.pinnedHosts = pinnedHosts
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host
        guard let configuredPins = pinnedHosts[host] else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard !configuredPins.isEmpty, !configuredPins.contains(where: { $0.hasPrefix("REPLACE_WITH_") }) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let policy = SecPolicyCreateSSL(true, host as CFString)
        SecTrustSetPolicies(serverTrust, policy)

        var trustError: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &trustError) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let presentedPins = serverTrust.certificateSHA256Pins()
        guard !presentedPins.isDisjoint(with: configuredPins) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

private extension SecTrust {
    func certificateSHA256Pins() -> Set<String> {
        let certificates = (SecTrustCopyCertificateChain(self) as? [SecCertificate]) ?? []
        return Set(certificates.map { certificate in
            let certificateData = SecCertificateCopyData(certificate) as Data
            let digest = SHA256.hash(data: certificateData)
            return Data(digest).base64EncodedString()
        })
    }
}
