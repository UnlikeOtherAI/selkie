import CryptoKit
import Foundation

enum WireGuardKeyError: LocalizedError {
    case invalidStoredKey

    var errorDescription: String? {
        switch self {
        case .invalidStoredKey:
            return "The stored WireGuard private key is invalid."
        }
    }
}

struct WireGuardKeyPair {
    let privateKeyBase64: String
    let publicKeyBase64: String

    static func loadOrCreate(existingPrivateKeyBase64: String?) throws -> WireGuardKeyPair {
        let privateKey: Curve25519.KeyAgreement.PrivateKey

        if let existingPrivateKeyBase64,
           let rawPrivateKey = Data(base64Encoded: existingPrivateKeyBase64) {
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
        } else if existingPrivateKeyBase64 != nil {
            throw WireGuardKeyError.invalidStoredKey
        } else {
            privateKey = Curve25519.KeyAgreement.PrivateKey()
        }

        return WireGuardKeyPair(
            privateKeyBase64: privateKey.rawRepresentation.base64EncodedString(),
            publicKeyBase64: privateKey.publicKey.rawRepresentation.base64EncodedString()
        )
    }
}
