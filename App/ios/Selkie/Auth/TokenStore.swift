import Foundation
import Security

enum TokenStoreError: LocalizedError {
    case unexpectedStatus(OSStatus)
    case corruptData

    var errorDescription: String? {
        switch self {
        case let .unexpectedStatus(status):
            return "Keychain operation failed with status \(status)."
        case .corruptData:
            return "Stored data is corrupt."
        }
    }
}

final class TokenStore {
    private let service = "com.unlikeotherai.selkie.ios"

    func saveSessionToken(_ token: String) throws {
        try save(token, for: "session_token")
    }

    func loadSessionToken() throws -> String? {
        try loadString(for: "session_token")
    }

    func clearSessionToken() throws {
        try deleteValue(for: "session_token")
    }

    func saveDeviceID(_ deviceID: UUID) throws {
        try save(deviceID.uuidString, for: "device_id")
    }

    func loadDeviceID() throws -> UUID? {
        guard let value = try loadString(for: "device_id") else {
            return nil
        }
        return UUID(uuidString: value)
    }

    func clearDeviceID() throws {
        try deleteValue(for: "device_id")
    }

    func savePrivateKey(_ privateKey: String) throws {
        try save(privateKey, for: "wg_private_key")
    }

    func loadPrivateKey() throws -> String? {
        try loadString(for: "wg_private_key")
    }

    func clearPrivateKey() throws {
        try deleteValue(for: "wg_private_key")
    }

    func clearSessionArtifacts() throws {
        try clearSessionToken()
        try clearDeviceID()
        try clearPrivateKey()
    }

    private func save(_ value: String, for account: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess {
            return
        }
        if status != errSecItemNotFound {
            throw TokenStoreError.unexpectedStatus(status)
        }

        var createQuery = query
        createQuery.merge(attributes) { _, new in new }
        let addStatus = SecItemAdd(createQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw TokenStoreError.unexpectedStatus(addStatus)
        }
    }

    private func loadString(for account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw TokenStoreError.unexpectedStatus(status)
        }
        guard let data = result as? Data,
              let string = String(data: data, encoding: .utf8)
        else {
            throw TokenStoreError.corruptData
        }
        return string
    }

    private func deleteValue(for account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TokenStoreError.unexpectedStatus(status)
        }
    }
}
