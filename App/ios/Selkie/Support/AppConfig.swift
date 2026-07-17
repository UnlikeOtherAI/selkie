import Foundation

enum AppConfig {
    static let apiBaseURL = URL(string: "https://api.selkie.live")!
    static let uoaBaseURL = URL(string: "https://authentication.unlikeotherai.com")!
    static let callbackScheme = "selkie"
    static let callbackHost = "auth"
    static let tunnelExtensionBundleIdentifier = "com.unlikeotherai.selkie.ios.tunnel"
    static let appVersion = "0.1.0"
    static let relayHost = "relay.selkie.live"

    // Certificate SHA-256 pins for the live api.selkie.live chain. Update these on certificate rotation.
    // The mobile client should hard-fail if the API host is not pinned.
    static let pinnedCertificateHashesByHost: [String: Set<String>] = [
        "api.selkie.live": [
            "f4T3Ly2g+lcriVQ76pduHrCDIeCfKimDyNL0dfy3bh0=",
            "g2JP0zjI2bAjwYpny3qcBRnaQ9EXdbTGy9rUXD2ZfFI="
        ]
    ]

    static var currentArchitecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }

    static func authorizeURL(state: String) -> URL {
        var components = URLComponents(
            url: uoaBaseURL.appending(path: "/auth"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "config_url", value: uoaConfigURL.absoluteString),
            URLQueryItem(name: "redirect_url", value: mobileBridgeCallbackURL.absoluteString),
            URLQueryItem(name: "state", value: state)
        ]
        return components.url!
    }

    static var uoaConfigURL: URL {
        apiBaseURL.appending(path: "/auth/uoa-config")
    }

    static var mobileBridgeCallbackURL: URL {
        apiBaseURL.appending(path: "/auth/mobile/callback")
    }

    static func handoffCode(from callbackURL: URL) -> String? {
        value(named: "handoff_code", from: callbackURL)
    }

    static func state(from callbackURL: URL) -> String? {
        value(named: "state", from: callbackURL)
    }

    private static func value(named name: String, from url: URL) -> String? {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == name })?
            .value
    }
}
