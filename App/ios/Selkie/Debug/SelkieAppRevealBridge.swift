import Foundation

#if DEBUG
import AppReveal

final class SelkieAppRevealBridge: StateProviding, NavigationProviding {
    static let shared = SelkieAppRevealBridge()

    private let lock = NSLock()
    private var cachedSnapshot: [String: AnyCodable] = [
        "attached": AnyCodable(false),
        "phase": AnyCodable("unattached")
    ]
    private var cachedRoute = "auth.login"

    private init() {}

    @MainActor
    func sync(appState: AppStateMachine) {
        let route = route(for: appState.phase)
        let snapshot: [String: AnyCodable] = [
            "attached": AnyCodable(true),
            "phase": AnyCodable(appState.phase.rawValue),
            "serverCount": AnyCodable(appState.servers.count),
            "serverHostnames": AnyCodable(appState.servers.map(\.hostname)),
            "hasError": AnyCodable(appState.errorMessage != nil),
            "errorMessage": AnyCodable(appState.errorMessage ?? "")
        ]

        lock.lock()
        cachedRoute = route
        cachedSnapshot = snapshot
        lock.unlock()
    }

    func snapshot() -> [String: AnyCodable] {
        lock.lock()
        let snapshot = cachedSnapshot
        lock.unlock()
        return snapshot
    }

    var currentRoute: String {
        lock.lock()
        let route = cachedRoute
        lock.unlock()
        return route
    }

    var navigationStack: [String] {
        [currentRoute]
    }

    var presentedModals: [String] {
        []
    }

    private func route(for phase: AppStateMachine.Phase) -> String {
        switch phase {
        case .connected, .disconnecting:
            return "devices.list"
        case .authenticating, .exchangingHandoff, .enrollingDevice, .startingVPN,
             .loggedOut, .error:
            return "auth.login"
        }
    }
}
#endif
