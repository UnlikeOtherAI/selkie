import Foundation

#if DEBUG
import AppReveal
#endif

@MainActor
enum AppRevealBootstrap {
    static func activateIfNeeded() {
        #if DEBUG
        guard !isRunningTests else {
            return
        }

        AppReveal.start()
        AppReveal.registerStateProvider(SelkieAppRevealBridge.shared)
        AppReveal.registerNavigationProvider(SelkieAppRevealBridge.shared)
        #endif
    }

    static func attachIfNeeded(appState: AppStateMachine) {
        #if DEBUG
        guard !isRunningTests else {
            return
        }

        SelkieAppRevealBridge.shared.sync(appState: appState)
        #endif
    }

    private static var isRunningTests: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }
}
