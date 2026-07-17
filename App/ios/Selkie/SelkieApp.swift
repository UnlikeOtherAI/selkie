import SwiftUI

@main
struct SelkieApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var appState = AppStateMachine.live()

    init() {
        AppRevealBootstrap.activateIfNeeded()
    }

    var body: some Scene {
        WindowGroup {
            RootView(appState: appState)
                .task {
                    AppRevealBootstrap.attachIfNeeded(appState: appState)
                    await appState.bootstrapIfNeeded()
                }
                .onChange(of: scenePhase) { _, newPhase in
                    Task {
                        switch newPhase {
                        case .active:
                            await appState.appDidBecomeActive()
                        case .background:
                            appState.appDidEnterBackground()
                        default:
                            break
                        }
                    }
                }
        }
    }
}

private struct RootView: View {
    @ObservedObject var appState: AppStateMachine

    var body: some View {
        Group {
            switch appState.phase {
            case .connected, .disconnecting:
                ServerListView(appState: appState)
            default:
                LoginView(
                    phase: appState.phase,
                    errorMessage: appState.errorMessage,
                    onLogin: {
                        Task {
                            await appState.logIn()
                        }
                    }
                )
            }
        }
        .onReceive(appState.objectWillChange) { _ in
            AppRevealBootstrap.attachIfNeeded(appState: appState)
        }
    }
}
