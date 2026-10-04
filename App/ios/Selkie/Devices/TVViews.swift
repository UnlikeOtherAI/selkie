#if os(tvOS)
import SwiftUI

struct LoginView: View {
    let phase: AppStateMachine.Phase
    let errorMessage: String?
    let onLogin: () -> Void

    private var working: Bool { phase != .loggedOut && phase != .error }

    var body: some View {
        VStack(spacing: 32) {
            Image("BrandMark").resizable().scaledToFit().frame(width: 130, height: 130)
            Text("Selkie").font(.largeTitle.bold())
            Text("Connect your Apple TV to your private network.").font(.title2)
            Text("Sign in with UnlikeOtherAI using the instructions on screen, then allow the VPN connection.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            if let errorMessage {
                Text(errorMessage).foregroundStyle(.red).accessibilityIdentifier("auth.login.error")
            }
            if working { ProgressView("Connecting…") }
            Button(working ? "Connecting…" : "Sign In", action: onLogin)
                .disabled(working).accessibilityIdentifier("auth.login.submit")
        }
        .frame(maxWidth: 1000)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppTheme.backgroundBottom)
        .accessibilityIdentifier("auth.login.root")
    }
}

struct ServerListView: View {
    @ObservedObject var appState: AppStateMachine

    var body: some View {
        VStack(alignment: .leading, spacing: 30) {
            Text("Selkie · Connected").font(.largeTitle.bold())
            Text("Your private network is available. You can now open Rafiki Media.").foregroundStyle(.secondary)
            if let errorMessage = appState.errorMessage { Text(errorMessage).foregroundStyle(.red) }
            if appState.servers.isEmpty {
                Text("No home devices are online yet.").frame(maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 24) {
                        ForEach(appState.servers) { server in
                            HStack {
                                Image(systemName: "server.rack")
                                Text(server.hostname)
                                Spacer()
                                Text(server.overlayIP ?? "Unavailable").foregroundStyle(.secondary)
                            }
                            .padding(24)
                            .background(AppTheme.panel, in: RoundedRectangle(cornerRadius: 16))
                            .focusable()
                        }
                    }.padding(12)
                }.accessibilityIdentifier("devices.list")
            }
            HStack(spacing: 40) {
                Button("Refresh") { Task { await appState.refreshServers() } }
                    .disabled(appState.phase != .connected).accessibilityIdentifier("devices.refresh")
                Button("Disconnect", role: .destructive) { Task { await appState.disconnect() } }
                    .disabled(appState.phase == .disconnecting).accessibilityIdentifier("devices.disconnect")
            }
        }
        .padding(70)
        .background(AppTheme.backgroundBottom)
        .accessibilityIdentifier("devices.root")
    }
}
#endif
