import SwiftUI
import UIKit

struct ServerListView: View {
    @ObservedObject var appState: AppStateMachine

    @State private var copiedMessage: String?
    @State private var clearCopiedTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(
                    colors: [AppTheme.backgroundTop, AppTheme.backgroundBottom],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()

                VStack(spacing: 18) {
                    header

                    if appState.servers.isEmpty {
                        ContentUnavailableView(
                            "No Servers",
                            systemImage: "server.rack",
                            description: Text(
                                "The tunnel is up, but no active server-capable devices are visible yet."
                            )
                        )
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .accessibilityIdentifier("devices.empty")
                    } else {
                        List(appState.servers) { server in
                            ServerRow(server: server) {
                                copyOverlayIP(for: server)
                            }
                            .listRowInsets(EdgeInsets(top: 8, leading: 20, bottom: 8, trailing: 20))
                            .listRowSeparator(.hidden)
                            .listRowBackground(Color.clear)
                        }
                        .listStyle(.plain)
                        .scrollContentBackground(.hidden)
                        .background(Color.clear)
                        .accessibilityIdentifier("devices.list")
                    }

                    Button(role: .destructive) {
                        Task {
                            await appState.disconnect()
                        }
                    } label: {
                        Text(appState.phase == .disconnecting ? "Disconnecting" : "Disconnect")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 18)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(AppTheme.accent)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 20)
                    .disabled(appState.phase == .disconnecting)
                    .accessibilityIdentifier("devices.disconnect")
                }
            }
            .navigationTitle("Devices")
            .navigationBarTitleDisplayMode(.large)
            .accessibilityIdentifier("devices.root")
            .overlay(alignment: .top) {
                if let copiedMessage {
                    Text(copiedMessage)
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(AppTheme.headline)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(.ultraThinMaterial)
                        .clipShape(Capsule())
                        .padding(.top, 12)
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .accessibilityIdentifier("devices.copy_toast")
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task {
                            await appState.refreshServers()
                        }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .tint(AppTheme.accent)
                    .disabled(appState.phase != .connected)
                    .accessibilityIdentifier("devices.refresh")
                }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("VPN active")
                .font(.headline)
                .foregroundStyle(AppTheme.headline)
                .accessibilityIdentifier("devices.header.title")

            Text("Tap a server row to copy its overlay IP.")
                .font(.footnote)
                .foregroundStyle(AppTheme.body)
                .accessibilityIdentifier("devices.header.subtitle")

            if let errorMessage = appState.errorMessage, !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityIdentifier("devices.header.error")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(20)
        .background(AppTheme.panel)
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(AppTheme.panelBorder, lineWidth: 1)
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
        .accessibilityIdentifier("devices.header")
    }

    private func copyOverlayIP(for server: MobileServer) {
        guard let overlayIP = server.overlayIP, !overlayIP.isEmpty else {
            return
        }

        UIPasteboard.general.string = overlayIP
        clearCopiedTask?.cancel()
        withAnimation {
            copiedMessage = "Copied \(overlayIP)"
        }

        clearCopiedTask = Task {
            try? await Task.sleep(for: .seconds(1.5))
            guard !Task.isCancelled else {
                return
            }
            await MainActor.run {
                withAnimation {
                    copiedMessage = nil
                }
            }
        }
    }
}
