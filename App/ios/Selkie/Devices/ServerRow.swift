import SwiftUI

struct ServerRow: View {
    let server: MobileServer
    let onCopyOverlayIP: () -> Void

    var body: some View {
        Button(action: onCopyOverlayIP) {
            HStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(server.hostname)
                        .font(.headline)
                        .foregroundStyle(AppTheme.headline)
                        .accessibilityIdentifier("devices.server.hostname")

                    Text(serverSubtitle)
                        .font(.footnote)
                        .foregroundStyle(AppTheme.body)
                        .accessibilityIdentifier("devices.server.subtitle")
                }

                Spacer(minLength: 16)

                VStack(alignment: .trailing, spacing: 6) {
                    Text(server.status.capitalized)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(server.status == "active" ? AppTheme.accentSoft : AppTheme.muted)
                        .accessibilityIdentifier("devices.server.status")

                    if let overlayIP = server.overlayIP {
                        Text(overlayIP)
                            .font(.caption.monospaced())
                            .foregroundStyle(AppTheme.muted)
                            .accessibilityIdentifier("devices.server.overlay_ip")
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(AppTheme.panel)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(AppTheme.panelBorder, lineWidth: 1)
            }
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("devices.server.\(server.deviceID.uuidString)")
    }

    private var serverSubtitle: String {
        "\(server.osPlatform) • \(server.osArch)"
    }
}
