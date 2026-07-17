import SwiftUI

struct LoginView: View {
    let phase: AppStateMachine.Phase
    let errorMessage: String?
    let onLogin: () -> Void

    var body: some View {
        GeometryReader { proxy in
            ScrollView(showsIndicators: false) {
                VStack(spacing: 28) {
                    topBar
                    hero
                    statusCard
                }
                .frame(maxWidth: contentWidth(for: proxy.size.width))
                .padding(.horizontal, horizontalPadding(for: proxy.size.width))
                .padding(.top, topPadding(for: proxy.size.height))
                .padding(.bottom, bottomPadding(for: proxy.size.height))
                .frame(maxWidth: .infinity)
            }
            .background(backgroundGradient.ignoresSafeArea())
            .accessibilityIdentifier("auth.login.root")
        }
    }

    private var topBar: some View {
        HStack {
            Spacer(minLength: 0)

            Image("BrandMark")
                .resizable()
                .interpolation(.high)
                .antialiased(true)
                .scaledToFit()
                .frame(width: 120, height: 120)
                .background(AppTheme.panel)
                .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 28, style: .continuous)
                        .stroke(AppTheme.panelBorder, lineWidth: 1)
                }
                .shadow(color: AppTheme.cardShadow, radius: 18, y: 10)
                .accessibilityIdentifier("auth.login.brand_mark")
        }
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Selkie")
                .font(.system(size: 44, weight: .bold, design: .rounded))
                .foregroundStyle(AppTheme.headline)
                .accessibilityIdentifier("auth.login.title")

            Text("Private access, without starting the tunnel early.")
                .font(.system(size: 30, weight: .semibold, design: .rounded))
                .foregroundStyle(AppTheme.headline)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("auth.login.subtitle")

            Text(
                "Authenticate with UnlikeOtherAI, let Selkie enroll this device, and only then bring up the VPN."
            )
            .font(.title3)
            .foregroundStyle(AppTheme.body)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("auth.login.description")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Authenticate with UnlikeOtherAI")
                .font(.headline)
                .foregroundStyle(AppTheme.headline)
                .accessibilityIdentifier("auth.login.card_title")

            Text(statusMessage)
                .font(.body)
                .foregroundStyle(AppTheme.body)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("auth.login.status_message")

            if let errorMessage, !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityIdentifier("auth.login.error")
            }

            Button(action: onLogin) {
                HStack(spacing: 12) {
                    if isWorkingPhase {
                        ProgressView()
                            .tint(.white)
                    }

                    Text(buttonTitle)
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
                .padding(.horizontal, 20)
                .background(AppTheme.accent)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            }
            .disabled(phase != .loggedOut && phase != .error)
            .accessibilityIdentifier("auth.login.submit")

            Text(
                "Selkie keeps its own pinned API surface. The browser-based UOA login stays " +
                "inside the system authentication session."
            )
            .font(.footnote)
            .foregroundStyle(AppTheme.muted)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("auth.login.note")
        }
        .padding(cardPadding)
        .background(AppTheme.panel)
        .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .stroke(AppTheme.panelBorder, lineWidth: 1)
        }
        .shadow(color: AppTheme.cardShadow, radius: 24, y: 16)
        .accessibilityIdentifier("auth.login.card")
    }

    private var backgroundGradient: LinearGradient {
        LinearGradient(
            colors: [AppTheme.backgroundTop, AppTheme.backgroundBottom],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    private var cardPadding: CGFloat {
        isWorkingPhase ? 28 : 30
    }

    private var statusMessage: String {
        switch phase {
        case .authenticating:
            return "Opening the secure login flow and waiting for the handoff back into Selkie."
        case .exchangingHandoff:
            return (
                "Verifying the handoff and turning it into a Selkie session " +
                "for this device."
            )
        case .enrollingDevice:
            return (
                "Binding this device to your authenticated session and " +
                "fetching the tunnel configuration."
            )
        case .startingVPN:
            return (
                "The tunnel is being brought up now that authentication " +
                "and enrollment are complete."
            )
        case .error:
            return "The last login attempt failed. Review the error below and try again."
        default:
            return (
                "If the VPN is down, this screen is still reachable. " +
                "The tunnel will not start until Selkie finishes the " +
                "authenticated enrollment flow."
            )
        }
    }

    private var isWorkingPhase: Bool {
        switch phase {
        case .authenticating, .exchangingHandoff, .enrollingDevice, .startingVPN:
            true
        default:
            false
        }
    }

    private var buttonTitle: String {
        switch phase {
        case .authenticating:
            return "Opening Login"
        case .exchangingHandoff:
            return "Finalizing Login"
        case .enrollingDevice:
            return "Enrolling Device"
        case .startingVPN:
            return "Starting VPN"
        default:
            return "Log In"
        }
    }

    private func contentWidth(for width: CGFloat) -> CGFloat {
        min(width - 32, 640)
    }

    private func horizontalPadding(for width: CGFloat) -> CGFloat {
        width >= 768 ? 40 : 20
    }

    private func topPadding(for height: CGFloat) -> CGFloat {
        height >= 900 ? 60 : 28
    }

    private func bottomPadding(for height: CGFloat) -> CGFloat {
        height >= 900 ? 72 : 28
    }
}
