// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SelkieTunnelRuntime",
    platforms: [.iOS(.v16), .tvOS(.v17), .macOS(.v12)],
    products: [.library(name: "SelkieTunnelRuntime", targets: ["SelkieTunnelRuntime"])],
    dependencies: [],
    targets: [
        .target(name: "WireGuardKitC", path: "App/ios/Vendor/WireGuardKit/Sources/WireGuardKitC",
                publicHeadersPath: "."),
        .target(name: "WireGuardKitGo", path: "App/ios/Vendor/WireGuardKit/Sources/WireGuardKitGo",
                exclude: ["goruntime-boottime-over-monotonic.diff", "go.mod", "go.sum", "api-apple.go", "Makefile"],
                publicHeadersPath: ".", linkerSettings: [.linkedLibrary("wg-go")]),
        .target(name: "WireGuardKit", dependencies: ["WireGuardKitGo", "WireGuardKitC"],
                path: "App/ios/Vendor/WireGuardKit/Sources/WireGuardKit"),
        .target(
            name: "SelkieTunnelRuntime",
            dependencies: ["WireGuardKit"],
            path: "App/ios",
            exclude: ["Vendor", "Selkie", "SelkieTests", "Selkie.xcodeproj", "scripts",
                      "project.yml", "SelkieTunnelExtension/Info.plist", "SelkieTunnelExtension/TVInfo.plist",
                      "SelkieTunnelExtension/SelkieTunnelExtension.entitlements"],
            sources: ["Shared", "SelkieTunnelExtension/PacketTunnelProvider.swift",
                      "SelkieTunnelExtension/WireGuardTunnelConfiguration.swift"]
        )
    ]
)
