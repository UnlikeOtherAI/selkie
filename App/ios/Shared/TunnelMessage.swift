import Foundation

/// UTF-8 command strings exchanged between the container app and the packet-tunnel
/// extension via `NETunnelProviderSession.sendProviderMessage` / `handleAppMessage`.
///
/// Kept product-agnostic and shared so the same extension can serve sibling products.
enum TunnelMessage {
    static let getRuntimeConfiguration = "getruntimeconfiguration"
    static let getLog = "getlog"
}
