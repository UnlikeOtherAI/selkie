import XCTest
@testable import Selkie

final class WireGuardConfigTests: XCTestCase {
    func testWireGuardConfigParsesInterfacePeerAndRoutes() throws {
        let config = try WireGuardConfig(configString: sampleConfig)

        XCTAssertEqual(config.firstIPv4Address?.address, "10.100.0.7")
        XCTAssertEqual(config.firstIPv4Address?.prefixLength, 32)
        XCTAssertEqual(config.dnsServers, ["10.100.0.1", "1.1.1.1"])
        XCTAssertEqual(config.remoteAddress, "relay.selkie.live")
        XCTAssertEqual(config.ipv4AllowedIPs.map(\.address), ["10.100.0.1", "10.100.0.0"])
        XCTAssertEqual(config.mtu, 1280)
    }

    func testWireGuardConfigRequiresInterfaceAddress() {
        XCTAssertThrowsError(try WireGuardConfig(configString: "[Peer]\nAllowedIPs = 10.100.0.1/32"))
    }

    func testWireGuardConfigParsesKeysEndpointAndKeepalive() throws {
        let config = try WireGuardConfig(configString: sampleConfig)

        XCTAssertEqual(config.privateKey, "private")
        XCTAssertEqual(config.peerPublicKey, "peer")
        XCTAssertEqual(config.endpoint, "relay.selkie.live:51820")
        XCTAssertEqual(config.persistentKeepalive, 25)
        XCTAssertNil(config.presharedKey)
        XCTAssertEqual(config.allowedIPs.map(\.stringRepresentation), ["10.100.0.1/32", "10.100.0.0/16"])
    }

    func testWireGuardConfigParsesPresharedKey() throws {
        let config = try WireGuardConfig(configString: """
        [Interface]
        PrivateKey = privkey
        Address = 10.100.0.7/32

        [Peer]
        PublicKey = pubkey
        PresharedKey = psk
        AllowedIPs = 10.100.0.0/16
        Endpoint = relay.selkie.live:51820
        """)

        XCTAssertEqual(config.presharedKey, "psk")
    }

    func testSettingPrivateKeyReplacesExistingInterfaceKey() throws {
        let config = try WireGuardConfig(configString: sampleConfig)
        let injected = config.settingPrivateKey("DEVICE_KEY")

        XCTAssertTrue(injected.contains("PrivateKey = DEVICE_KEY"))
        XCTAssertFalse(injected.contains("PrivateKey = private"))
        // Everything else is preserved.
        XCTAssertTrue(injected.contains("Address = 10.100.0.7/32"))
        XCTAssertTrue(injected.contains("Endpoint = relay.selkie.live:51820"))

        let reparsed = try WireGuardConfig(configString: injected)
        XCTAssertEqual(reparsed.privateKey, "DEVICE_KEY")
    }

    func testSettingPrivateKeyInsertsWhenMissing() throws {
        let config = try WireGuardConfig(configString: """
        [Interface]
        Address = 10.100.0.7/32

        [Peer]
        PublicKey = peer
        AllowedIPs = 10.100.0.0/16
        Endpoint = relay.selkie.live:51820
        """)
        XCTAssertNil(config.privateKey)

        let injected = config.settingPrivateKey("DEVICE_KEY")
        let reparsed = try WireGuardConfig(configString: injected)
        XCTAssertEqual(reparsed.privateKey, "DEVICE_KEY")
        XCTAssertEqual(reparsed.firstIPv4Address?.address, "10.100.0.7")
    }

    private let sampleConfig = """
    [Interface]
    PrivateKey = private
    Address = 10.100.0.7/32
    DNS = 10.100.0.1, 1.1.1.1
    MTU = 1280

    [Peer]
    PublicKey = peer
    AllowedIPs = 10.100.0.1/32, 10.100.0.0/16
    Endpoint = relay.selkie.live:51820
    PersistentKeepalive = 25
    """
}
