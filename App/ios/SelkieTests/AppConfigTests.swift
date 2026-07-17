import XCTest
@testable import Selkie

final class AppConfigTests: XCTestCase {
    func testHandoffCodeAndStateParsing() {
        let callbackURL = URL(string: "selkie://auth?handoff_code=abc123&state=expected-state")!

        XCTAssertEqual(AppConfig.handoffCode(from: callbackURL), "abc123")
        XCTAssertEqual(AppConfig.state(from: callbackURL), "expected-state")
    }

    func testAuthorizeURLTargetsMobileBridgeCallback() {
        let url = AppConfig.authorizeURL(state: "state-1")
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let items = Dictionary(uniqueKeysWithValues: (components?.queryItems ?? []).map { ($0.name, $0.value ?? "") })

        XCTAssertEqual(components?.scheme, "https")
        XCTAssertEqual(components?.host, "authentication.unlikeotherai.com")
        XCTAssertEqual(components?.path, "/auth")
        XCTAssertEqual(items["config_url"], AppConfig.uoaConfigURL.absoluteString)
        XCTAssertEqual(items["redirect_url"], AppConfig.mobileBridgeCallbackURL.absoluteString)
        XCTAssertEqual(items["state"], "state-1")
    }
    func testPinnedCertificatesAreConfiguredForAPIHost() {
        let pins = AppConfig.pinnedCertificateHashesByHost["api.selkie.live"]

        XCTAssertEqual(pins?.count, 2)
        XCTAssertFalse((pins ?? []).contains(where: { $0.hasPrefix("REPLACE_WITH_") }))
        XCTAssertTrue((pins ?? []).contains("f4T3Ly2g+lcriVQ76pduHrCDIeCfKimDyNL0dfy3bh0="))
        XCTAssertTrue((pins ?? []).contains("g2JP0zjI2bAjwYpny3qcBRnaQ9EXdbTGy9rUXD2ZfFI="))
    }

}
