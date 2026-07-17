import XCTest
import NetworkExtension
@testable import Selkie

final class TunnelManagerTests: XCTestCase {
    func testOnDemandRulesCoverWiFiAndCellular() {
        let rules = TunnelManager.onDemandRules()

        XCTAssertEqual(rules.count, 2)
        XCTAssertTrue(rules.allSatisfy { $0 is NEOnDemandRuleConnect })
        XCTAssertTrue(rules.allSatisfy { $0.action == .connect })

        let interfaceTypes = Set(rules.map { $0.interfaceTypeMatch })
        XCTAssertTrue(interfaceTypes.contains(.wiFi))
        XCTAssertTrue(interfaceTypes.contains(.cellular))
    }
}
