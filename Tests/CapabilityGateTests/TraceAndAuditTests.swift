import XCTest
@testable import CapabilityGate

/// Every number quoted in the README and the article is read out of here.
final class TraceAndAuditTests: XCTestCase {

    func testAuditOfTheWorkedSurface() throws {
        let surface = try MailAssistantSurface.surface()
        let report = ReachabilityAudit.audit(surface)

        XCTAssertEqual(report.toolCount, 12)
        XCTAssertEqual(report.ingestPoints, ["readInbox", "readWebPage"])
        XCTAssertEqual(
            report.exfiltrationCapableTools,
            ["sendMail", "shareFile", "postWebhook", "deleteAllArchived"]
        )
        XCTAssertEqual(report.reachableWhenClean.count, 12)
        XCTAssertEqual(report.reachableWhenTainted.count, 8)
        XCTAssertEqual(
            report.stateDependentTools,
            ["sendMail", "shareFile", "postWebhook", "deleteAllArchived"]
        )
        // Two tools decide whether the other four are reachable at all.
        XCTAssertEqual(report.collapseRatio, 4.0 / 12.0, accuracy: 0.0001)
    }

    func testTraceReplayIsDeterministicAndProducesTheQuotedNumbers() throws {
        let gate = CapabilityGate(surface: try MailAssistantSurface.surface())
        let result = MailAssistantTrace.replay(gate: gate)
        let ledger = result.ledger

        XCTAssertEqual(result.outcomes.count, 24)
        XCTAssertEqual(ledger.total, 24)
        XCTAssertEqual(result.taintedAtStep, 9)

        XCTAssertEqual(ledger.count(of: .unreachableFromTaintedScope), 6)
        XCTAssertEqual(ledger.count(of: .notInSurface), 1)
        XCTAssertEqual(ledger.denied, 7)
        XCTAssertEqual(ledger.allowed, 16)
        XCTAssertEqual(ledger.needsConfirmation, 1)

        XCTAssertEqual(ledger.blockedRate, 7.0 / 24.0, accuracy: 0.0001)
        XCTAssertEqual(ledger.frictionRate, 8.0 / 24.0, accuracy: 0.0001)

        // Replay twice: byte-identical.
        XCTAssertEqual(MailAssistantTrace.replay(gate: gate), result)
    }

    func testEveryStepAfterTaintThatTriesToLeaveIsRefused() throws {
        let gate = CapabilityGate(surface: try MailAssistantSurface.surface())
        let result = MailAssistantTrace.replay(gate: gate)

        for outcome in result.outcomes where outcome.taintBefore == .foreign {
            guard let tool = gate.surface.tool(named: outcome.toolName) else {
                XCTAssertEqual(outcome.decision, .deny(.notInSurface))
                continue
            }
            if tool.effect.isExfiltrationCapable {
                XCTAssertEqual(outcome.decision, .deny(.unreachableFromTaintedScope), "step \(outcome.step)")
            } else {
                XCTAssertEqual(outcome.decision, .allow, "step \(outcome.step)")
            }
        }
    }

    func testLedgerRatesOnAnEmptyLedgerDoNotDivideByZero() {
        let ledger = FidelityLedger()
        XCTAssertEqual(ledger.total, 0)
        XCTAssertEqual(ledger.frictionRate, 0)
        XCTAssertEqual(ledger.blockedRate, 0)
        XCTAssertEqual(ledger.count(of: .notInSurface), 0)
    }
}
