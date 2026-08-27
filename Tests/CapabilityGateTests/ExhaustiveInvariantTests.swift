import XCTest
@testable import CapabilityGate

/// The point of the whole library.
///
/// A probabilistic defence gets a sampled failure rate: run a thousand attack
/// prompts, count the ones that got through, publish a percentage that is not
/// zero and has no upper bound. A deterministic one gets this instead — the
/// full cross product, enumerated, with the invariant asserted on every cell.
final class ExhaustiveInvariantTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private enum ConfirmationCase: CaseIterable {
        case absent, matching, stale
    }

    func testEgressNeverReachableFromTaintedScopeAcrossEveryCombination() throws {
        let surface = try MailAssistantSurface.surface()
        let gate = CapabilityGate(surface: surface)

        var evaluated = 0
        var deniedForTaint = 0

        for taint in SessionScope.Taint.allCases {
            for tool in surface.tools {
                for confirmationCase in ConfirmationCase.allCases {
                    let arguments = ["to": "someone@example.com"]
                    let statement = EffectStatement(tool: tool, arguments: arguments)

                    let confirmation: ConfirmationToken?
                    switch confirmationCase {
                    case .absent:
                        confirmation = nil
                    case .matching:
                        confirmation = ConfirmationToken(statement: statement, issuedAt: now)
                    case .stale:
                        confirmation = ConfirmationToken(
                            statement: statement,
                            issuedAt: now.addingTimeInterval(-gate.confirmationLifetime - 1)
                        )
                    }

                    let decision = gate.evaluate(
                        ToolRequest(toolName: tool.name, arguments: arguments, confirmation: confirmation),
                        in: SessionScope.scope(taint: taint),
                        now: now
                    )
                    evaluated += 1

                    if taint == .foreign && tool.effect.isExfiltrationCapable {
                        XCTAssertEqual(
                            decision,
                            .deny(.unreachableFromTaintedScope),
                            "tool=\(tool.name) confirmation=\(confirmationCase) leaked past the gate"
                        )
                        deniedForTaint += 1
                    } else {
                        XCTAssertNotEqual(decision, .deny(.unreachableFromTaintedScope))
                    }
                }
            }
        }

        // 2 taint states x 12 tools x 3 confirmation states.
        XCTAssertEqual(evaluated, 72)
        // 1 tainted state x 4 exfiltration-capable tools x 3 confirmation states.
        XCTAssertEqual(deniedForTaint, 12)
    }

    func testEvaluateIsPureAndTotal() throws {
        let gate = CapabilityGate(surface: try MailAssistantSurface.surface())
        let request = ToolRequest(toolName: "sendMail", arguments: ["to": "a@b.example"])
        let scope = SessionScope()

        let first = gate.evaluate(request, in: scope, now: now)
        for _ in 0..<50 {
            XCTAssertEqual(gate.evaluate(request, in: scope, now: now), first)
        }
        XCTAssertEqual(scope, SessionScope(), "evaluate must not mutate the scope it is handed")
    }

    func testEveryDenialReasonIsReachable() throws {
        let gate = CapabilityGate(surface: try MailAssistantSurface.surface())
        var seen: Set<DenialReason> = []

        // notInSurface
        if case .deny(let r) = gate.evaluate(ToolRequest(toolName: "nope"), in: SessionScope(), now: now) {
            seen.insert(r)
        }
        // unreachableFromTaintedScope
        if case .deny(let r) = gate.evaluate(
            ToolRequest(toolName: "postWebhook"),
            in: SessionScope.scope(taint: .foreign),
            now: now
        ) { seen.insert(r) }

        guard let sendMail = gate.surface.tool(named: "sendMail") else { return XCTFail("missing tool") }
        let statement = EffectStatement(tool: sendMail, arguments: ["to": "a@b.example"])

        // confirmationBoundToDifferentEffect
        if case .deny(let r) = gate.evaluate(
            ToolRequest(
                toolName: "sendMail",
                arguments: ["to": "z@evil.example"],
                confirmation: ConfirmationToken(statement: statement, issuedAt: now)
            ),
            in: SessionScope(),
            now: now
        ) { seen.insert(r) }

        // confirmationExpired
        if case .deny(let r) = gate.evaluate(
            ToolRequest(
                toolName: "sendMail",
                arguments: ["to": "a@b.example"],
                confirmation: ConfirmationToken(statement: statement, issuedAt: now.addingTimeInterval(-9999))
            ),
            in: SessionScope(),
            now: now
        ) { seen.insert(r) }

        XCTAssertEqual(seen, Set(DenialReason.allCases))
    }
}
