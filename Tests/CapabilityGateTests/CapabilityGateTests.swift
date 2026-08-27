import XCTest
@testable import CapabilityGate

final class CapabilityGateTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeGate() throws -> CapabilityGate {
        CapabilityGate(surface: try MailAssistantSurface.surface())
    }

    // MARK: - Surface construction is the security review

    func testSurfaceRejectsSelfContainedExfiltrationPrimitive() {
        let tools = MailAssistantSurface.tools + [MailAssistantSurface.rejectedConvenienceTool]
        XCTAssertThrowsError(try CapabilitySurface(tools: tools)) { error in
            XCTAssertEqual(
                error as? CapabilitySurface.SurfaceError,
                .selfContainedExfiltrationPrimitive(tool: "summarizeThreadAndForward", channel: "SMTP")
            )
        }
    }

    func testSurfaceRejectsDuplicateToolNames() {
        let duplicated = MailAssistantSurface.tools + [MailAssistantSurface.tools[0]]
        XCTAssertThrowsError(try CapabilitySurface(tools: duplicated)) { error in
            XCTAssertEqual(error as? CapabilitySurface.SurfaceError, .duplicateTool(name: "readInbox"))
        }
    }

    func testEmptySurfaceIsRejected() {
        XCTAssertThrowsError(try CapabilitySurface(tools: [])) { error in
            XCTAssertEqual(error as? CapabilitySurface.SurfaceError, .empty)
        }
    }

    // MARK: - The load-bearing rule

    func testEgressIsUnreachableOnceScopeIsTainted() throws {
        let gate = try makeGate()
        let tainted = SessionScope.scope(taint: .foreign)

        for tool in gate.surface.exfiltrationCapableTools {
            let statement = EffectStatement(tool: tool, arguments: [:])
            let request = ToolRequest(
                toolName: tool.name,
                confirmation: ConfirmationToken(statement: statement, issuedAt: now)
            )
            XCTAssertEqual(
                gate.evaluate(request, in: tainted, now: now),
                .deny(.unreachableFromTaintedScope),
                "\(tool.name) must be unreachable from a tainted scope even WITH a valid confirmation"
            )
        }
    }

    func testReadsAndLocalMutationsStayAvailableWhenTainted() throws {
        let gate = try makeGate()
        let tainted = SessionScope.scope(taint: .foreign)

        for tool in gate.surface.tools where tool.effect.isExfiltrationCapable == false {
            XCTAssertEqual(
                gate.evaluate(ToolRequest(toolName: tool.name), in: tainted, now: now),
                .allow,
                "\(tool.name) is harmless after taint and must not be blocked"
            )
        }
    }

    func testTaintIsMonotonic() throws {
        let gate = try makeGate()
        var scope = SessionScope()
        XCTAssertEqual(scope.taint, .clean)

        guard let inbox = gate.surface.tool(named: "readInbox"),
              let notes = gate.surface.tool(named: "searchNotes") else {
            return XCTFail("worked-example surface is missing its own tools")
        }

        scope.record(ran: inbox)
        XCTAssertEqual(scope.taint, .foreign)

        // A hundred clean reads do not wash it out.
        for _ in 0..<100 { scope.record(ran: notes) }
        XCTAssertEqual(scope.taint, .foreign)
        XCTAssertEqual(scope.ingestedFrom, ["readInbox"])
    }

    // MARK: - Confirmations

    func testEgressRequiresConfirmationEvenInACleanScope() throws {
        let gate = try makeGate()
        let decision = gate.evaluate(
            ToolRequest(toolName: "sendMail", arguments: ["to": "a@b.example"]),
            in: SessionScope(),
            now: now
        )
        guard case .requireConfirmation(let statement) = decision else {
            return XCTFail("expected a confirmation requirement, got \(decision)")
        }
        XCTAssertTrue(statement.sentence.contains("Sends data out of this app to SMTP"))
        XCTAssertTrue(statement.sentence.contains("to=a@b.example"))
    }

    func testStatementDescribesTheEffectNotTheIntent() throws {
        let gate = try makeGate()
        guard let delete = gate.surface.tool(named: "deleteAllArchived") else {
            return XCTFail("missing tool")
        }
        let statement = EffectStatement(tool: delete, arguments: ["reason": "tidy up, totally routine"])
        XCTAssertTrue(statement.sentence.hasPrefix("Permanently performs: delete every archived message"))
        XCTAssertTrue(statement.sentence.contains("cannot be undone"))
    }

    func testConfirmationForOneEffectDoesNotAuthorizeAnother() throws {
        let gate = try makeGate()
        guard let sendMail = gate.surface.tool(named: "sendMail") else { return XCTFail("missing tool") }

        let benign = EffectStatement(tool: sendMail, arguments: ["to": "priya@team.example"])
        let replayed = ConfirmationToken(statement: benign, issuedAt: now)

        let hostile = ToolRequest(
            toolName: "sendMail",
            arguments: ["to": "attacker@evil.example"],
            confirmation: replayed
        )
        XCTAssertEqual(
            gate.evaluate(hostile, in: SessionScope(), now: now),
            .deny(.confirmationBoundToDifferentEffect)
        )
    }

    func testConfirmationExpires() throws {
        let gate = try makeGate()
        guard let sendMail = gate.surface.tool(named: "sendMail") else { return XCTFail("missing tool") }
        let statement = EffectStatement(tool: sendMail, arguments: ["to": "priya@team.example"])
        let token = ConfirmationToken(statement: statement, issuedAt: now)
        let request = ToolRequest(toolName: "sendMail", arguments: ["to": "priya@team.example"], confirmation: token)

        XCTAssertEqual(gate.evaluate(request, in: SessionScope(), now: now.addingTimeInterval(119)), .allow)
        XCTAssertEqual(
            gate.evaluate(request, in: SessionScope(), now: now.addingTimeInterval(121)),
            .deny(.confirmationExpired)
        )
    }

    func testConfirmationIssuedInTheFutureIsRejected() throws {
        let gate = try makeGate()
        guard let sendMail = gate.surface.tool(named: "sendMail") else { return XCTFail("missing tool") }
        let statement = EffectStatement(tool: sendMail, arguments: [:])
        let token = ConfirmationToken(statement: statement, issuedAt: now.addingTimeInterval(60))
        let request = ToolRequest(toolName: "sendMail", confirmation: token)
        XCTAssertEqual(gate.evaluate(request, in: SessionScope(), now: now), .deny(.confirmationExpired))
    }

    // MARK: - Edge cases

    func testUnknownToolIsDeniedNotGuessed() throws {
        let gate = try makeGate()
        XCTAssertEqual(
            gate.evaluate(ToolRequest(toolName: "sendMai1"), in: SessionScope(), now: now),
            .deny(.notInSurface)
        )
    }

    func testDigestIsStableAcrossInstancesAndArgumentOrder() throws {
        let gate = try makeGate()
        guard let sendMail = gate.surface.tool(named: "sendMail") else { return XCTFail("missing tool") }
        let a = EffectStatement(tool: sendMail, arguments: ["to": "x@y.example", "subject": "hi"])
        let b = EffectStatement(tool: sendMail, arguments: ["subject": "hi", "to": "x@y.example"])
        XCTAssertEqual(a.digest, b.digest)
        // Pinned: a process-seeded hash would change between runs, so a
        // confirmation token could not survive one. This one does not move.
        XCTAssertEqual(StableDigest.of(""), 0xcbf2_9ce4_8422_2325)
        XCTAssertEqual(StableDigest.of("sendMail|2|SMTP|to=x@y.example"), 0xc4bd_b247_4d40_9821)
    }
}
