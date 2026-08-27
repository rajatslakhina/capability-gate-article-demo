# CapabilityGate

A deterministic authorization gate for a model-driven tool surface on iOS — the
kind of control Apple's WWDC26 security session means when it says a
probabilistic mitigation is not a security guarantee.

The library takes a declared tool surface, tracks one bit of session state, and
answers `allow` / `requireConfirmation` / `deny` as a **pure, total function**.
No prompt, no classifier, no model in the decision path.

> Article: (added after publish)

## The argument, in one screen

Flip the toggle and nothing about the model changes — the same 24 requests, in
the same order, with the same arguments. The only difference is whether a
deterministic gate sits between the model and the tools.

## What it does

Three rules, all checked at the call boundary:

1. **Schema review happens in `init`.** A tool that both reads foreign data and
   sends data out of the app is a complete exfiltration primitive on its own, so
   `CapabilitySurface.init` refuses to build a surface containing one — before a
   single token is generated.
2. **Taint is monotonic.** Once a call has pulled attacker-choosable bytes into
   the transcript, every egress-or-worse tool is unreachable for the rest of the
   session. There is no un-taint path, because there is no deterministic
   procedure that removes instructions from text.
3. **Confirmations bind to one effect.** A `ConfirmationToken` carries a stable
   digest of `(tool, effect, arguments)`. Approving "email Priya" cannot be
   replayed to authorize "email attacker@evil.example".

```swift
let surface = try MailAssistantSurface.surface()
let gate = CapabilityGate(surface: surface)

var scope = SessionScope()
scope.record(ran: readInbox)          // foreign bytes are now in the transcript

gate.evaluate(
    ToolRequest(toolName: "postWebhook", confirmation: validToken),
    in: scope,
    now: .now
)
// .deny(.unreachableFromTaintedScope) — even with a valid confirmation
```

The surface review is the part most teams skip:

```swift
let convenience = ToolDescriptor(
    name: "summarizeThreadAndForward",
    ingests: [.foreign],
    effect: .externalEgress(channel: "SMTP")
)

try CapabilitySurface(tools: MailAssistantSurface.tools + [convenience])
// throws .selfContainedExfiltrationPrimitive(tool:channel:)
// "Split it: the reading half and the sending half must not sit in one
//  authorization scope."
```

## The numbers (all read out of tests, none asserted in prose)

Worked example: a 12-tool mail-and-notes assistant surface.

| Measurement | Value | Where it comes from |
|---|---|---|
| Tools declared | 12 | `ReachabilityAudit.audit` |
| Tools that can ingest foreign bytes | 2 (`readInbox`, `readWebPage`) | same |
| Tools that can move data off-device or destroy it | 4 | same |
| Tools reachable in a clean scope | 12 | same |
| Tools reachable after the first foreign read | 8 | same |
| Surface collapse once tainted | 33.3% | `collapseRatio` |
| Trace length | 24 requests | `MailAssistantTrace` |
| Scope becomes tainted at | step 9 | `replay(...).taintedAtStep` |
| Ran / paused for a human / refused | 16 / 1 / 7 | `FidelityLedger` |
| Refused because unreachable from a tainted scope | 6 | `denials` |
| Refused because the tool is not in the surface | 1 | `denials` |
| Blocked rate (the fidelity cost, counted) | 29.2% | `blockedRate` |
| Exhaustive invariant check | 72 evaluations, 12 must-deny cells, 0 leaks | `ExhaustiveInvariantTests` |

Two tools decide whether the other four are reachable at all. That is the
review that matters, and it is a property of the schema — not of the prompt.

## How to run it

```bash
git clone https://github.com/rajatslakhina/capability-gate-article-demo.git
cd capability-gate-article-demo
open Demo.xcodeproj      # pick any iOS Simulator, then Build & Run
```

No second repo, no package resolution step — `Demo.xcodeproj` consumes the
library through a local package reference to this same checkout.

Library only:

```bash
swift build
swift test
```

## Verification status

Honest accounting of what was and was not verified:

- **`swift build` — passes.** Swift 6.0.3, `swift-tools-version: 6.0`.
- **`swift test` — passes. 20 tests, 0 failures.** Covering the surface-rejection
  rules, taint monotonicity, confirmation binding and expiry, the unknown-tool
  path, the empty-ledger division-by-zero edge case, the full 24-step trace
  replay, and an exhaustive 72-cell enumeration of the taint invariant.
- **The app was NOT launched on a Simulator during the run that produced this
  repo, and there is no Simulator screenshot in this README.** The run was an
  unattended scheduled task, and this environment cannot grant Xcode or
  Simulator control in that mode — the request is refused at the platform
  level, not skipped by choice. What was done instead: `Demo.xcodeproj`'s
  `project.pbxproj` was checked for brace and paren balance (32/32, 24/24),
  for dangling object references (22 defined, 22 referenced, 0 dangling), and
  for a correct `XCLocalSwiftPackageReference` with a relative path; the shared
  scheme's `BlueprintIdentifier` was confirmed to match the `PBXNativeTarget`
  id; and the SwiftUI view was compiled and reviewed by hand against its iOS 17
  availability floor. Treat the Xcode target as reviewed, not as run.

## Layout

```
Sources/CapabilityGate/
  Provenance.swift          where a byte came from
  Effect.swift              what a tool does to the world
  ToolDescriptor.swift      one callable tool, as a security review reads it
  CapabilitySurface.swift   the schema check — throws on a bad surface
  SessionScope.swift        monotonic taint
  EffectStatement.swift     effect-derived confirmation text + stable digest
  CapabilityGate.swift      evaluate(): pure, total, no force parameter
  FidelityLedger.swift      the price of the policy, counted
  ReachabilityAudit.swift   the CI-runnable static audit
  MailAssistantSurface.swift  worked example + the 24-step trace
  CapabilityGateDemoView.swift
Tests/CapabilityGateTests/  20 tests
Demo/                       the runnable app target
```

## Licence

MIT. See [LICENSE](LICENSE).
