#if canImport(SwiftUI)
import Foundation
import SwiftUI

/// The argument on one screen.
///
/// Flip the toggle and nothing about the model changes — same 24 requests, same
/// order, same arguments. The only thing that changes is whether a
/// deterministic gate sits between the model and the tools.
@available(iOS 17.0, macOS 14.0, *)
public struct CapabilityGateDemoView: View {

    @State private var gateEnabled = true

    private let gate: CapabilityGate?

    public init() {
        self.gate = (try? MailAssistantSurface.surface()).map { CapabilityGate(surface: $0) }
    }

    public var body: some View {
        NavigationStack {
            Group {
                if let gate {
                    content(gate: gate)
                } else {
                    ContentUnavailableView(
                        "Surface rejected",
                        systemImage: "exclamationmark.shield",
                        description: Text("The declared tool surface failed its own audit.")
                    )
                }
            }
            .navigationTitle("Capability Gate")
        }
    }

    @ViewBuilder
    private func content(gate: CapabilityGate) -> some View {
        let result = MailAssistantTrace.replay(gate: gate)

        List {
            Section {
                Toggle("Deterministic gate", isOn: $gateEnabled)
                Text(gateEnabled
                     ? "Every request is evaluated against the capability surface before the tool sees it."
                     : "Guardrail prompt only. The model was asked nicely. Nothing is checked at the call boundary.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Defence")
            }

            Section {
                scoreboard(for: result)
            } header: {
                Text("24 requests, replayed")
            }

            Section {
                ForEach(result.outcomes, id: \.step) { outcome in
                    row(for: outcome)
                }
            } header: {
                Text("Transcript")
            } footer: {
                Text(gateEnabled
                     ? "Step \(result.taintedAtStep.map(String.init) ?? "—") read the inbox. Everything that leaves the app is unreachable from there on — including the four calls carrying a valid confirmation."
                     : "Every request reaches its tool, because a prompt is not a call-site check.")
            }
        }
    }

    @ViewBuilder
    private func scoreboard(for result: MailAssistantTrace.Result) -> some View {
        let ledger = result.ledger
        let allowed = gateEnabled ? ledger.allowed : ledger.total
        let confirmed = gateEnabled ? ledger.needsConfirmation : 0
        let denied = gateEnabled ? ledger.denied : 0

        HStack(spacing: 12) {
            tile("Ran", value: allowed, tint: .green)
            tile("Paused", value: confirmed, tint: .orange)
            tile("Refused", value: denied, tint: .red)
        }
        .padding(.vertical, 4)

        LabeledContent("Data left the app after taint") {
            Text(gateEnabled ? "0 of 6 attempts" : "6 of 6 attempts")
                .foregroundStyle(gateEnabled ? .green : .red)
                .monospacedDigit()
        }
        .font(.callout)
    }

    private func tile(_ title: String, value: Int, tint: Color) -> some View {
        VStack(spacing: 2) {
            Text("\(value)")
                .font(.title2.weight(.semibold).monospacedDigit())
                .foregroundStyle(tint)
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private func row(for outcome: MailAssistantTrace.Outcome) -> some View {
        let effective: Decision = gateEnabled ? outcome.decision : .allow

        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text("\(outcome.step)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .frame(width: 22, alignment: .trailing)

                Image(systemName: symbol(for: effective))
                    .foregroundStyle(tint(for: effective))
                    .font(.footnote)

                Text(outcome.toolName)
                    .font(.callout.monospaced())

                Spacer()

                if outcome.taintBefore == .foreign {
                    Text("tainted")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }
            }
            if let detail = detail(for: effective) {
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.leading, 30)
            }
        }
    }

    private func symbol(for decision: Decision) -> String {
        switch decision {
        case .allow: return "checkmark.circle.fill"
        case .requireConfirmation: return "hand.raised.fill"
        case .deny: return "xmark.octagon.fill"
        }
    }

    private func tint(for decision: Decision) -> Color {
        switch decision {
        case .allow: return .green
        case .requireConfirmation: return .orange
        case .deny: return .red
        }
    }

    private func detail(for decision: Decision) -> String? {
        switch decision {
        case .allow: return nil
        case .requireConfirmation(let statement): return statement.sentence
        case .deny(let reason): return reason.rawValue
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    CapabilityGateDemoView()
}
#endif
