import Foundation

/// One callable tool, described the way a security review can actually read it.
///
/// The two fields that matter are `ingests` and `effect`. Everything the gate
/// decides falls out of those. Note what is *absent*: there is no prompt here,
/// no description string the model reads, no instructions. Those are inputs to
/// the model, not inputs to the control.
public struct ToolDescriptor: Sendable, Hashable, Codable, Identifiable {

    /// The name the model calls. Also the identity used in audits.
    public let name: String

    /// The provenances of data this tool can pull into the transcript.
    public let ingests: Set<Provenance>

    /// What running it does to the world.
    public let effect: Effect

    public var id: String { name }

    public init(name: String, ingests: Set<Provenance>, effect: Effect) {
        self.name = name
        self.ingests = ingests
        self.effect = effect
    }

    /// `true` when calling this tool can pull attacker-chosen bytes into the
    /// transcript, which from that moment on are indistinguishable from
    /// instructions to the model.
    public var isIngestPoint: Bool {
        ingests.contains { $0.isAttackerControlled }
    }

    /// A tool that both reads attacker-chosen data and moves data off the
    /// device is a complete exfiltration primitive on its own. No sequencing
    /// required, no scope state involved: one call is the whole attack.
    public var isSelfContainedExfiltrationPrimitive: Bool {
        isIngestPoint && effect.isExfiltrationCapable
    }
}
