import Foundation

/// Why a request was refused.
public enum DenialReason: String, Sendable, Hashable, Codable, CaseIterable {
    /// The model named a tool that is not in the surface.
    case notInSurface
    /// Foreign bytes are in the transcript; egress-or-worse is unreachable.
    case unreachableFromTaintedScope
    /// A confirmation was presented, but for a different effect.
    case confirmationBoundToDifferentEffect
    /// A confirmation was presented, but it is older than the lifetime.
    case confirmationExpired
}

/// The gate's answer. Three cases, total, no fourth "probably fine".
public enum Decision: Sendable, Equatable {
    case allow
    case requireConfirmation(EffectStatement)
    case deny(DenialReason)

    public var isAllowed: Bool { self == .allow }
}

/// One thing the model asked to do.
public struct ToolRequest: Sendable, Equatable {
    public let toolName: String
    public let arguments: [String: String]
    public let confirmation: ConfirmationToken?

    public init(toolName: String, arguments: [String: String] = [:], confirmation: ConfirmationToken? = nil) {
        self.toolName = toolName
        self.arguments = arguments
        self.confirmation = confirmation
    }
}

/// A deterministic authorization gate for a model-driven tool surface.
///
/// `evaluate` is a pure, total function of `(surface, scope, request, now)`.
/// That is the entire claim being made: not that it is smarter than a system
/// prompt, but that its failure rate for the property it enforces is zero and
/// can be checked by enumeration rather than estimated by sampling.
public struct CapabilityGate: Sendable {

    public let surface: CapabilitySurface

    /// How long a confirmation stays valid. Short on purpose: a confirmation
    /// is approval of an action about to happen, not a standing grant.
    public let confirmationLifetime: TimeInterval

    public init(surface: CapabilitySurface, confirmationLifetime: TimeInterval = 120) {
        self.surface = surface
        self.confirmationLifetime = confirmationLifetime
    }

    /// Decide. No `force` parameter exists, which is the point: there is no
    /// argument the caller — or the model, through the caller — can pass to
    /// skip a confirmation.
    public func evaluate(_ request: ToolRequest, in scope: SessionScope, now: Date) -> Decision {
        guard let tool = surface.tool(named: request.toolName) else {
            return .deny(.notInSurface)
        }

        // Rule 1. Once foreign bytes are in the transcript, nothing that leaves
        // the app is reachable. Not "flagged", not "double-checked" — refused,
        // before the tool sees an argument.
        if scope.taint == .foreign && tool.effect.isExfiltrationCapable {
            return .deny(.unreachableFromTaintedScope)
        }

        // Rule 2. Effects the user cannot walk back need a human, every time,
        // bound to this exact effect.
        guard tool.effect.isExfiltrationCapable else { return .allow }

        let statement = EffectStatement(tool: tool, arguments: request.arguments)

        guard let confirmation = request.confirmation else {
            return .requireConfirmation(statement)
        }
        guard confirmation.digest == statement.digest else {
            return .deny(.confirmationBoundToDifferentEffect)
        }
        let age = now.timeIntervalSince(confirmation.issuedAt)
        guard age >= 0 && age <= confirmationLifetime else {
            return .deny(.confirmationExpired)
        }
        return .allow
    }
}
