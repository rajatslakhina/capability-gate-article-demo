import Foundation

/// The price of the policy, counted.
///
/// Hardening a surface costs task fidelity — every refusal is a thing the
/// product could have done and now cannot. That trade is a product decision,
/// so somebody has to be able to see the number. This is that number.
public struct FidelityLedger: Sendable, Equatable {

    public private(set) var allowed = 0
    public private(set) var needsConfirmation = 0
    public private(set) var denials: [DenialReason: Int] = [:]

    public init() {}

    public mutating func record(_ decision: Decision) {
        switch decision {
        case .allow:
            allowed += 1
        case .requireConfirmation:
            needsConfirmation += 1
        case .deny(let reason):
            denials[reason, default: 0] += 1
        }
    }

    public var denied: Int { denials.values.reduce(0, +) }
    public var total: Int { allowed + needsConfirmation + denied }

    /// Share of requests that did not sail straight through.
    public var frictionRate: Double {
        guard total > 0 else { return 0 }
        return Double(needsConfirmation + denied) / Double(total)
    }

    /// Share of requests refused outright — the part the product genuinely
    /// loses, as opposed to merely slows down.
    public var blockedRate: Double {
        guard total > 0 else { return 0 }
        return Double(denied) / Double(total)
    }

    public func count(of reason: DenialReason) -> Int { denials[reason] ?? 0 }
}
