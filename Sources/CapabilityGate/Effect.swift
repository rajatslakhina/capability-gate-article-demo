import Foundation

/// What a tool does to the world when it runs.
///
/// Deliberately coarse. A four-value ladder you can argue about in a review is
/// worth more than a twenty-value taxonomy nobody fills in correctly.
public enum Effect: Sendable, Hashable, Codable {

    /// Reads. Changes nothing.
    case none

    /// Writes state the app owns, and the user can undo it from inside the app.
    case localMutation

    /// Data crosses the app boundary. The `channel` names where it goes.
    case externalEgress(channel: String)

    /// Cannot be undone from inside the app. The `what` names the loss.
    case irreversible(what: String)

    /// Position on the ladder. Higher is harder to take back.
    public var severity: Int {
        switch self {
        case .none: return 0
        case .localMutation: return 1
        case .externalEgress: return 2
        case .irreversible: return 3
        }
    }

    /// The severity at which a tool stops being safe to reach from
    /// attacker-chosen input.
    public static let egressThreshold = 2

    /// `true` when reaching this effect from foreign data is a data-exfiltration
    /// or destructive-action primitive.
    public var isExfiltrationCapable: Bool { severity >= Effect.egressThreshold }
}
