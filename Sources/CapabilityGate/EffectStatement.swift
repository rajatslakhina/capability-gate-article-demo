import Foundation

/// A stable 64-bit digest.
///
/// Swift's `Hasher` is seeded per process, so `hashValue` changes between
/// launches. A confirmation token that survives a relaunch — or that is
/// compared across an XPC boundary — cannot be built on it. FNV-1a is not a
/// security hash, and it is not being used as one: it binds a confirmation to
/// the exact effect the user saw, in one process, over a short TTL.
enum StableDigest {
    static func of(_ string: String) -> UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in string.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        return hash
    }
}

/// What the user is actually being asked to approve.
///
/// Built from the tool's declared effect and the concrete arguments — never
/// from a model-written summary. The model does not get to describe its own
/// side effect to the person authorizing it.
public struct EffectStatement: Sendable, Hashable, Codable {

    /// The sentence shown to the user. Names the effect, not the intent.
    public let sentence: String

    /// Binds a confirmation to this exact (tool, effect, arguments) triple.
    public let digest: UInt64

    public init(tool: ToolDescriptor, arguments: [String: String]) {
        let renderedArguments = arguments
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ", ")

        self.sentence = EffectStatement.sentence(
            for: tool.effect,
            tool: tool.name,
            arguments: renderedArguments
        )
        self.digest = StableDigest.of("\(tool.name)|\(tool.effect.severity)|\(tool.effect.channelDescription)|\(renderedArguments)")
    }

    private static func sentence(for effect: Effect, tool: String, arguments: String) -> String {
        let detail = arguments.isEmpty ? "no arguments" : arguments
        switch effect {
        case .none:
            return "Read only. \(tool) changes nothing. (\(detail))"
        case .localMutation:
            return "Changes data stored in this app. You can undo it here. \(tool) (\(detail))"
        case .externalEgress(let channel):
            return "Sends data out of this app to \(channel). Once it leaves, you cannot recall it. \(tool) (\(detail))"
        case .irreversible(let what):
            return "Permanently performs: \(what). This cannot be undone. \(tool) (\(detail))"
        }
    }
}

/// Proof that a human approved one specific effect, once.
///
/// It carries the digest of the statement they saw. It is not a general
/// "the user said yes" flag, because a general yes is what turns one benign
/// confirmation into authorization for whatever the model asks next.
public struct ConfirmationToken: Sendable, Hashable, Codable {
    public let digest: UInt64
    public let issuedAt: Date

    public init(statement: EffectStatement, issuedAt: Date) {
        self.digest = statement.digest
        self.issuedAt = issuedAt
    }
}
