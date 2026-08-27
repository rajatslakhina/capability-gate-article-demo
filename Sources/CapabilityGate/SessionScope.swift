import Foundation

/// The gate's memory of what this session has already touched.
///
/// One rule runs the whole thing: taint is monotonic. A scope that has ingested
/// foreign bytes never becomes clean again, because there is no deterministic
/// procedure that removes instructions from text. "Sanitize and continue" is
/// the probabilistic mitigation this type exists to refuse.
public struct SessionScope: Sendable, Equatable {

    public enum Taint: String, Sendable, Equatable, Codable, CaseIterable {
        /// Nothing attacker-controlled has entered the transcript.
        case clean
        /// Foreign bytes are in the transcript and cannot be separated from
        /// instructions.
        case foreign
    }

    public private(set) var taint: Taint
    public private(set) var ingestedFrom: [String]

    public init() {
        self.taint = .clean
        self.ingestedFrom = []
    }

    /// Record that a tool ran. The only state transition in the type.
    public mutating func record(ran tool: ToolDescriptor) {
        guard tool.isIngestPoint else { return }
        taint = .foreign
        if ingestedFrom.contains(tool.name) == false {
            ingestedFrom.append(tool.name)
        }
    }

    /// Test seam: build a scope already in a given state.
    public static func scope(taint: Taint) -> SessionScope {
        var scope = SessionScope()
        if taint == .foreign {
            scope.taint = .foreign
            scope.ingestedFrom = ["<preset>"]
        }
        return scope
    }
}
