import Foundation

/// A static audit of a declared surface. Runs in CI. Needs no model, no
/// transcript and no test corpus, because it is reading the schema — which is
/// where the security property lives.
public enum ReachabilityAudit {

    public struct Report: Sendable, Equatable {
        public let toolCount: Int
        public let ingestPoints: [String]
        public let exfiltrationCapableTools: [String]

        /// Effects still reachable before anything foreign is read.
        public let reachableWhenClean: [String]
        /// Effects still reachable after the first foreign read.
        public let reachableWhenTainted: [String]

        /// Tools whose reachability depends on session state rather than on
        /// their own declaration. These are the ones a prompt-only defence
        /// silently leaves open.
        public let stateDependentTools: [String]

        /// The share of the surface that collapses once foreign bytes land.
        public var collapseRatio: Double {
            guard toolCount > 0 else { return 0 }
            return Double(stateDependentTools.count) / Double(toolCount)
        }
    }

    public static func audit(_ surface: CapabilitySurface, gate: CapabilityGate? = nil) -> Report {
        let gate = gate ?? CapabilityGate(surface: surface)
        let now = Date(timeIntervalSince1970: 0)

        func reachable(under taint: SessionScope.Taint) -> [String] {
            let scope = SessionScope.scope(taint: taint)
            return surface.tools.filter { tool in
                gate.evaluate(ToolRequest(toolName: tool.name), in: scope, now: now)
                    != .deny(.unreachableFromTaintedScope)
            }.map(\.name)
        }

        let clean = reachable(under: .clean)
        let tainted = reachable(under: .foreign)
        let taintedSet = Set(tainted)

        return Report(
            toolCount: surface.tools.count,
            ingestPoints: surface.ingestPoints.map(\.name),
            exfiltrationCapableTools: surface.exfiltrationCapableTools.map(\.name),
            reachableWhenClean: clean,
            reachableWhenTainted: tainted,
            stateDependentTools: clean.filter { taintedSet.contains($0) == false }
        )
    }
}
