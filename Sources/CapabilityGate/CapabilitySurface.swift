import Foundation

/// Everything reachable from a model in one authorization scope.
///
/// Constructing one is the security review. If a surface can be built, it has
/// no self-contained exfiltration primitive in it — that is checked here, in
/// `init`, before a single token is generated.
public struct CapabilitySurface: Sendable, Equatable {

    /// Why a declared surface was rejected.
    public enum SurfaceError: Error, Equatable, CustomStringConvertible {
        case empty
        case duplicateTool(name: String)
        case selfContainedExfiltrationPrimitive(tool: String, channel: String)

        public var description: String {
            switch self {
            case .empty:
                return "A capability surface must declare at least one tool."
            case .duplicateTool(let name):
                return "Tool '\(name)' is declared twice; tool names are the identity used by the gate."
            case .selfContainedExfiltrationPrimitive(let tool, let channel):
                return "Tool '\(tool)' reads foreign data and sends to '\(channel)' in one call. "
                     + "Split it: the reading half and the sending half must not sit in one authorization scope."
            }
        }
    }

    public let tools: [ToolDescriptor]
    private let index: [String: ToolDescriptor]

    public init(tools: [ToolDescriptor]) throws(SurfaceError) {
        guard tools.isEmpty == false else { throw .empty }

        var index: [String: ToolDescriptor] = [:]
        index.reserveCapacity(tools.count)

        for tool in tools {
            guard index[tool.name] == nil else {
                throw .duplicateTool(name: tool.name)
            }
            if tool.isSelfContainedExfiltrationPrimitive {
                throw .selfContainedExfiltrationPrimitive(
                    tool: tool.name,
                    channel: tool.effect.channelDescription
                )
            }
            index[tool.name] = tool
        }

        self.tools = tools
        self.index = index
    }

    /// Look a tool up by the name the model used. Unknown names are a denial,
    /// never a best-effort match.
    public func tool(named name: String) -> ToolDescriptor? { index[name] }

    /// Tools that can pull attacker-chosen bytes into the transcript.
    public var ingestPoints: [ToolDescriptor] { tools.filter(\.isIngestPoint) }

    /// Tools whose effect is egress-or-worse.
    public var exfiltrationCapableTools: [ToolDescriptor] {
        tools.filter { $0.effect.isExfiltrationCapable }
    }
}

extension Effect {
    /// A short human name for where the effect lands, used in messages.
    var channelDescription: String {
        switch self {
        case .none: return "nothing"
        case .localMutation: return "local storage"
        case .externalEgress(let channel): return channel
        case .irreversible(let what): return what
        }
    }
}
