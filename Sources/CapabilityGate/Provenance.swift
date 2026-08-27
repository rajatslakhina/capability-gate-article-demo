import Foundation

/// Where a piece of data came from.
///
/// This is the unit the gate actually reasons about. Not "is this string
/// suspicious" — that is a judgement call, and judgement calls are
/// probabilistic. Only: did this byte originate somewhere an attacker can
/// write to.
public enum Provenance: String, Sendable, Hashable, Codable, CaseIterable {

    /// Data the app itself owns and wrote: local database rows, bundled
    /// resources, values the app computed.
    case appOwned

    /// Data the human at the keyboard typed into this app, in this session.
    case userTyped

    /// Data authored by somebody who is not the user: email bodies, web pages,
    /// shared documents, calendar invites from strangers, another agent's
    /// output. Anyone can write here.
    case foreign

    /// `true` when an attacker can choose these bytes.
    public var isAttackerControlled: Bool { self == .foreign }
}
