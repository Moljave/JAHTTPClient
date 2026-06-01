namespace JASniffer.Core.Models;

/// <summary>
/// A single HTTP header as it appeared on the wire, preserving order and the
/// exact (possibly duplicated) name/value pairing. Stored rather than a
/// dictionary so inspectors and the <c>.saz</c> export reproduce the request and
/// response faithfully (e.g. multiple <c>Set-Cookie</c> lines).
/// </summary>
/// <param name="Name">Header field name, original casing.</param>
/// <param name="Value">Header field value, unmodified.</param>
public readonly record struct HeaderEntry(string Name, string Value);
