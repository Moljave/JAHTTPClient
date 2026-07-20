namespace JASniffer.Core.Models;

/// <summary>
/// The full TLS ClientHello fingerprint of the <b>upstream</b> leg for one captured
/// request — the real JA3/JA4 the engine emits for the preset that re-issued it,
/// captured over loopback (past any TLS inspector) and stamped onto the session.
/// </summary>
/// <remarks>
/// This is the same detail the Info tab renders. It is persisted <em>per request</em>
/// so it survives a <c>.saz</c> export/import round-trip: a preset label alone can't
/// be turned back into a JA3, and a live scan isn't available when an archive captured
/// on another machine is re-opened. A plain, JSON-serializable value type (no engine or
/// transport dependency) so <see cref="JASniffer.Core.Export.SazExporter"/> can embed it
/// and the importer can read it back.
/// </remarks>
public sealed record SessionFingerprint
{
    /// <summary>Display label of the preset this fingerprint was emitted for, e.g. <c>Chrome 148</c>.</summary>
    public string Preset { get; init; } = string.Empty;

    /// <summary>Raw JA3 string (<c>version,ciphers,extensions,curves,pointformats</c>).</summary>
    public string Ja3 { get; init; } = string.Empty;

    /// <summary>MD5 of the JA3 string (the canonical JA3 hash).</summary>
    public string Ja3Md5 { get; init; } = string.Empty;

    /// <summary>JA4 TLS-client fingerprint (FoxIO spec).</summary>
    public string Ja4 { get; init; } = string.Empty;

    /// <summary>Highest offered TLS version, e.g. <c>TLS 1.3</c>.</summary>
    public string? TlsVersion { get; init; }

    public int CipherCount { get; init; }
    public int ExtensionCount { get; init; }
    public bool Tls13 { get; init; }
    public bool KeyShare { get; init; }
    public bool Grease { get; init; }
    public bool Sni { get; init; }

    public IReadOnlyList<int> Ciphers { get; init; } = [];
    public IReadOnlyList<int> Extensions { get; init; } = [];
    public IReadOnlyList<int> Curves { get; init; } = [];
    public IReadOnlyList<int> PointFormats { get; init; } = [];
    public IReadOnlyList<int> SupportedVersions { get; init; } = [];
    public IReadOnlyList<int> SignatureAlgorithms { get; init; } = [];
    public IReadOnlyList<string> Alpn { get; init; } = [];
}
