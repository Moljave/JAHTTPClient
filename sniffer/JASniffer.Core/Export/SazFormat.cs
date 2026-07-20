using System.Text.Json;

namespace JASniffer.Core.Export;

/// <summary>
/// Shared conventions for JASniffer's <c>.saz</c> extensions, so <see cref="SazExporter"/>
/// (write) and <see cref="SazImporter"/> (read) never drift on file names, flag names or
/// JSON options. Everything here is additive: a stock Fiddler reader ignores the extra
/// <c>raw/NNN_f.json</c> sidecar and the <c>x-jasniffer-*</c> session flags, while JASniffer
/// uses them to round-trip the full per-request fingerprint and session metadata that
/// Fiddler's format doesn't model (scheme, absolute URL, timing, JA3/JA4 detail).
/// </summary>
internal static class SazFormat
{
    /// <summary>
    /// JSON options shared by write and read of the fingerprint sidecar so it round-trips
    /// exactly. Web defaults = camelCase property names + case-insensitive reads.
    /// </summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>Per-request full-fingerprint sidecar: <c>raw/NNN_f.json</c>.</summary>
    public static string FingerprintPath(string n) => $"raw/{n}_f.json";

    // Custom <SessionFlag> names carrying the session metadata Fiddler's format has no slot
    // for. Import prefers these; a foreign (stock-Fiddler) archive without them is imported
    // best-effort by inferring scheme/URL from the Host header and egress port.
    public const string FlagScheme = "x-jasniffer-scheme";
    public const string FlagHost = "x-jasniffer-host";
    public const string FlagUrl = "x-jasniffer-url";
    public const string FlagFinalUrl = "x-jasniffer-finalurl";
    public const string FlagDurationMs = "x-jasniffer-durationms";
    public const string FlagReqHttp = "x-jasniffer-reqhttp";
    public const string FlagRespHttp = "x-jasniffer-resphttp";
    public const string FlagPreset = "x-jasniffer-preset";
    public const string FlagUpstreamOk = "x-jasniffer-upstreamok";
    public const string FlagError = "x-jasniffer-error";
    public const string FlagTlsSummary = "x-jasniffer-tlssummary";

    // Human-readable fingerprint summary (also machine-usable): the full detail lives in the
    // JSON sidecar, but these keep JA3/JA4 visible in a stock Fiddler's session-flags view.
    public const string FlagJa3 = "x-jasniffer-ja3";
    public const string FlagJa3Md5 = "x-jasniffer-ja3md5";
    public const string FlagJa4 = "x-jasniffer-ja4";
    public const string FlagTls = "x-jasniffer-tls";
}
