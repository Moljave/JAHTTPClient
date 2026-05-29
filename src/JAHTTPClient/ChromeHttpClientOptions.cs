using System.Net;
using JAHTTPClient.Fingerprinting;

namespace JAHTTPClient;

/// <summary>
/// Configuration for a <see cref="ChromeHttpClient"/>. Mirrors the familiar
/// <c>HttpClientHandler</c> knobs so existing code migrates with minimal change.
/// </summary>
public sealed class ChromeHttpClientOptions
{
    /// <summary>
    /// When true, requests are sent with a spoofed browser TLS/HTTP2 fingerprint
    /// (<see cref="FingerprintPreset"/>). When false the native default profile
    /// is used. Defaults to true.
    /// </summary>
    public bool EnableJa3Fingerprinting { get; set; } = true;

    /// <summary>Which browser fingerprint to emulate. Defaults to <see cref="Ja3Preset.Chrome"/> (Chrome 148).</summary>
    public Ja3Preset FingerprintPreset { get; set; } = Ja3Preset.Chrome;

    /// <summary>
    /// Override the native TLS profile identifier (e.g. <c>"chrome_146"</c>)
    /// while keeping the preset's headers. Null = use the preset default.
    /// </summary>
    public string? TlsIdentifier { get; set; }

    /// <summary>Follow HTTP redirects automatically. Defaults to true.</summary>
    public bool AllowAutoRedirect { get; set; } = true;

    /// <summary>
    /// Maximum number of redirects to follow automatically. The response
    /// returned is the one produced at this hop (or earlier, if a non-3xx
    /// arrives first). Set to 1 to stop after the first redirect, etc.
    /// Defaults to 10. Ignored when <see cref="AllowAutoRedirect"/> is false.
    /// </summary>
    public int MaxAutomaticRedirections { get; set; } = 10;

    /// <summary>Proxy URL, e.g. <c>http://user:pass@host:port</c>. Null = direct.</summary>
    public string? Proxy { get; set; }

    /// <summary>Hint that <see cref="Proxy"/> rotates the exit IP per request.</summary>
    public bool RotatingProxy { get; set; }

    /// <summary>Per-request timeout. Defaults to 100 seconds (same as <see cref="System.Net.Http.HttpClient"/>).</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(100);

    /// <summary>Skip TLS certificate verification (e.g. when going through an intercepting proxy).</summary>
    public bool InsecureSkipVerify { get; set; }

    /// <summary>Force HTTP/1.1 instead of negotiating HTTP/2.</summary>
    public bool ForceHttp1 { get; set; }

    /// <summary>
    /// Optional cap on concurrent in-flight native requests. 0 (default) = no
    /// limit. Set a positive value to bound memory under extreme fan-out, since
    /// each in-flight request holds a managed thread blocked on the native call.
    /// </summary>
    public int MaxConcurrency { get; set; }

    /// <summary>Headers added to every request unless overridden per-request.</summary>
    public IDictionary<string, string> DefaultHeaders { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Optional seed cookies imported into the session jar on first use. Cookies
    /// gathered from responses are then persisted in the native jar automatically.
    /// </summary>
    public CookieContainer? Cookies { get; set; }
}
