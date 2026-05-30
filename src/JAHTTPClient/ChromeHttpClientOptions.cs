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

    /// <summary>
    /// Disable HTTP keep-alive connection pooling (a fresh connection is dialed
    /// per request). <see langword="null"/> (default) means "auto": pooling is
    /// disabled automatically when <see cref="RotatingProxy"/> is set.
    /// </summary>
    /// <remarks>
    /// Pooled keep-alive connections are pinned to one proxy exit IP. When a
    /// rotating proxy rotates, a reused connection is already dead, so the next
    /// request fails with <c>EOF</c> — exactly the failure seen under heavy
    /// concurrency. Disabling reuse trades a little throughput for reliability.
    /// Set explicitly to <see langword="false"/> to keep pooling even with a
    /// rotating proxy (e.g. a sticky-session gateway).
    /// </remarks>
    public bool? DisableConnectionReuse { get; set; }

    /// <summary>
    /// How many times to transparently retry a request that fails at the
    /// transport level (no HTTP response received: DNS/connect/proxy drop/EOF/
    /// timeout) before surfacing the failure as <see cref="System.Net.Http.HttpRequestException"/>.
    /// Retries use exponential backoff with jitter; with a rotating proxy each
    /// retry re-dials a fresh exit IP. Defaults to 2. Set to 0 to disable.
    /// </summary>
    /// <remarks>
    /// Only transport failures are retried — a real HTTP response (including 4xx
    /// or 5xx) is always returned as-is and never retried.
    /// </remarks>
    public int MaxRetries { get; set; } = 2;

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
