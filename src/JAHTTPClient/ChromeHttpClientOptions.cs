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
    /// Run requests without the per-session cookie jar: server <c>Set-Cookie</c>
    /// headers are neither persisted nor auto-replayed, and only the cookies the
    /// caller puts on the request (e.g. a verbatim <c>Cookie</c> header) are sent.
    /// Defaults to false (the persistent jar is used).
    /// </summary>
    /// <remarks>
    /// This is what a faithful intercepting proxy wants: the upstream request must
    /// carry exactly the cookies the browser sent — no more, no less — so a shared
    /// client never contaminates one host/tab with another's cookies. The native
    /// tls-client contract supports this per request (<c>withoutCookieJar</c>).
    /// Note that with the jar disabled, managed redirect following no longer
    /// carries <c>Set-Cookie</c> values across hops, so leave it false when you rely
    /// on <see cref="AllowAutoRedirect"/> to walk a chain — or use
    /// <see cref="IsolateRedirectCookies"/> to carry them in request-scoped state.
    /// </remarks>
    public bool WithoutCookieJar { get; set; }

    /// <summary>
    /// Walk an automatic redirect chain carrying <c>Set-Cookie</c> across hops in
    /// <b>request-scoped</b> managed state instead of the shared per-session jar. The
    /// native jar is bypassed entirely (as if <see cref="WithoutCookieJar"/> were set),
    /// so cookies set during one request's redirect chain are honored on its later hops
    /// but never persist into other requests on the same client. Defaults to false.
    /// </summary>
    /// <remarks>
    /// This is what a shared intercepting-proxy client wants when it follows redirects:
    /// correct within-chain cookie behavior (login/SSO flows that set a cookie then
    /// redirect) with no cross-request/cross-tab contamination, and no need to rebuild
    /// the client (which would drop its connection pool). Cookies are scoped per host by
    /// the BCL <see cref="CookieContainer"/>; the caller's verbatim <c>Cookie</c> header
    /// seeds the chain for the initial host. Has no effect when
    /// <see cref="AllowAutoRedirect"/> is false.
    /// </remarks>
    public bool IsolateRedirectCookies { get; set; }

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
