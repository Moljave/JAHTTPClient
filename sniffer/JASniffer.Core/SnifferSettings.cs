namespace JASniffer.Core;

/// <summary>
/// Live, mutable knobs that the UI flips at runtime. Reads are lock-free
/// (volatile) so the proxy hot-path can consult them per request without
/// contention; writes come from the (single) settings endpoint.
/// </summary>
public sealed class SnifferSettings
{
    private volatile bool _smartRedirects;
    private volatile int _maxRedirects = 10;
    private volatile bool _capture = true;
    private volatile string? _upstreamProxy;
    private volatile string _fingerprintPreset = "Chrome";
    private volatile bool _forceHttp1;

    /// <summary>
    /// When false (default, most faithful), the browser receives raw 3xx responses
    /// and follows them itself, so every hop is captured as its own session and the
    /// upstream client runs without a cookie jar. When true, the upstream client
    /// walks the redirect chain (carrying cookies across hops) and only the final
    /// response is returned to the browser.
    /// </summary>
    public bool SmartRedirects
    {
        get => _smartRedirects;
        set => _smartRedirects = value;
    }

    /// <summary>Maximum redirect hops the upstream client follows when <see cref="SmartRedirects"/> is on.</summary>
    public int MaxRedirects
    {
        get => _maxRedirects;
        set => _maxRedirects = Math.Clamp(value, 1, 50);
    }

    /// <summary>Master capture switch. When false, traffic is still proxied but not recorded into the session list.</summary>
    public bool Capture
    {
        get => _capture;
        set => _capture = value;
    }

    /// <summary>Optional upstream egress proxy applied to the JAHTTPClient leg (null = direct).</summary>
    public string? UpstreamProxy
    {
        get => _upstreamProxy;
        set => _upstreamProxy = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>
    /// Browser fingerprint to emulate upstream: one of <c>Chrome</c>, <c>ChromeLatest</c>,
    /// <c>Edge</c>, <c>Firefox</c>, <c>Safari</c>. Changing it rebuilds the upstream clients.
    /// </summary>
    public string FingerprintPreset
    {
        get => _fingerprintPreset;
        set => _fingerprintPreset = string.IsNullOrWhiteSpace(value) ? "Chrome" : value.Trim();
    }

    /// <summary>Force HTTP/1.1 upstream instead of negotiating HTTP/2 (some anti-bot setups prefer h1).</summary>
    public bool ForceHttp1
    {
        get => _forceHttp1;
        set => _forceHttp1 = value;
    }

    /// <summary>
    /// Hard cap on the body bytes retained in memory per direction. Larger bodies
    /// are truncated for the preview/inspector and flagged; this bounds memory for
    /// a long-running capture.
    /// </summary>
    public int MaxBodyBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>Upper bound on the number of sessions kept in the in-memory ring.</summary>
    public int MaxSessions { get; init; } = 20_000;

    /// <summary>
    /// The sniffer's own UI port. Loopback traffic to this port (the SPA, its REST
    /// calls and the SignalR socket) is proxied transparently but never recorded,
    /// so the session list isn't flooded with the tool's own localhost requests
    /// when the system proxy doesn't bypass loopback.
    /// </summary>
    public int SelfUiPort { get; init; }
}
