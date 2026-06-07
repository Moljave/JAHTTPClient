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
    private volatile bool _interceptAllPorts = true;
    private volatile bool _ignoreUpstreamCertErrors;
    private volatile string[] _bypassHosts = [];

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
    /// Hosts to pass through WITHOUT TLS interception (raw tunnel), one per line/comma.
    /// Use for endpoints that break under MITM (certificate pinning, etc.). A bare
    /// host matches it and all its subdomains (e.g. <c>ls.app</c> matches <c>cdn.ls.app</c>).
    /// Bypassed hosts still show in the list as a tunneled (uninspected) session.
    /// </summary>
    public string BypassHosts
    {
        get => string.Join("\n", _bypassHosts);
        set => _bypassHosts = (value ?? string.Empty)
            .Split(['\n', '\r', ',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(h => h.Trim().TrimStart('*', '.').ToLowerInvariant())
            .Where(h => h.Length > 0)
            .Distinct()
            .ToArray();
    }

    /// <summary>True when <paramref name="host"/> should be tunneled un-decrypted (exact or a subdomain).</summary>
    public bool IsBypassed(string host)
    {
        var patterns = _bypassHosts;
        if (patterns.Length == 0)
        {
            return false;
        }

        host = host.ToLowerInvariant();
        foreach (var p in patterns)
        {
            if (host == p || host.EndsWith("." + p, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Intercept (MITM) HTTPS on every CONNECT port, not just 443/8443 — needed to
    /// sniff local dev servers on non-standard ports (e.g. 3000, 5173, 9443).
    /// Defaults to true. Browser CONNECTs are always TLS, so this is safe for browser
    /// traffic; turn it off to raw-tunnel non-standard ports (for non-HTTP services).
    /// </summary>
    public bool InterceptAllPorts
    {
        get => _interceptAllPorts;
        set => _interceptAllPorts = value;
    }

    /// <summary>
    /// Don't verify the upstream server's TLS certificate — lets the proxy reach
    /// local dev servers (and others) with self-signed/invalid certificates without
    /// failing. Defaults to false; enable only when debugging trusted endpoints.
    /// </summary>
    public bool IgnoreUpstreamCertErrors
    {
        get => _ignoreUpstreamCertErrors;
        set => _ignoreUpstreamCertErrors = value;
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
