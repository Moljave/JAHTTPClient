using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;
using JASniffer.Core;
using JASniffer.Core.Models;
using JASniffer.Core.Parsing;

namespace JASniffer.Proxy;

/// <summary>
/// Re-issues intercepted requests upstream through <c>JAHTTPClient</c> so the
/// outgoing leg carries a genuine Chrome 148 TLS (JA3/JA4) + HTTP/2 fingerprint,
/// and records both legs into a <see cref="CapturedSession"/>.
/// </summary>
/// <remarks>
/// Two long-lived, thread-safe clients are kept so the UI's "smart redirects"
/// toggle is honored per request with the right cookie semantics, without ever
/// rebuilding a client (which would drop its connection pool):
/// <list type="bullet">
/// <item><b>faithful</b> — redirects off, <b>cookie jar off</b>: the browser gets
/// raw 3xx responses and follows them itself, each hop captured separately, and
/// the upstream request carries exactly the browser's cookies (no contamination).</item>
/// <item><b>follow</b> — redirects on, request-scoped cookies: the chain is walked
/// upstream carrying Set-Cookie across hops in per-request managed state (the shared
/// native jar is bypassed, so tabs/requests never cross-contaminate) and only the
/// final response returns.</item>
/// </list>
/// </remarks>
public sealed record ProxyTestResult(bool Ok, string? Ip = null, string? Proxy = null, string? Error = null);

public sealed class UpstreamRelay : IDisposable
{
    // Content headers must live on HttpContent, not the request; Content-Length is
    // recomputed by ByteArrayContent, so it is never forwarded verbatim.
    private static readonly HashSet<string> SkippedRequestHeaders =
        new(StringComparer.OrdinalIgnoreCase) { "Host", "Content-Length", "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization" };

    private readonly SnifferSettings _settings;
    private readonly Lock _swap = new();
    private readonly ConcurrentDictionary<string, string?> _hostIpCache = new(StringComparer.OrdinalIgnoreCase);

    // Swapped atomically by Reconfigure when the fingerprint preset or forced HTTP
    // version changes (both are baked at client construction in the engine). volatile so
    // a concurrent RelayAsync reading them lock-free observes the post-swap instance.
    private volatile TlsClientChromeHttpClient _faithful;
    private volatile TlsClientChromeHttpClient _follow;
    private Ja3Preset _preset;
    private bool _forceHttp1;
    private bool _insecure;
    private string? _proxyUrl;
    private bool _proxyRotating;

    /// <summary>Display label for the active fingerprint preset, e.g. <c>Chrome 148</c>.</summary>
    public string CurrentPresetLabel { get; private set; }

    public UpstreamRelay(SnifferSettings settings)
    {
        _settings = settings;
        _preset = ParsePreset(settings.FingerprintPreset);
        _forceHttp1 = settings.ForceHttp1;
        _insecure = settings.IgnoreUpstreamCertErrors;
        _proxyUrl = settings.UpstreamProxy;
        _proxyRotating = settings.RotatingProxy;
        CurrentPresetLabel = LabelFor(_preset);
        (_faithful, _follow) = BuildClients(_preset, _forceHttp1, _insecure, settings.MaxRedirects);
        ApplyProxyToClients();
    }

    /// <summary>
    /// Rebuilds the two upstream clients with a new fingerprint preset / forced HTTP
    /// version / cert-verification setting (no-op if unchanged). The engine bakes
    /// these at construction, so a rebuild is required; old clients are disposed after
    /// a short grace so in-flight requests can finish.
    /// </summary>
    public void Reconfigure(string presetName, bool forceHttp1, bool insecure)
    {
        var preset = ParsePreset(presetName);
        lock (_swap)
        {
            if (preset == _preset && forceHttp1 == _forceHttp1 && insecure == _insecure)
            {
                return;
            }

            var (newFaithful, newFollow) = BuildClients(preset, forceHttp1, insecure, _settings.MaxRedirects);
            var oldFaithful = _faithful;
            var oldFollow = _follow;

            _faithful = newFaithful;
            _follow = newFollow;
            _preset = preset;
            _forceHttp1 = forceHttp1;
            _insecure = insecure;
            CurrentPresetLabel = LabelFor(preset);
            ApplyProxyToClients(); // the fresh clients start direct — restore the egress proxy

            // Dispose the superseded clients after a grace longer than the request
            // timeout (100 s), so a request still in flight on an old client finishes (or
            // times out) before its client is disposed — never an ObjectDisposedException.
            _ = Task.Delay(TimeSpan.FromSeconds(120)).ContinueWith(_ =>
            {
                try { oldFaithful.Dispose(); oldFollow.Dispose(); } catch { /* best effort */ }
            }, TaskScheduler.Default);
        }
    }

    private static (TlsClientChromeHttpClient Faithful, TlsClientChromeHttpClient Follow) BuildClients(
        Ja3Preset preset, bool forceHttp1, bool insecure, int maxRedirects)
    {
        var faithful = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = preset,
            AllowAutoRedirect = false,
            WithoutCookieJar = true,
            ForceHttp1 = forceHttp1,
            InsecureSkipVerify = insecure,
            Timeout = TimeSpan.FromSeconds(100),
        });

        var follow = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = preset,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = maxRedirects,
            // Carry Set-Cookie across the redirect chain in request-scoped state (native
            // jar off) so this shared client never leaks cookies between tabs/requests.
            IsolateRedirectCookies = true,
            ForceHttp1 = forceHttp1,
            InsecureSkipVerify = insecure,
            Timeout = TimeSpan.FromSeconds(100),
        });

        return (faithful, follow);
    }

    private static Ja3Preset ParsePreset(string? name)
        => Enum.TryParse<Ja3Preset>(name, ignoreCase: true, out var preset) ? preset : Ja3Preset.Chrome;

    private static string LabelFor(Ja3Preset preset) => preset switch
    {
        Ja3Preset.Chrome => "Chrome 148",
        Ja3Preset.ChromeLatest => "Chrome 146",
        Ja3Preset.Edge => "Edge",
        Ja3Preset.Firefox => "Firefox",
        Ja3Preset.Safari => "Safari",
        _ => preset.ToString(),
    };

    /// <summary>
    /// Captures the engine's real ClientHello over loopback for the active preset and
    /// returns its JA3 — interception-proof local verification of the TLS fingerprint.
    /// </summary>
    public Task<Ja3Report> CaptureClientHelloAsync(CancellationToken ct)
        => Ja3SelfTest.CaptureAsync(_preset, _forceHttp1, CurrentPresetLabel, ct);

    /// <summary>
    /// Builds and sends a request composed in the UI's Requester through the upstream
    /// client (current fingerprint/settings), recording it as a session. Returns its id.
    /// </summary>
    public async Task<int> ComposeAsync(
        SessionStore store, string method, string url, IReadOnlyList<HeaderEntry> headers, byte[] body, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new ArgumentException("URL must be an absolute http(s) URL.");
        }

        var request = new ProxyRequest
        {
            Method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant(),
            Scheme = uri.Scheme,
            Host = uri.Host,
            Port = uri.Port,
            Path = uri.AbsolutePath,
            Query = uri.Query,
            Url = uri.AbsoluteUri,
            HttpVersion = "1.1",
            Headers = [.. headers],
            Body = body,
        };

        var session = new CapturedSession
        {
            Id = store.NextId(),
            Method = request.Method,
            Scheme = request.Scheme,
            Host = request.Host,
            Port = request.Port,
            Path = request.Path,
            Query = request.Query,
            Url = request.Url,
            RequestHttpVersion = "1.1",
            RequestHeaders = request.Headers,
            RequestBody = body,
            RequestContentType = HttpParsing.FirstHeader(request.Headers, "Content-Type"),
            ClientEndpoint = "composer",
            FingerprintPreset = CurrentPresetLabel,
        };

        store.Add(session);
        await RelayAsync(request, session, ct).ConfigureAwait(false);
        store.Update(session);
        return session.Id;
    }

    /// <summary>
    /// Sends <paramref name="request"/> upstream, records the exchange into
    /// <paramref name="session"/>, and returns the bytes/status to write back to the
    /// browser. Never throws for transport failures — those become a 502 plus
    /// <see cref="CapturedSession.Error"/>.
    /// </summary>
    internal async Task<RelayResult> RelayAsync(ProxyRequest request, CapturedSession session, CancellationToken ct)
    {
        var follow = _settings.SmartRedirects;
        var client = follow ? _follow : _faithful;

        if (follow)
        {
            client.MaxAutomaticRedirections = _settings.MaxRedirects;
        }

        session.FollowedRedirects = follow;
        session.HostIp = ResolveHostIp(request.Host);

        var sw = Stopwatch.StartNew();
        try
        {
            using var upstream = BuildUpstreamRequest(request);
            using var response = await client.SendAsync(upstream, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            sw.Stop();

            return RecordSuccess(request, session, response, body, sw.Elapsed.TotalMilliseconds);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            sw.Stop();
            session.DurationMs = sw.Elapsed.TotalMilliseconds;
            session.Completed = true;
            session.UpstreamOk = false;
            session.Error = ex.Message;
            session.StatusCode = 502;
            session.ReasonPhrase = "Bad Gateway";
            session.ResponseHttpVersion = string.Empty;
            session.FinalUrl = request.Url;
            return RelayResult.Gateway502(ex.Message);
        }
    }

    private RelayResult RecordSuccess(
        ProxyRequest request, CapturedSession session, HttpResponseMessage response, byte[] body, double elapsedMs)
    {
        var responseHeaders = CollectResponseHeaders(response);
        var contentType = HttpParsing.FirstHeader(responseHeaders, "Content-Type");
        var httpVersion = response.Version.Major >= 2 ? "2.0" : "1.1";

        session.DurationMs = elapsedMs;
        session.Completed = true;
        session.UpstreamOk = true;
        session.StatusCode = (int)response.StatusCode;
        session.ReasonPhrase = response.ReasonPhrase;
        session.ResponseHttpVersion = httpVersion;
        session.ResponseHeaders = responseHeaders;
        session.ResponseContentType = contentType;
        session.BodyLength = body.LongLength;
        session.ResponseBody = Cap(body, out var truncated);
        session.ResponseBodyTruncated = truncated;
        session.FinalUrl = response.RequestMessage?.RequestUri?.ToString() ?? request.Url;
        session.FingerprintPreset = CurrentPresetLabel;
        session.TlsSummary = $"{CurrentPresetLabel} · HTTP/{httpVersion} · TLS 1.3 (assumed)";

        return new RelayResult
        {
            Status = (int)response.StatusCode,
            Reason = response.ReasonPhrase ?? string.Empty,
            Headers = responseHeaders,
            Body = body,
        };
    }

    private HttpRequestMessage BuildUpstreamRequest(ProxyRequest request)
    {
        var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);

        byte[]? body = request.Body.Length > 0 ? request.Body : null;
        if (body is not null)
        {
            message.Content = new ByteArrayContent(body);
            message.Content.Headers.Clear();
        }

        foreach (var (name, value) in request.Headers)
        {
            if (name.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) || SkippedRequestHeaders.Contains(name))
            {
                continue;
            }

            if (IsContentHeader(name))
            {
                // Content headers (Content-Type, Content-Encoding, …) belong on the
                // body; skip them when there is no body to attach them to.
                message.Content?.Headers.TryAddWithoutValidation(name, value);
            }
            else
            {
                message.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return message;
    }

    /// <summary>
    /// Hot-swaps the upstream egress proxy on both clients (cookies/connection pool
    /// preserved). Call when the proxy setting changes. <paramref name="url"/> must
    /// already be canonical (<see cref="ProxyUrl.Normalize"/>) or null for direct.
    /// </summary>
    public void ApplyProxy(string? url, bool rotating)
    {
        lock (_swap)
        {
            _proxyUrl = url;
            _proxyRotating = rotating;
            ApplyProxyToClients();
        }
    }

    private void ApplyProxyToClients()
    {
        try
        {
            _faithful.SetProxy(_proxyUrl, _proxyRotating);
            _follow.SetProxy(_proxyUrl, _proxyRotating);
        }
        catch (ArgumentException)
        {
            // Defensive: a malformed value never breaks the relay (go direct).
        }
    }

    /// <summary>
    /// Sends a probe through <paramref name="proxyInput"/> and reports the egress IP,
    /// so the UI can confirm a pasted proxy actually works.
    /// </summary>
    public async Task<ProxyTestResult> TestProxyAsync(string? proxyInput, CancellationToken ct)
    {
        var url = ProxyUrl.Normalize(proxyInput);
        if (!string.IsNullOrWhiteSpace(proxyInput) && url is null)
        {
            return new ProxyTestResult(false, Error: "Не удалось разобрать строку прокси.");
        }

        using var probe = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = _preset,
            Proxy = url,
            RotatingProxy = _proxyRotating,
            InsecureSkipVerify = _insecure,
            Timeout = TimeSpan.FromSeconds(20),
            MaxRetries = 0,
        });

        try
        {
            using var r = await probe.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://api.ipify.org/?format=text"), ct).ConfigureAwait(false);
            var ip = (await r.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();
            return new ProxyTestResult((int)r.StatusCode == 200, ip, url);
        }
        catch (Exception ex)
        {
            return new ProxyTestResult(false, Proxy: url, Error: ex.Message);
        }
    }

    private string? ResolveHostIp(string host)
    {
        // Only successful lookups are cached: caching a null would let one transient DNS
        // failure blank a host's IP for the whole process lifetime.
        if (_hostIpCache.TryGetValue(host, out var cached))
        {
            return cached;
        }

        if (IPAddress.TryParse(host, out var literal))
        {
            return _hostIpCache[host] = literal.ToString();
        }

        try
        {
            var addrs = Dns.GetHostAddresses(host);
            if (addrs.Length > 0)
            {
                return _hostIpCache[host] = addrs[0].ToString();
            }
        }
        catch (Exception)
        {
            // Transient/unresolvable — leave it uncached so a later request retries.
        }

        return null;
    }

    private byte[] Cap(byte[] body, out bool truncated)
    {
        if (body.Length <= _settings.MaxBodyBytes)
        {
            truncated = false;
            return body;
        }

        truncated = true;
        return body[.._settings.MaxBodyBytes];
    }

    private static List<HeaderEntry> CollectResponseHeaders(HttpResponseMessage response)
    {
        var headers = new List<HeaderEntry>();
        foreach (var (name, values) in response.Headers)
        {
            foreach (var value in values)
            {
                headers.Add(new HeaderEntry(name, value));
            }
        }

        if (response.Content is not null)
        {
            foreach (var (name, values) in response.Content.Headers)
            {
                foreach (var value in values)
                {
                    headers.Add(new HeaderEntry(name, value));
                }
            }
        }

        return headers;
    }


    private static bool IsContentHeader(string name)
        => name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _faithful.Dispose();
        _follow.Dispose();
    }
}
