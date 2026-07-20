using System.Net;
using JAHTTPClient.Cookies;
using JAHTTPClient.Fingerprinting;
using JAHTTPClient.Interop;
using JAHTTPClient.Native;

namespace JAHTTPClient;

/// <summary>
/// Default <see cref="ChromeHttpClient"/> implementation backed by the native
/// tls-client (utls) library via P/Invoke.
/// </summary>
/// <remarks>
/// <para>
/// Each instance owns a native session id, which gives it an isolated, persistent
/// cookie jar and connection pool. Dispose the client to release the session.
/// </para>
/// <para>
/// Instances are thread-safe and designed for heavy fan-out: the native layer
/// performs the real asynchronous network I/O, so a single client can drive
/// thousands of concurrent requests. <see cref="ChromeHttpClientOptions.MaxConcurrency"/>
/// optionally bounds in-flight requests.
/// </para>
/// </remarks>
public sealed class TlsClientChromeHttpClient : ChromeHttpClient
{
    // Content-headers that the native body transform already accounts for, so we
    // must not copy them verbatim onto the rebuilt managed response content.
    private static readonly HashSet<string> SkippedResponseContentHeaders =
        new(StringComparer.OrdinalIgnoreCase) { "Content-Length", "Content-Encoding" };

    // Connection-specific / hop-by-hop headers. HTTP/2 forbids them and the
    // native h2 transport rejects the whole request if one is present (e.g.
    // "http2: invalid Connection request header"). Real browsers never carry
    // these on an h2 request — the transport owns them — so we strip them unless
    // HTTP/1.1 is forced.
    private static readonly HashSet<string> Http2ForbiddenHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "TE",
        };

    private readonly ChromeHttpClientOptions _options;
    private readonly FingerprintProfile _profile;
    private readonly string _sessionId;
    private readonly ChromeCookieContainer _cookies;
    private readonly SemaphoreSlim? _throttle;
    private readonly Dictionary<string, string> _defaultHeaders;

    // Live redirect policy, seeded from options but mutable at runtime so callers
    // can toggle redirect following between requests.
    private volatile bool _allowAutoRedirect;
    private int _maxAutomaticRedirections;

    // Live egress, seeded from options but hot-swappable at runtime. The native
    // tls-client re-points the session's transport when the proxy URL changes.
    private volatile string? _proxy;
    private volatile bool _rotatingProxy;

    private int _seeded;
    private bool _disposed;

    static TlsClientChromeHttpClient()
    {
        // Each in-flight request blocks one managed thread on the native call.
        // Raise the floor so massive fan-out doesn't stall on slow thread-pool
        // ramp-up.
        ThreadPool.GetMinThreads(out var worker, out var io);
        ThreadPool.SetMinThreads(Math.Max(worker, 512), Math.Max(io, 512));
    }

    /// <summary>Creates a client with the given options (or Chrome 148 defaults).</summary>
    public TlsClientChromeHttpClient(ChromeHttpClientOptions? options = null)
    {
        _options = options ?? new ChromeHttpClientOptions();
        _profile = FingerprintProfiles.Resolve(_options.FingerprintPreset, _options.TlsIdentifier);
        _sessionId = Guid.NewGuid().ToString("N");
        _cookies = new ChromeCookieContainer(_sessionId);
        _defaultHeaders = new Dictionary<string, string>(_options.DefaultHeaders, StringComparer.OrdinalIgnoreCase);
        _allowAutoRedirect = _options.AllowAutoRedirect;
        _maxAutomaticRedirections = _options.MaxAutomaticRedirections;
        _proxy = string.IsNullOrWhiteSpace(_options.Proxy) ? null : _options.Proxy;
        _rotatingProxy = _options.RotatingProxy;

        if (_options.MaxConcurrency > 0)
        {
            _throttle = new SemaphoreSlim(_options.MaxConcurrency, _options.MaxConcurrency);
        }
    }

    /// <inheritdoc />
    public override ChromeCookieContainer Cookies => _cookies;

    /// <inheritdoc />
    public override IDictionary<string, string> DefaultRequestHeaders => _defaultHeaders;

    /// <inheritdoc />
    public override bool AllowAutoRedirect
    {
        get => _allowAutoRedirect;
        set => _allowAutoRedirect = value;
    }

    /// <inheritdoc />
    public override int MaxAutomaticRedirections
    {
        get => Volatile.Read(ref _maxAutomaticRedirections);
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            Volatile.Write(ref _maxAutomaticRedirections, value);
        }
    }

    /// <inheritdoc />
    public override string? Proxy => _proxy;

    /// <inheritdoc />
    public override void SetProxy(string? proxyUrl, bool? rotating = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var normalized = string.IsNullOrWhiteSpace(proxyUrl) ? null : proxyUrl.Trim();
        if (normalized is not null && !Uri.TryCreate(normalized, UriKind.Absolute, out _))
        {
            throw new ArgumentException(
                $"Proxy must be an absolute URI like \"http://user:pass@host:port\" or \"socks5://host:port\" (got: \"{proxyUrl}\").",
                nameof(proxyUrl));
        }

        _proxy = normalized;
        if (rotating is { } r)
        {
            _rotatingProxy = r;
        }
    }

    /// <inheritdoc />
    public override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestUri is null)
        {
            throw new InvalidOperationException("HttpRequestMessage.RequestUri must be set.");
        }

        SeedCookiesOnce(request.RequestUri);

        var method = request.Method;
        var currentUri = request.RequestUri;
        var orderedHeaders = CollectHeaders(request);
        var (body, isByteBody) = await ReadBodyAsync(request, cancellationToken).ConfigureAwait(false);

        // Request-scoped cookie carrying: when isolating, a fresh container walks the
        // redirect chain so Set-Cookie is honored across hops without ever touching the
        // shared native jar — a shared client can't contaminate one request/tab with
        // another's cookies. Seeded from the caller's verbatim Cookie header.
        var chainCookies = _options.IsolateRedirectCookies ? new CookieContainer() : null;
        if (chainCookies is not null)
        {
            SeedChainCookies(chainCookies, currentUri, orderedHeaders);
        }

        var redirects = 0;
        while (true)
        {
            if (chainCookies is not null)
            {
                ApplyChainCookies(chainCookies, currentUri, orderedHeaders);
            }

            var payload = BuildPayload(method, currentUri, orderedHeaders, body, isByteBody);
            var response = await ExecuteWithRetryAsync(payload, cancellationToken).ConfigureAwait(false);

            // Mirror this hop's Set-Cookie headers so Cookies.GetCookiesJson() can
            // export full metadata even though the native jar only reads back
            // name→value pairs.
            _cookies.CaptureResponseCookies(currentUri, response.Headers);
            if (chainCookies is not null)
            {
                CaptureChainCookies(chainCookies, currentUri, response.Headers);
            }

            var location = ExtractLocation(response);
            if (location is not null &&
                ShouldRedirect(response.Status, redirects) &&
                Uri.TryCreate(currentUri, location, out var next))
            {
                redirects++;
                // Apply browser redirect method/body semantics for the next hop.
                (method, body, isByteBody) = NextHop(method, response.Status, body, isByteBody, orderedHeaders);
                orderedHeaders["referer"] = currentUri.ToString();
                currentUri = next;
                continue;
            }

            return BuildResponse(response, request, method, currentUri);
        }
    }

    // ---- payload construction ---------------------------------------------

    private TlsRequestPayload BuildPayload(
        HttpMethod method,
        Uri uri,
        Dictionary<string, string> headers,
        string? body,
        bool isByteBody)
    {
        var merged = NormalizeHeaders(MergeFingerprintHeaders(uri, headers), _options.ForceHttp1);
        var hasCustom = _profile.CustomTlsSpec is not null;

        return new TlsRequestPayload
        {
            SessionId = _sessionId,
            // Named profile OR a fully custom TLS/H2 spec — mutually exclusive in the native API.
            // Custom profiles pin the exact ClientHello, so extension-order shuffling is disabled.
            TlsClientIdentifier = hasCustom ? null : _profile.TlsIdentifier,
            CustomTlsClient = _profile.CustomTlsSpec,
            RequestUrl = uri.AbsoluteUri,
            RequestMethod = method.Method,
            RequestBody = body,
            IsByteRequest = isByteBody,
            IsByteResponse = true, // lossless: native returns base64, we decode to bytes
            Headers = merged,
            HeaderOrder = BuildHeaderOrder(merged),
            FollowRedirects = false, // redirects handled in managed code
            InsecureSkipVerify = _options.InsecureSkipVerify,
            // A faithful sniffing proxy opts out of the jar so a shared client only
            // ever sends the cookies the caller put on the request (the browser's
            // verbatim Cookie header) and never cross-contaminates hosts/tabs.
            // Isolated-redirect mode likewise bypasses the native jar — it carries
            // cookies across hops in request-scoped managed state instead.
            WithDefaultCookieJar = !(_options.WithoutCookieJar || _options.IsolateRedirectCookies),
            WithoutCookieJar = _options.WithoutCookieJar || _options.IsolateRedirectCookies,
            // Don't shuffle extensions for custom profiles — the exact order is already pinned
            // in the JA3 string and the native library respects it for customTlsClient.
            WithRandomTlsExtensionOrder = _options.EnableJa3Fingerprinting && !hasCustom,
            ForceHttp1 = _options.ForceHttp1,
            TimeoutMilliseconds = (int)Math.Clamp(_options.Timeout.TotalMilliseconds, 1, int.MaxValue),
            ProxyUrl = _proxy,
            IsRotatingProxy = _rotatingProxy,
            // Pooled keep-alive connections are bound to one proxy exit IP; reusing
            // one after a rotating proxy rotates yields EOF. Disable pooling so each
            // request dials fresh. Defaults on for rotating proxies, overridable.
            TransportOptions = (_options.DisableConnectionReuse ?? _rotatingProxy)
                ? new TransportOptions { DisableKeepAlives = true }
                : null,
        };
    }

    /// <summary>Layers fingerprint client-hints under the user's headers (user wins on conflict).</summary>
    private Dictionary<string, string> MergeFingerprintHeaders(Uri uri, Dictionary<string, string> headers)
    {
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (_options.EnableJa3Fingerprinting)
        {
            AddIfMissing(merged, "user-agent", _profile.UserAgent);
            AddIfMissing(merged, "sec-ch-ua", _profile.SecChUa);
            AddIfMissing(merged, "sec-ch-ua-mobile", _profile.SecChUaMobile);
            AddIfMissing(merged, "sec-ch-ua-platform", _profile.SecChUaPlatform);
        }

        foreach (var (k, v) in _defaultHeaders)
        {
            merged[k] = v;
        }

        foreach (var (k, v) in headers)
        {
            merged[k] = v;
        }

        return merged;

        static void AddIfMissing(IDictionary<string, string> d, string k, string v)
        {
            if (!string.IsNullOrEmpty(v))
            {
                d[k] = v;
            }
        }
    }

    /// <summary>
    /// Defends the outgoing header set against two real-world hazards before it
    /// reaches the native transport:
    /// <list type="number">
    /// <item>Values that smuggled an entire header block via embedded CR/LF —
    /// common when a raw devtools/Burp paste is added as a single header — are
    /// unfolded back into the discrete headers the caller meant.</item>
    /// <item>Connection-specific headers that HTTP/2 forbids are dropped (unless
    /// HTTP/1.1 is forced), since the Go h2 transport rejects the request
    /// outright when it sees e.g. <c>Connection</c>.</item>
    /// </list>
    /// </summary>
    private static Dictionary<string, string> NormalizeHeaders(Dictionary<string, string> headers, bool forceHttp1)
    {
        var result = headers;

        if (HasLineBreak(headers))
        {
            result = new Dictionary<string, string>(headers.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var (name, value) in headers)
            {
                if (value.IndexOf('\n') < 0 && value.IndexOf('\r') < 0)
                {
                    result[name] = value;
                    continue;
                }

                Unfold(result, name, value);
            }
        }

        if (!forceHttp1)
        {
            foreach (var forbidden in Http2ForbiddenHeaders)
            {
                result.Remove(forbidden);
            }
        }

        return result;
    }

    private static bool HasLineBreak(Dictionary<string, string> headers)
    {
        foreach (var value in headers.Values)
        {
            if (value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Splits a folded <c>"value\nName: Value\n..."</c> blob back into discrete
    /// headers. The first physical line stays as <paramref name="name"/>'s value;
    /// each subsequent <c>"Name: Value"</c> line becomes its own header, and a
    /// continuation line with no colon is appended to the header being built.
    /// </summary>
    private static void Unfold(Dictionary<string, string> target, string name, string value)
    {
        var lastName = name;
        var first = true;

        foreach (var rawLine in value.Split('\n'))
        {
            var line = rawLine.Trim('\r', ' ', '\t');

            if (first)
            {
                target[name] = line;
                first = false;
                continue;
            }

            if (line.Length == 0)
            {
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                // Obs-fold continuation line: append to the header being built.
                target[lastName] = target.TryGetValue(lastName, out var prev) && prev.Length > 0
                    ? $"{prev} {line}"
                    : line;
                continue;
            }

            var headerName = line[..colon].Trim();
            if (headerName.Length == 0)
            {
                continue;
            }

            target[headerName] = line[(colon + 1)..].Trim();
            lastName = headerName;
        }
    }

    /// <summary>Builds the emission order: canonical browser order first, then any extras.</summary>
    private List<string> BuildHeaderOrder(Dictionary<string, string> headers)
    {
        var order = new List<string>(headers.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in _profile.HeaderOrder)
        {
            if (headers.ContainsKey(name) && seen.Add(name))
            {
                order.Add(name);
            }
        }

        foreach (var name in headers.Keys)
        {
            if (seen.Add(name))
            {
                order.Add(name);
            }
        }

        return order;
    }

    /// <summary>Collects request + content headers preserving insertion order.</summary>
    private static Dictionary<string, string> CollectHeaders(HttpRequestMessage request)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in request.Headers)
        {
            headers[header.Key] = string.Join(", ", header.Value);
        }

        if (request.Content is not null)
        {
            foreach (var header in request.Content.Headers)
            {
                headers[header.Key] = string.Join(", ", header.Value);
            }
        }

        return headers;
    }

    private static async Task<(string? body, bool isByte)> ReadBodyAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Content is null)
        {
            return (null, false);
        }

        var bytes = await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (bytes.Length == 0)
        {
            return (string.Empty, false);
        }

        // Send textual bodies as-is; otherwise base64 + isByteRequest for fidelity.
        return IsTextual(request.Content.Headers.ContentType?.MediaType)
            ? (System.Text.Encoding.UTF8.GetString(bytes), false)
            : (Convert.ToBase64String(bytes), true);
    }

    private static bool IsTextual(string? mediaType)
    {
        if (string.IsNullOrEmpty(mediaType))
        {
            return true; // form-url-encoded / plain by default
        }

        return mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
            || mediaType.Contains("json", StringComparison.OrdinalIgnoreCase)
            || mediaType.Contains("xml", StringComparison.OrdinalIgnoreCase)
            || mediaType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || mediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase);
    }

    // ---- native execution --------------------------------------------------

    /// <summary>
    /// Runs one hop, transparently retrying transport-level failures (no HTTP
    /// response received — DNS/connect/proxy drop/EOF/timeout) up to
    /// <see cref="ChromeHttpClientOptions.MaxRetries"/> times with jittered
    /// backoff. A genuine HTTP response (any status) is returned immediately;
    /// exhausted transport failures surface as <see cref="HttpRequestException"/>.
    /// </summary>
    private async Task<TlsResponsePayload> ExecuteWithRetryAsync(TlsRequestPayload payload, CancellationToken ct)
    {
        var maxAttempts = Math.Max(1, _options.MaxRetries + 1);
        TlsResponsePayload response = null!;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            response = await ExecuteAsync(payload, ct).ConfigureAwait(false);

            if (!IsTransportFailure(response))
            {
                return response;
            }

            if (attempt < maxAttempts)
            {
                // Re-dialing usually lands on a fresh rotating-proxy exit IP, which
                // clears the transient connection drop.
                await Task.Delay(RetryBackoff(attempt), ct).ConfigureAwait(false);
            }
        }

        throw new HttpRequestException(TransportErrorMessage(response));
    }

    // tls-client reports a pre-response failure (DNS/connect/proxy/EOF/timeout) as
    // status 0 with the Go error text in the body and no headers; a real HTTP
    // exchange always carries a non-zero status.
    private static bool IsTransportFailure(TlsResponsePayload response) => response.Status == 0;

    private static string TransportErrorMessage(TlsResponsePayload response)
        => string.IsNullOrWhiteSpace(response.Body)
            ? "The native tls-client transport failed before receiving a response."
            : response.Body!.Trim();

    private static TimeSpan RetryBackoff(int attempt)
    {
        // Exponential backoff with jitter so a burst of concurrent failures (a
        // saturated rotating proxy) doesn't retry in lockstep.
        var baseMs = 50 * (1 << Math.Min(attempt - 1, 5)); // 50,100,200,…,1600 cap
        return TimeSpan.FromMilliseconds(baseMs + Random.Shared.Next(0, baseMs / 2 + 1));
    }

    private async Task<TlsResponsePayload> ExecuteAsync(TlsRequestPayload payload, CancellationToken ct)
    {
        if (_throttle is not null)
        {
            await _throttle.WaitAsync(ct).ConfigureAwait(false);
        }

        try
        {
            // The native call is blocking; offload it so we never block the caller.
            return await Task.Run(() => TlsClientNative.Request(payload), ct).ConfigureAwait(false);
        }
        finally
        {
            _throttle?.Release();
        }
    }

    // ---- redirect handling -------------------------------------------------

    private bool ShouldRedirect(int status, int redirects)
    {
        if (!_allowAutoRedirect || redirects >= Volatile.Read(ref _maxAutomaticRedirections))
        {
            return false;
        }

        return status is >= 300 and < 400;
    }

    /// <summary>Reads the (case-insensitive) Location header from a native response.</summary>
    private static string? ExtractLocation(TlsResponsePayload response)
    {
        if (response.Headers is null)
        {
            return null;
        }

        foreach (var (name, values) in response.Headers)
        {
            if (name.Equals("Location", StringComparison.OrdinalIgnoreCase) && values.Count > 0)
            {
                return string.IsNullOrWhiteSpace(values[0]) ? null : values[0];
            }
        }

        return null;
    }

    private static (HttpMethod method, string? body, bool isByte) NextHop(
        HttpMethod method, int status, string? body, bool isByte, Dictionary<string, string> headers)
    {
        // 307/308 preserve method and body; 301/302/303 degrade non-GET/HEAD to GET.
        if (status is 307 or 308)
        {
            return (method, body, isByte);
        }

        if (method == HttpMethod.Get || method == HttpMethod.Head)
        {
            return (method, body, isByte);
        }

        // Drop the request body and its content headers when switching to GET.
        headers.Remove("content-type");
        headers.Remove("content-length");
        return (HttpMethod.Get, null, false);
    }

    // ---- response construction --------------------------------------------

    private static HttpResponseMessage BuildResponse(
        TlsResponsePayload payload, HttpRequestMessage original, HttpMethod finalMethod, Uri finalUri)
    {
        var response = new HttpResponseMessage((HttpStatusCode)payload.Status)
        {
            // Surface the protocol that was actually negotiated (h2 vs http/1.1).
            Version = payload.UsedProtocol switch
            {
                "h2" or "HTTP/2.0" or "2" => System.Net.HttpVersion.Version20,
                "http/1.1" or "HTTP/1.1" or "1.1" => System.Net.HttpVersion.Version11,
                _ => System.Net.HttpVersion.Unknown,
            },
        };

        var (bytes, dataUriMediaType) = DecodeBody(payload.Body);
        response.Content = new ByteArrayContent(bytes);

        if (payload.Headers is not null)
        {
            foreach (var (name, values) in payload.Headers)
            {
                foreach (var value in values)
                {
                    if (IsContentHeader(name))
                    {
                        if (!SkippedResponseContentHeaders.Contains(name))
                        {
                            response.Content.Headers.TryAddWithoutValidation(name, value);
                        }
                    }
                    else
                    {
                        response.Headers.TryAddWithoutValidation(name, value);
                    }
                }
            }
        }

        // If the upstream didn't surface a Content-Type but the data-URI body
        // carried one, apply it so ReadAsStringAsync picks the right charset.
        if (response.Content.Headers.ContentType is null && dataUriMediaType is not null)
        {
            response.Content.Headers.TryAddWithoutValidation("Content-Type", dataUriMediaType);
        }

        // Reflect the final landing URL so callers reading RequestMessage.RequestUri
        // (e.g. after redirects) see where they actually ended up.
        response.RequestMessage = new HttpRequestMessage(finalMethod, finalUri)
        {
            Version = original.Version,
        };

        return response;
    }

    private static (byte[] Bytes, string? MediaType) DecodeBody(string? body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return ([], null);
        }

        // With isByteResponse=true the native layer returns the body as an
        // RFC 2397 data URI:  data:<mediatype>[;base64],<payload>
        if (body.StartsWith("data:", StringComparison.Ordinal))
        {
            var comma = body.IndexOf(',');
            if (comma > 0)
            {
                var meta = body[5..comma];          // e.g. "text/plain;charset=utf-8;base64"
                var payload = body[(comma + 1)..];

                const string base64Token = ";base64";
                var isBase64 = meta.EndsWith(base64Token, StringComparison.OrdinalIgnoreCase);
                var mediaType = isBase64 ? meta[..^base64Token.Length] : meta;
                if (string.IsNullOrWhiteSpace(mediaType))
                {
                    mediaType = null;
                }

                try
                {
                    var data = isBase64
                        ? Convert.FromBase64String(payload)
                        : System.Text.Encoding.UTF8.GetBytes(Uri.UnescapeDataString(payload));
                    return (data, mediaType);
                }
                catch (FormatException)
                {
                    // Fall through to the plain handling below.
                }
            }
        }

        try
        {
            return (Convert.FromBase64String(body), null);
        }
        catch (FormatException)
        {
            // Defensive: if the native side ever returns a plain string.
            return (System.Text.Encoding.UTF8.GetBytes(body), null);
        }
    }

    private static bool IsContentHeader(string name)
        => name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Expires", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Last-Modified", StringComparison.OrdinalIgnoreCase);

    // ---- cookie seeding ----------------------------------------------------

    private void SeedCookiesOnce(Uri uri)
    {
        if (_options.Cookies is null || Interlocked.Exchange(ref _seeded, 1) == 1)
        {
            return;
        }

        try
        {
            _cookies.Import(uri.GetLeftPart(UriPartial.Authority), _options.Cookies);
        }
        catch
        {
            // Seeding is best-effort; never fail the first request because of it.
        }
    }

    // ---- request-scoped redirect cookies (IsolateRedirectCookies) ----------

    /// <summary>
    /// Seeds the per-request container with the caller's verbatim <c>Cookie</c> header,
    /// scoped to the initial host, then drops that header — every hop's Cookie header is
    /// recomputed from the container instead (host/path scoped by the BCL).
    /// </summary>
    private static void SeedChainCookies(CookieContainer jar, Uri uri, Dictionary<string, string> headers)
    {
        if (headers.TryGetValue("cookie", out var cookieHeader) && !string.IsNullOrWhiteSpace(cookieHeader))
        {
            foreach (var pair in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var eq = pair.IndexOf('=');
                if (eq <= 0)
                {
                    continue;
                }

                try
                {
                    jar.Add(uri, new Cookie(pair[..eq].Trim(), pair[(eq + 1)..].Trim()) { Path = "/" });
                }
                catch (Exception ex) when (ex is CookieException or ArgumentException)
                {
                    // Skip a cookie the BCL won't accept; the rest still carry.
                }
            }
        }

        headers.Remove("cookie");
    }

    /// <summary>Sets this hop's <c>Cookie</c> header from the container (empty → no header).</summary>
    private static void ApplyChainCookies(CookieContainer jar, Uri uri, Dictionary<string, string> headers)
    {
        var header = jar.GetCookieHeader(uri);
        if (string.IsNullOrEmpty(header))
        {
            headers.Remove("cookie");
        }
        else
        {
            headers["cookie"] = header;
        }
    }

    /// <summary>Folds this hop's <c>Set-Cookie</c> response headers into the container.</summary>
    private static void CaptureChainCookies(CookieContainer jar, Uri uri, IReadOnlyDictionary<string, List<string>>? headers)
    {
        if (headers is null)
        {
            return;
        }

        foreach (var (name, values) in headers)
        {
            if (!name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var value in values)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                try
                {
                    jar.SetCookies(uri, value);
                }
                catch (CookieException)
                {
                    // Malformed Set-Cookie — skip it (best-effort, like the export mirror).
                }
            }
        }
    }

    // ---- lifetime ----------------------------------------------------------

    /// <inheritdoc />
    public override void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _throttle?.Dispose();

        try
        {
            TlsClientNative.DestroySession(_sessionId);
        }
        catch
        {
            // Best-effort cleanup; the native library may already be unloaded at shutdown.
        }
    }
}
