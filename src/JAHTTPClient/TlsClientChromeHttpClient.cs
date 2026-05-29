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

    private readonly ChromeHttpClientOptions _options;
    private readonly FingerprintProfile _profile;
    private readonly string _sessionId;
    private readonly ChromeCookieContainer _cookies;
    private readonly SemaphoreSlim? _throttle;
    private readonly Dictionary<string, string> _defaultHeaders;

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

        var redirects = 0;
        while (true)
        {
            var payload = BuildPayload(method, currentUri, orderedHeaders, body, isByteBody);
            var response = await ExecuteAsync(payload, cancellationToken).ConfigureAwait(false);

            if (ShouldRedirect(response.Status, redirects, out var location) &&
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
        var merged = MergeFingerprintHeaders(uri, headers);

        return new TlsRequestPayload
        {
            SessionId = _sessionId,
            // The native library always needs a profile; impersonation toggles
            // the client hints and ClientHello extension shuffling, not the base.
            TlsClientIdentifier = _profile.TlsIdentifier,
            RequestUrl = uri.AbsoluteUri,
            RequestMethod = method.Method,
            RequestBody = body,
            IsByteRequest = isByteBody,
            IsByteResponse = true, // lossless: native returns base64, we decode to bytes
            Headers = merged,
            HeaderOrder = BuildHeaderOrder(merged),
            FollowRedirects = false, // redirects handled in managed code
            InsecureSkipVerify = _options.InsecureSkipVerify,
            WithDefaultCookieJar = true,
            WithRandomTlsExtensionOrder = _options.EnableJa3Fingerprinting,
            ForceHttp1 = _options.ForceHttp1,
            TimeoutMilliseconds = (int)Math.Clamp(_options.Timeout.TotalMilliseconds, 1, int.MaxValue),
            ProxyUrl = _options.Proxy,
            IsRotatingProxy = _options.RotatingProxy,
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

    private bool ShouldRedirect(int status, int redirects, out string location)
    {
        location = string.Empty;
        if (!_options.AllowAutoRedirect || redirects >= _options.MaxAutomaticRedirections)
        {
            return false;
        }

        return status is >= 300 and < 400;
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
        var response = new HttpResponseMessage((HttpStatusCode)payload.Status);

        var bytes = DecodeBody(payload.Body);
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

        // Reflect the final landing URL so callers reading RequestMessage.RequestUri
        // (e.g. after redirects) see where they actually ended up.
        response.RequestMessage = new HttpRequestMessage(finalMethod, finalUri)
        {
            Version = original.Version,
        };

        return response;
    }

    private static byte[] DecodeBody(string? body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return [];
        }

        try
        {
            return Convert.FromBase64String(body);
        }
        catch (FormatException)
        {
            // Defensive: if the native side ever returns a plain string.
            return System.Text.Encoding.UTF8.GetBytes(body);
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
