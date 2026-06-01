using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;
using JASniffer.Core;
using JASniffer.Core.Models;

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
/// <item><b>follow</b> — redirects on, cookie jar on: the chain is walked upstream
/// (the jar carries Set-Cookie across hops) and only the final response returns.</item>
/// </list>
/// </remarks>
public sealed class UpstreamRelay : IDisposable
{
    private static readonly string PresetLabel = "Chrome 148";

    // Content headers must live on HttpContent, not the request; Content-Length is
    // recomputed by ByteArrayContent, so it is never forwarded verbatim.
    private static readonly HashSet<string> SkippedRequestHeaders =
        new(StringComparer.OrdinalIgnoreCase) { "Host", "Content-Length", "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization" };

    private readonly SnifferSettings _settings;
    private readonly TlsClientChromeHttpClient _faithful;
    private readonly TlsClientChromeHttpClient _follow;
    private readonly ConcurrentDictionary<string, string?> _hostIpCache = new(StringComparer.OrdinalIgnoreCase);

    public UpstreamRelay(SnifferSettings settings)
    {
        _settings = settings;

        _faithful = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = Ja3Preset.Chrome,
            AllowAutoRedirect = false,
            WithoutCookieJar = true,
            Timeout = TimeSpan.FromSeconds(100),
        });

        _follow = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = Ja3Preset.Chrome,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = settings.MaxRedirects,
            WithoutCookieJar = false,
            Timeout = TimeSpan.FromSeconds(100),
        });
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

        ApplyUpstreamProxy(client);
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
        var contentType = HeaderValue(responseHeaders, "Content-Type");
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
        session.TlsSummary = $"{PresetLabel} · HTTP/{httpVersion} · TLS 1.3 (assumed)";

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

    private void ApplyUpstreamProxy(TlsClientChromeHttpClient client)
    {
        var desired = _settings.UpstreamProxy;
        if (!string.Equals(client.Proxy, desired, StringComparison.Ordinal))
        {
            client.SetProxy(desired);
        }
    }

    private string? ResolveHostIp(string host)
        => _hostIpCache.GetOrAdd(host, static h =>
        {
            if (IPAddress.TryParse(h, out var literal))
            {
                return literal.ToString();
            }

            try
            {
                var addrs = Dns.GetHostAddresses(h);
                return addrs.Length > 0 ? addrs[0].ToString() : null;
            }
            catch (Exception)
            {
                return null;
            }
        });

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

    private static string? HeaderValue(List<HeaderEntry> headers, string name)
    {
        foreach (var h in headers)
        {
            if (h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    private static bool IsContentHeader(string name)
        => name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _faithful.Dispose();
        _follow.Dispose();
    }
}
