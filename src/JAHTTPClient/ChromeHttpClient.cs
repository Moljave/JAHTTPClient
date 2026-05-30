using JAHTTPClient.Cookies;

namespace JAHTTPClient;

/// <summary>
/// Browser-impersonating HTTP client. The public surface intentionally mirrors
/// <see cref="System.Net.Http.HttpClient"/> so existing code (working with
/// <see cref="HttpRequestMessage"/> / <see cref="HttpResponseMessage"/> /
/// <see cref="CancellationToken"/>) migrates with little to no change.
/// </summary>
/// <remarks>
/// Unlike <see cref="System.Net.Http.HttpClient"/>, the underlying transport
/// emulates a real browser's TLS (JA3/JA4) and HTTP/2 fingerprint, defeating
/// anti-bot systems (Akamai, Cloudflare) that fingerprint the ClientHello.
/// </remarks>
public abstract class ChromeHttpClient : IDisposable, IAsyncDisposable
{
    /// <summary>Per-client cookie management (backed by the native session jar).</summary>
    public abstract ChromeCookieContainer Cookies { get; }

    /// <summary>Headers applied to every request unless a request overrides them.</summary>
    public abstract IDictionary<string, string> DefaultRequestHeaders { get; }

    /// <summary>
    /// Whether HTTP redirects are followed automatically. Unlike the option of
    /// the same name (read once at construction), this is a live switch: flip it
    /// between requests to enable/disable redirect following on the fly, e.g.
    /// <c>client.AllowAutoRedirect = false;</c> to capture a raw 3xx response.
    /// </summary>
    public abstract bool AllowAutoRedirect { get; set; }

    /// <summary>
    /// Maximum number of redirects followed when <see cref="AllowAutoRedirect"/>
    /// is enabled. Adjustable at any time. Must be zero or positive.
    /// </summary>
    public abstract int MaxAutomaticRedirections { get; set; }

    /// <summary>The egress proxy currently in effect, or <see langword="null"/> for direct egress.</summary>
    public abstract string? Proxy { get; }

    /// <summary>
    /// Hot-swaps the egress proxy for all subsequent requests. Pass
    /// <see langword="null"/> or empty to go direct. Optionally update the
    /// rotating-proxy hint at the same time (leave <see langword="null"/> to keep
    /// the current setting).
    /// </summary>
    /// <param name="proxyUrl">
    /// Absolute proxy URI, e.g. <c>http://user:pass@host:port</c> or
    /// <c>socks5://host:port</c>; <see langword="null"/>/empty = direct.
    /// </param>
    /// <param name="rotating">
    /// When provided, updates whether the proxy rotates its exit IP per request
    /// (affects connection-reuse handling).
    /// </param>
    /// <remarks>
    /// The swap applies from the next request onward and is safe to call while
    /// other requests are in flight.
    /// </remarks>
    public abstract void SetProxy(string? proxyUrl, bool? rotating = null);

    /// <summary>
    /// Sends an HTTP request and returns the response, honoring the configured
    /// redirect policy. This is the single primitive every other helper builds on.
    /// </summary>
    public abstract Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default);

    /// <summary>Sends a GET request to <paramref name="url"/>.</summary>
    public Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Get, url), cancellationToken);

    /// <summary>Sends a POST request with <paramref name="content"/> to <paramref name="url"/>.</summary>
    public Task<HttpResponseMessage> PostAsync(string url, HttpContent content, CancellationToken cancellationToken = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Post, url) { Content = content }, cancellationToken);

    /// <summary>Convenience GET returning the body as a string.</summary>
    public async Task<string> GetStringAsync(string url, CancellationToken cancellationToken = default)
    {
        using var response = await GetAsync(url, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public abstract void Dispose();

    /// <inheritdoc />
    public virtual ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
