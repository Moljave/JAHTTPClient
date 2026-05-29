using System.Net;
using JAHTTPClient.Interop;
using JAHTTPClient.Native;

namespace JAHTTPClient.Cookies;

/// <summary>
/// Cookie management facade over a single native tls-client session jar.
/// </summary>
/// <remarks>
/// <para>
/// The authoritative store is the native per-session cookie jar: cookies set by
/// servers (including Akamai's <c>_abck</c>/<c>ak_bmsc</c>/<c>bm_sz</c> and
/// Cloudflare's <c>cf_clearance</c>) persist automatically across requests that
/// share the owning client's session id.
/// </para>
/// <para>
/// This class lets the caller inspect that jar and inject/replace cookies of
/// their own. User-supplied cookies overwrite server cookies of the same
/// name+domain (last write wins), which is what you want when replaying a
/// captured browser session.
/// </para>
/// <para>All members are safe for concurrent use.</para>
/// </remarks>
public sealed class ChromeCookieContainer
{
    private readonly string _sessionId;

    internal ChromeCookieContainer(string sessionId) => _sessionId = sessionId;

    /// <summary>Adds or overwrites a single cookie for <paramref name="url"/>.</summary>
    public void SetCookie(string url, string name, string value, string? path = "/", string? domain = null)
    {
        TlsClientNative.AddCookies(new SessionCookiesPayload
        {
            SessionId = _sessionId,
            Url = url,
            Cookies = [new TlsCookie { Name = name, Value = value, Path = path, Domain = domain }],
        });
    }

    /// <summary>
    /// Adds/overwrites cookies from a raw header string, e.g.
    /// <c>"a=1; b=2; c=3"</c> (an optional leading <c>"Cookie:"</c> is stripped).
    /// </summary>
    public void AddRaw(string url, string rawCookieHeader)
    {
        if (string.IsNullOrWhiteSpace(rawCookieHeader))
        {
            return;
        }

        var span = rawCookieHeader.AsSpan().Trim();
        if (span.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase))
        {
            span = span[7..].Trim();
        }

        var cookies = new List<TlsCookie>();
        foreach (var pair in span.ToString().Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            cookies.Add(new TlsCookie
            {
                Name = pair[..eq].Trim(),
                Value = pair[(eq + 1)..].Trim(),
                Path = "/",
            });
        }

        if (cookies.Count > 0)
        {
            TlsClientNative.AddCookies(new SessionCookiesPayload { SessionId = _sessionId, Url = url, Cookies = cookies });
        }
    }

    /// <summary>Imports every applicable cookie from a standard <see cref="CookieContainer"/>.</summary>
    public void Import(string url, CookieContainer container)
    {
        var uri = new Uri(url);
        var collection = container.GetCookies(uri);
        if (collection.Count == 0)
        {
            return;
        }

        var cookies = new List<TlsCookie>(collection.Count);
        foreach (Cookie c in collection)
        {
            cookies.Add(new TlsCookie
            {
                Name = c.Name,
                Value = c.Value,
                Path = string.IsNullOrEmpty(c.Path) ? "/" : c.Path,
                Domain = string.IsNullOrEmpty(c.Domain) ? null : c.Domain,
            });
        }

        TlsClientNative.AddCookies(new SessionCookiesPayload { SessionId = _sessionId, Url = url, Cookies = cookies });
    }

    /// <summary>Returns the current jar contents for <paramref name="url"/> as name → value.</summary>
    public IReadOnlyDictionary<string, string> GetCookies(string url)
    {
        var response = TlsClientNative.GetCookies(new SessionCookiesPayload { SessionId = _sessionId, Url = url });
        return response.Cookies ?? new Dictionary<string, string>();
    }

    /// <summary>Replaces (or creates) a cookie by name. Alias for <see cref="SetCookie"/> for readability.</summary>
    public void Replace(string url, string name, string value, string? path = "/", string? domain = null)
        => SetCookie(url, name, value, path, domain);
}
