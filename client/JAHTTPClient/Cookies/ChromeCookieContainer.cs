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

    // The native jar is authoritative for what gets *sent*, but its read API only
    // exposes name→value pairs. To produce a faithful, browser-extension-style
    // export we keep a managed mirror that captures full metadata (domain, path,
    // expiry, Secure, HttpOnly) from Set-Cookie response headers and from any
    // cookies the caller injects. CookieContainer instance members aren't
    // guaranteed thread-safe, so every touch is guarded by _mirrorLock.
    private readonly CookieContainer _mirror = new();
    private readonly object _mirrorLock = new();

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

        MirrorAdd(url, new Cookie(name, value)
        {
            Path = string.IsNullOrEmpty(path) ? "/" : path,
            Domain = domain ?? string.Empty,
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

            var cookie = new TlsCookie
            {
                Name = pair[..eq].Trim(),
                Value = pair[(eq + 1)..].Trim(),
                Path = "/",
            };
            cookies.Add(cookie);
            MirrorAdd(url, new Cookie(cookie.Name, cookie.Value) { Path = "/" });
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
            MirrorAdd(url, c);
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

    /// <summary>
    /// Exports every cookie observed on this session (across all domains) as a
    /// JSON array in browser cookie-extension format (Cookie-Editor /
    /// EditThisCookie), ready to be saved and re-imported. Expired cookies are
    /// dropped. Cookies are tracked from <c>Set-Cookie</c> response headers and
    /// from any cookies injected via <see cref="SetCookie"/>/<see cref="AddRaw"/>/
    /// <see cref="Import"/>.
    /// </summary>
    /// <param name="indented">Pretty-print the JSON. Defaults to compact.</param>
    public string GetCookiesJson(bool indented = false)
    {
        lock (_mirrorLock)
        {
            return CookieContainerExporter.ToJson(_mirror, indented);
        }
    }

    /// <summary>
    /// Exports just the cookies applicable to <paramref name="url"/> as a JSON
    /// array in browser cookie-extension format.
    /// </summary>
    public string GetCookiesJson(string url, bool indented = false)
    {
        var uri = new Uri(url);
        CookieCollection collection;
        lock (_mirrorLock)
        {
            collection = _mirror.GetCookies(uri);
        }

        return CookieContainerExporter.ToJson(collection, indented);
    }

    /// <summary>
    /// Records the <c>Set-Cookie</c> headers from a response so the export mirror
    /// keeps full cookie metadata. Best-effort: malformed headers are ignored and
    /// never surface to the caller. Invoked by the client for every response hop.
    /// </summary>
    internal void CaptureResponseCookies(Uri responseUri, IReadOnlyDictionary<string, List<string>>? headers)
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

                lock (_mirrorLock)
                {
                    try
                    {
                        // Lets the BCL parse the full Set-Cookie grammar
                        // (expires/max-age/path/domain/secure/httponly) for us.
                        _mirror.SetCookies(responseUri, value);
                    }
                    catch (CookieException)
                    {
                        // Malformed/unsupported cookie — skip it, the native jar
                        // remains the authoritative store for sending.
                    }
                }
            }
        }
    }

    /// <summary>Adds a cookie to the export mirror, inferring the domain from <paramref name="url"/> when absent.</summary>
    private void MirrorAdd(string url, Cookie cookie)
    {
        try
        {
            var uri = new Uri(url);
            lock (_mirrorLock)
            {
                // CookieContainer.Add(Uri, Cookie) fills in an empty Domain from
                // the URI and validates path scoping for us.
                _mirror.Add(uri, cookie);
            }
        }
        catch (Exception ex) when (ex is UriFormatException or CookieException or ArgumentException)
        {
            // Mirroring is best-effort and must never break the primary jar write.
        }
    }
}
