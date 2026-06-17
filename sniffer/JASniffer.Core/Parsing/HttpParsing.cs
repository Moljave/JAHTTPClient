using System.Text;
using JASniffer.Core.Models;

namespace JASniffer.Core.Parsing;

/// <summary>A decoded query-string parameter.</summary>
public readonly record struct QueryParam(string Name, string Value);

/// <summary>A single cookie parsed from a request <c>Cookie</c> header.</summary>
public readonly record struct RequestCookie(string Name, string Value);

/// <summary>A cookie parsed from a response <c>Set-Cookie</c> header, with its attributes.</summary>
public sealed record ResponseCookie(
    string Name,
    string Value,
    string? Domain,
    string? Path,
    string? Expires,
    string? MaxAge,
    bool Secure,
    bool HttpOnly,
    string? SameSite);

/// <summary>Parsed <c>Authorization</c> header (Basic / Bearer / other).</summary>
public sealed record AuthInfo(string Scheme, string? Username, string? Password, string? Token);

/// <summary>
/// Stateless helpers that turn raw headers/bodies into the structured views the
/// Fiddler-style inspectors show (Params / Cookies / Auth) and that classify
/// bodies for the Preview tab. Kept dependency-free and defensive: malformed
/// input yields empty results rather than throwing.
/// </summary>
public static class HttpParsing
{
    /// <summary>Splits a raw query string (with or without a leading '?') into ordered params.</summary>
    public static IReadOnlyList<QueryParam> ParseQuery(string? query)
    {
        if (string.IsNullOrEmpty(query))
        {
            return [];
        }

        var span = query.AsSpan();
        if (span[0] == '?')
        {
            span = span[1..];
        }

        var result = new List<QueryParam>();
        foreach (var range in span.Split('&'))
        {
            var pair = span[range];
            if (pair.IsEmpty)
            {
                continue;
            }

            var eq = pair.IndexOf('=');
            if (eq < 0)
            {
                result.Add(new QueryParam(Decode(pair.ToString()), string.Empty));
            }
            else
            {
                result.Add(new QueryParam(Decode(pair[..eq].ToString()), Decode(pair[(eq + 1)..].ToString())));
            }
        }

        return result;
    }

    /// <summary>Parses the (possibly multiple) request <c>Cookie</c> headers into name/value pairs.</summary>
    public static IReadOnlyList<RequestCookie> ParseRequestCookies(IReadOnlyList<HeaderEntry> headers)
    {
        var result = new List<RequestCookie>();
        foreach (var h in headers)
        {
            if (!h.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var part in h.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var eq = part.IndexOf('=');
                if (eq <= 0)
                {
                    result.Add(new RequestCookie(part, string.Empty));
                }
                else
                {
                    result.Add(new RequestCookie(part[..eq].Trim(), part[(eq + 1)..].Trim()));
                }
            }
        }

        return result;
    }

    /// <summary>Parses every response <c>Set-Cookie</c> header, including its attributes.</summary>
    public static IReadOnlyList<ResponseCookie> ParseResponseCookies(IReadOnlyList<HeaderEntry> headers)
    {
        var result = new List<ResponseCookie>();
        foreach (var h in headers)
        {
            if (!h.Name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parsed = ParseSetCookie(h.Value);
            if (parsed is not null)
            {
                result.Add(parsed);
            }
        }

        return result;
    }

    private static ResponseCookie? ParseSetCookie(string value)
    {
        var segments = value.Split(';');
        if (segments.Length == 0)
        {
            return null;
        }

        var first = segments[0];
        var eq = first.IndexOf('=');
        if (eq < 0)
        {
            return null;
        }

        var name = first[..eq].Trim();
        var val = first[(eq + 1)..].Trim();
        if (name.Length == 0)
        {
            return null;
        }

        string? domain = null, path = null, expires = null, maxAge = null, sameSite = null;
        var secure = false;
        var httpOnly = false;

        for (var i = 1; i < segments.Length; i++)
        {
            var attr = segments[i].Trim();
            if (attr.Length == 0)
            {
                continue;
            }

            var aeq = attr.IndexOf('=');
            var key = (aeq < 0 ? attr : attr[..aeq]).Trim();
            var aval = aeq < 0 ? string.Empty : attr[(aeq + 1)..].Trim();

            if (key.Equals("Domain", StringComparison.OrdinalIgnoreCase)) domain = aval;
            else if (key.Equals("Path", StringComparison.OrdinalIgnoreCase)) path = aval;
            else if (key.Equals("Expires", StringComparison.OrdinalIgnoreCase)) expires = aval;
            else if (key.Equals("Max-Age", StringComparison.OrdinalIgnoreCase)) maxAge = aval;
            else if (key.Equals("SameSite", StringComparison.OrdinalIgnoreCase)) sameSite = aval;
            else if (key.Equals("Secure", StringComparison.OrdinalIgnoreCase)) secure = true;
            else if (key.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)) httpOnly = true;
        }

        return new ResponseCookie(name, val, domain, path, expires, maxAge, secure, httpOnly, sameSite);
    }

    /// <summary>Parses the first <c>Authorization</c> header into scheme + credentials.</summary>
    public static AuthInfo? ParseAuthorization(IReadOnlyList<HeaderEntry> headers)
    {
        foreach (var h in headers)
        {
            if (!h.Name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var raw = h.Value.Trim();
            var sp = raw.IndexOf(' ');
            var scheme = sp < 0 ? raw : raw[..sp];
            var rest = sp < 0 ? string.Empty : raw[(sp + 1)..].Trim();

            if (scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(rest));
                    var colon = decoded.IndexOf(':');
                    return colon < 0
                        ? new AuthInfo("Basic", decoded, null, null)
                        : new AuthInfo("Basic", decoded[..colon], decoded[(colon + 1)..], null);
                }
                catch (FormatException)
                {
                    return new AuthInfo("Basic", null, null, rest);
                }
            }

            if (scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                return new AuthInfo("Bearer", null, null, rest);
            }

            return new AuthInfo(scheme, null, null, rest);
        }

        return null;
    }

    /// <summary>Finds the value of the first header matching <paramref name="name"/> (case-insensitive).</summary>
    public static string? FirstHeader(IReadOnlyList<HeaderEntry> headers, string name)
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

    /// <summary>True when a content type denotes textual data we can show as text.</summary>
    public static bool IsTextual(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
        {
            return false;
        }

        var ct = contentType.AsSpan();
        return ct.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("json", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("xml", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("javascript", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("csv", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("html", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Coarse body category used by the Preview tab: json/html/image/text/binary.</summary>
    public static string ContentKind(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
        {
            return "binary";
        }

        var ct = contentType.ToLowerInvariant();
        if (ct.Contains("json")) return "json";
        if (ct.Contains("html")) return "html";
        if (ct.Contains("xml")) return "xml";
        if (ct.StartsWith("image/")) return "image";
        if (ct.StartsWith("text/") || ct.Contains("javascript") || ct.Contains("css")
            || ct.Contains("x-www-form-urlencoded") || ct.Contains("csv")) return "text";
        return "binary";
    }

    /// <summary>Extracts the charset from a content type, defaulting to UTF-8.</summary>
    public static Encoding CharsetOf(string? contentType)
    {
        if (!string.IsNullOrEmpty(contentType))
        {
            var idx = contentType.IndexOf("charset=", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                // Cut the value at the next parameter (';') BEFORE stripping quotes —
                // otherwise a quoted charset followed by another param (charset="x"; y=z)
                // keeps a stray quote and the lookup silently falls back to UTF-8.
                var cs = contentType[(idx + 8)..].Trim();
                var semi = cs.IndexOf(';');
                if (semi >= 0)
                {
                    cs = cs[..semi].Trim();
                }

                cs = cs.Trim('"');

                try
                {
                    return Encoding.GetEncoding(cs);
                }
                catch (ArgumentException)
                {
                    // Unknown/typo'd charset — fall through to UTF-8.
                }
            }
        }

        return Encoding.UTF8;
    }

    private static string Decode(string s)
    {
        try
        {
            return Uri.UnescapeDataString(s.Replace('+', ' '));
        }
        catch (Exception)
        {
            return s;
        }
    }
}
