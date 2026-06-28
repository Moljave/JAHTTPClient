namespace JASniffer.Core;

/// <summary>
/// Normalizes the many shapes people paste a proxy in into the canonical
/// <c>scheme://[user:pass@]host:port</c> URI the engine expects. Accepts:
/// <list type="bullet">
/// <item><c>http://user:pass@host:port</c> / <c>http://host:port</c> / <c>socks5://host:port</c></item>
/// <item><c>host:port</c> (assumes http)</item>
/// <item><c>host:port:user:pass</c> (and <c>scheme://host:port:user:pass</c>)</item>
/// <item><c>user:pass@host:port</c> (no scheme)</item>
/// </list>
/// Returns <see langword="null"/> for empty input or anything it can't parse.
/// </summary>
public static class ProxyUrl
{
    private static readonly HashSet<string> Schemes =
        new(StringComparer.OrdinalIgnoreCase) { "http", "https", "socks5", "socks5h", "socks4", "socks4a" };

    public static string? Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        var s = input.Trim();

        // Optional scheme.
        var scheme = "http";
        var schemeIdx = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx > 0)
        {
            var found = s[..schemeIdx].ToLowerInvariant();
            scheme = Schemes.Contains(found) ? found : "http";
            s = s[(schemeIdx + 3)..];
        }

        string? user = null, pass = null;
        string host;
        int port;

        var at = s.LastIndexOf('@');
        if (at >= 0)
        {
            // [user[:pass]]@host:port
            var creds = s[..at];
            var colon = creds.IndexOf(':');
            if (colon >= 0)
            {
                user = creds[..colon];
                pass = creds[(colon + 1)..];
            }
            else
            {
                user = creds;
            }

            if (!TrySplitHostPort(s[(at + 1)..], out host, out port))
            {
                return null;
            }
        }
        else if (s.StartsWith('['))
        {
            // IPv6 literal in the no-credentials form: [::1]:8080
            var end = s.IndexOf(']');
            if (end <= 1 || end + 2 >= s.Length || s[end + 1] != ':' || !int.TryParse(s[(end + 2)..], out port))
            {
                return null;
            }

            host = s[..(end + 1)]; // keep the brackets for the URL authority
        }
        else
        {
            // host:port  OR  host:port:user:pass(:more-of-pass)
            var parts = s.Split(':');
            if (parts.Length == 2)
            {
                host = parts[0];
                if (!int.TryParse(parts[1], out port))
                {
                    return null;
                }
            }
            else if (parts.Length >= 4)
            {
                host = parts[0];
                if (!int.TryParse(parts[1], out port))
                {
                    return null;
                }

                user = parts[2];
                pass = string.Join(':', parts[3..]); // a password may itself contain ':'
            }
            else
            {
                return null;
            }
        }

        if (string.IsNullOrEmpty(host) || port is <= 0 or > 65535)
        {
            return null;
        }

        var auth = user is null ? string.Empty : $"{Uri.EscapeDataString(user)}:{Uri.EscapeDataString(pass ?? string.Empty)}@";
        return $"{scheme}://{auth}{host}:{port}";
    }

    private static bool TrySplitHostPort(string s, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        var i = s.LastIndexOf(':');
        if (i <= 0)
        {
            return false;
        }

        host = s[..i];
        return int.TryParse(s[(i + 1)..], out port);
    }
}
