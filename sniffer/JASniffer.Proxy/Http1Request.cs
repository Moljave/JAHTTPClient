using JASniffer.Core.Models;

namespace JASniffer.Proxy;

/// <summary>
/// Parses an HTTP/1.1 header block into a <see cref="ProxyRequest"/> and reads its
/// body off an <see cref="Http1Reader"/> using the request's framing headers.
/// </summary>
internal static class Http1Request
{
    /// <summary>
    /// Parses the request line + headers. <paramref name="tunnelHost"/>/<paramref name="tunnelPort"/>
    /// supply the authority for origin-form targets seen inside a CONNECT tunnel;
    /// for plain proxying the target is absolute-form and carries its own authority.
    /// Returns null if the block is not a well-formed request line.
    /// </summary>
    public static ProxyRequest? Parse(string headerBlock, bool secure, string? tunnelHost, int tunnelPort)
    {
        var lines = headerBlock.Split("\r\n");
        if (lines.Length == 0 || lines[0].Length == 0)
        {
            return null;
        }

        var parts = lines[0].Split(' ', 3, StringSplitOptions.None);
        if (parts.Length < 3)
        {
            return null;
        }

        var method = parts[0];
        var target = parts[1];
        var version = parts[2];

        var headers = ParseHeaders(lines);

        string scheme, host, path, query, url;
        int port;

        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(target, UriKind.Absolute, out var abs))
            {
                return null;
            }

            scheme = abs.Scheme;
            host = abs.Host;
            port = abs.Port;
            path = abs.AbsolutePath;
            query = abs.Query;
            url = abs.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
        }
        else
        {
            scheme = secure ? "https" : "http";
            var authority = tunnelHost ?? HostHeader(headers) ?? "unknown";
            (host, port) = SplitHostPort(authority, secure ? 443 : 80);
            if (tunnelHost is not null)
            {
                port = tunnelPort;
            }

            var q = target.IndexOf('?');
            path = q < 0 ? target : target[..q];
            query = q < 0 ? string.Empty : target[q..];
            if (path.Length == 0)
            {
                path = "/";
            }

            var defaultPort = secure ? 443 : 80;
            var authorityForUrl = port == defaultPort ? host : $"{host}:{port}";
            url = $"{scheme}://{authorityForUrl}{path}{query}";
        }

        return new ProxyRequest
        {
            Method = method,
            Scheme = scheme,
            Host = host,
            Port = port,
            Path = path,
            Query = query,
            Url = url,
            HttpVersion = version,
            Headers = headers,
            IsUpgrade = DetectUpgrade(headers),
            IsEventStream = DetectEventStream(headers),
            WantsClose = DetectClose(headers, version),
        };
    }

    /// <summary>Reads the request body (Content-Length or chunked); empty when neither applies.</summary>
    public static async Task<byte[]> ReadBodyAsync(ProxyRequest request, Http1Reader reader, CancellationToken ct)
    {
        var transferEncoding = Header(request.Headers, "Transfer-Encoding");
        if (transferEncoding is not null && transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return await reader.ReadChunkedAsync(ct).ConfigureAwait(false);
        }

        var contentLength = Header(request.Headers, "Content-Length");
        if (contentLength is not null && long.TryParse(contentLength.Trim(), out var len) && len > 0)
        {
            // Bodies are bounded by Content-Length; cap the single allocation defensively.
            if (len > int.MaxValue)
            {
                throw new InvalidDataException("Request body too large.");
            }

            return await reader.ReadExactlyAsync((int)len, ct).ConfigureAwait(false);
        }

        return [];
    }

    private static List<HeaderEntry> ParseHeaders(string[] lines)
    {
        var headers = new List<HeaderEntry>(lines.Length);
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0)
            {
                continue;
            }

            // Obsolete line folding: a leading space/tab continues the previous value.
            if ((line[0] == ' ' || line[0] == '\t') && headers.Count > 0)
            {
                var prev = headers[^1];
                headers[^1] = prev with { Value = $"{prev.Value} {line.Trim()}" };
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            headers.Add(new HeaderEntry(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        return headers;
    }

    private static string? Header(List<HeaderEntry> headers, string name)
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

    private static string? HostHeader(List<HeaderEntry> headers) => Header(headers, "Host");

    private static bool DetectUpgrade(List<HeaderEntry> headers)
    {
        var connection = Header(headers, "Connection");
        if (connection is not null && connection.Contains("upgrade", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return Header(headers, "Upgrade") is not null || Header(headers, "Sec-WebSocket-Key") is not null;
    }

    private static bool DetectEventStream(List<HeaderEntry> headers)
    {
        var accept = Header(headers, "Accept");
        return accept is not null && accept.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase);
    }

    private static bool DetectClose(List<HeaderEntry> headers, string version)
    {
        var connection = Header(headers, "Connection");
        if (connection is not null)
        {
            if (connection.Contains("close", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (connection.Contains("keep-alive", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // HTTP/1.0 defaults to close; HTTP/1.1 defaults to keep-alive.
        return version.Equals("HTTP/1.0", StringComparison.OrdinalIgnoreCase);
    }

    private static (string host, int port) SplitHostPort(string authority, int defaultPort)
    {
        if (authority.StartsWith('['))
        {
            // IPv6 literal: [::1]:443
            var end = authority.IndexOf(']');
            if (end > 0)
            {
                var h = authority[1..end];
                var rest = authority[(end + 1)..];
                return rest.StartsWith(':') && int.TryParse(rest[1..], out var p6) ? (h, p6) : (h, defaultPort);
            }
        }

        var colon = authority.LastIndexOf(':');
        if (colon > 0 && int.TryParse(authority[(colon + 1)..], out var p))
        {
            return (authority[..colon], p);
        }

        return (authority, defaultPort);
    }
}
