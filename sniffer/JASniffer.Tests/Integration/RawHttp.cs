using System.Net;
using System.Net.Sockets;
using System.Text;

namespace JASniffer.Tests.Integration;

/// <summary>Minimal raw HTTP/1.1 client used to drive the proxy the way a browser would.</summary>
internal static class RawHttp
{
    /// <summary>
    /// Sends a verbatim request (request-line + headers + optional body) to a loopback
    /// port and parses the response. The caller should send <c>Connection: close</c> so
    /// the read terminates at EOF.
    /// </summary>
    public static async Task<RawResponse> SendAsync(int port, string requestText, byte[]? body = null)
        => RawResponse.Parse(await SendRawAsync(port, requestText, body));

    /// <summary>
    /// Like <see cref="SendAsync"/> but returns the raw response bytes unparsed — used
    /// when a single connection carries several pipelined responses.
    /// </summary>
    public static async Task<byte[]> SendRawAsync(int port, string requestText, byte[]? body = null)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();

        await stream.WriteAsync(Encoding.Latin1.GetBytes(requestText));
        if (body is { Length: > 0 })
        {
            await stream.WriteAsync(body);
        }

        await stream.FlushAsync();
        return await ReadToEndAsync(stream);
    }

    /// <summary>Reads a stream to EOF (bounded by a 30s safety timeout).</summary>
    public static async Task<byte[]> ReadToEndAsync(Stream stream)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        int n;
        while ((n = await stream.ReadAsync(buf, cts.Token)) > 0)
        {
            ms.Write(buf, 0, n);
        }

        return ms.ToArray();
    }
}

internal sealed record RawResponse(int Status, string Reason, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string BodyText => Encoding.Latin1.GetString(Body);

    public static RawResponse Parse(byte[] bytes)
    {
        var text = Encoding.Latin1.GetString(bytes);
        var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0)
        {
            throw new InvalidOperationException("No header terminator in proxy response:\n" + text);
        }

        var head = text[..headerEnd];
        var lines = head.Split("\r\n");
        var statusParts = lines[0].Split(' ', 3);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out var status))
        {
            throw new InvalidOperationException("Malformed status line from proxy: " + lines[0]);
        }

        var reason = statusParts.Length > 2 ? statusParts[2] : string.Empty;

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < lines.Length; i++)
        {
            var colon = lines[i].IndexOf(':');
            if (colon > 0)
            {
                headers[lines[i][..colon].Trim()] = lines[i][(colon + 1)..].Trim();
            }
        }

        var body = bytes[(headerEnd + 4)..];
        return new RawResponse(status, reason, headers, body);
    }
}
