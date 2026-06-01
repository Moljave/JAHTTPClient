using System.Text;
using JASniffer.Core.Models;

namespace JASniffer.Proxy;

/// <summary>
/// Serializes a <see cref="RelayResult"/> back onto the browser leg as HTTP/1.1.
/// Hop-by-hop and body-framing headers are dropped and an accurate
/// <c>Content-Length</c> is written, because the upstream body is already decoded
/// (no <c>Content-Encoding</c>) — sending the original framing would make the
/// browser try to un-gzip plain bytes or mis-read the length.
/// </summary>
internal static class WireResponse
{
    private static readonly HashSet<string> DropHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Length", "Content-Encoding", "Transfer-Encoding", "Connection", "Keep-Alive",
        "Proxy-Connection", "Proxy-Authenticate", "Upgrade", "TE", "Trailer",
    };

    public static async Task WriteAsync(Stream stream, RelayResult result, bool keepAlive, CancellationToken ct)
    {
        var head = new StringBuilder();
        var reason = string.IsNullOrEmpty(result.Reason) ? "OK" : result.Reason;
        head.Append("HTTP/1.1 ").Append(result.Status).Append(' ').Append(reason).Append("\r\n");

        foreach (var (name, value) in result.Headers)
        {
            if (DropHeaders.Contains(name))
            {
                continue;
            }

            head.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        head.Append("Content-Length: ").Append(result.Body.Length).Append("\r\n");
        head.Append("Connection: ").Append(keepAlive ? "keep-alive" : "close").Append("\r\n");
        head.Append("\r\n");

        await stream.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()), ct).ConfigureAwait(false);
        if (result.Body.Length > 0)
        {
            await stream.WriteAsync(result.Body, ct).ConfigureAwait(false);
        }

        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Writes a small plain-text status line response (used for proxy-level errors).</summary>
    public static async Task WriteStatusAsync(Stream stream, int status, string reason, string? body, CancellationToken ct)
    {
        var payload = body is null ? [] : Encoding.UTF8.GetBytes(body);
        var head = new StringBuilder();
        head.Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n");
        head.Append("Content-Type: text/plain; charset=utf-8\r\n");
        head.Append("Content-Length: ").Append(payload.Length).Append("\r\n");
        head.Append("Connection: close\r\n\r\n");

        await stream.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()), ct).ConfigureAwait(false);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        }

        await stream.FlushAsync(ct).ConfigureAwait(false);
    }
}
