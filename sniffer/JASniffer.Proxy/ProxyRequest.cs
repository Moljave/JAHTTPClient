using System.Text;
using JASniffer.Core.Models;

namespace JASniffer.Proxy;

/// <summary>
/// A parsed HTTP/1.1 request from the browser leg, with the scheme/host resolved
/// from either an absolute-form target (plain HTTP proxying) or the CONNECT
/// tunnel context (HTTPS). The body is attached separately once its framing is
/// known.
/// </summary>
internal sealed class ProxyRequest
{
    public required string Method { get; init; }
    public required string Scheme { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string Path { get; init; }
    public required string Query { get; init; }
    public required string Url { get; init; }
    public required string HttpVersion { get; init; }
    public required List<HeaderEntry> Headers { get; init; }

    public byte[] Body { get; set; } = [];

    /// <summary>Request asks to switch protocols (WebSocket/HTTP upgrade) — must be tunneled, not buffered.</summary>
    public bool IsUpgrade { get; init; }

    /// <summary>Request opts into Server-Sent Events — streaming the upstream can't buffer, so tunnel it.</summary>
    public bool IsEventStream { get; init; }

    /// <summary>Browser asked to close the connection after this exchange.</summary>
    public bool WantsClose { get; init; }

    /// <summary>Client sent <c>Expect: 100-continue</c> with a body and is withholding it until it receives an interim 100.</summary>
    public bool ExpectsContinue { get; init; }

    /// <summary>Reconstructs the raw request bytes (request line + headers + CRLFCRLF + body) for tunneling.</summary>
    public byte[] ToRawBytes()
    {
        var head = new StringBuilder();
        var target = Path + Query;
        if (target.Length == 0)
        {
            target = "/";
        }

        head.Append(Method).Append(' ').Append(target).Append(' ').Append(HttpVersion).Append("\r\n");
        foreach (var h in Headers)
        {
            head.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
        }

        head.Append("\r\n");
        var headBytes = Encoding.Latin1.GetBytes(head.ToString());
        if (Body.Length == 0)
        {
            return headBytes;
        }

        var raw = new byte[headBytes.Length + Body.Length];
        Buffer.BlockCopy(headBytes, 0, raw, 0, headBytes.Length);
        Buffer.BlockCopy(Body, 0, raw, headBytes.Length, Body.Length);
        return raw;
    }
}
