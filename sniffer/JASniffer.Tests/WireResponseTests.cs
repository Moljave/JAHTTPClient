using System.Text;
using JASniffer.Core.Models;
using JASniffer.Proxy;

namespace JASniffer.Tests;

public class WireResponseTests
{
    private static async Task<string> Write(RelayResult result, bool keepAlive)
    {
        using var ms = new MemoryStream();
        await WireResponse.WriteAsync(ms, result, keepAlive, default);
        return Encoding.Latin1.GetString(ms.ToArray());
    }

    [Fact]
    public async Task WriteAsync_StatusLineHeadersAndBody()
    {
        var result = new RelayResult
        {
            Status = 200,
            Reason = "OK",
            Headers = new List<HeaderEntry> { new("Content-Type", "text/plain") },
            Body = Encoding.Latin1.GetBytes("hi"),
        };
        var wire = await Write(result, keepAlive: true);

        Assert.StartsWith("HTTP/1.1 200 OK\r\n", wire);
        Assert.Contains("Content-Type: text/plain\r\n", wire);
        Assert.Contains("Content-Length: 2\r\n", wire);
        Assert.Contains("Connection: keep-alive\r\n", wire);
        Assert.EndsWith("\r\n\r\nhi", wire);
    }

    [Fact]
    public async Task WriteAsync_DropsHopByHopAndFramingHeaders()
    {
        var result = new RelayResult
        {
            Status = 200,
            Reason = "OK",
            Headers = new List<HeaderEntry>
            {
                new("Content-Encoding", "gzip"),
                new("Transfer-Encoding", "chunked"),
                new("Connection", "keep-alive"),
                new("Keep-Alive", "timeout=5"),
                new("Content-Length", "999"),
                new("Upgrade", "h2c"),
                new("X-Keep", "yes"),
            },
            Body = Encoding.Latin1.GetBytes("body"),
        };
        var wire = await Write(result, keepAlive: false);

        Assert.DoesNotContain("Content-Encoding", wire);
        Assert.DoesNotContain("Transfer-Encoding", wire);
        Assert.DoesNotContain("Keep-Alive: timeout=5", wire);
        Assert.DoesNotContain("Upgrade", wire);
        Assert.DoesNotContain("999", wire);
        Assert.Contains("X-Keep: yes\r\n", wire);
        Assert.Contains("Content-Length: 4\r\n", wire);
        Assert.Contains("Connection: close\r\n", wire); // exactly one Connection header, value from keepAlive
    }

    [Fact]
    public async Task WriteAsync_EmptyReasonDefaultsToOk()
    {
        var result = new RelayResult { Status = 200, Reason = "", Body = [] };
        var wire = await Write(result, keepAlive: true);
        Assert.StartsWith("HTTP/1.1 200 OK\r\n", wire);
    }

    [Fact]
    public async Task WriteStatusAsync_WritesPlainTextStatus()
    {
        using var ms = new MemoryStream();
        await WireResponse.WriteStatusAsync(ms, 400, "Bad Request", "nope", default);
        var wire = Encoding.UTF8.GetString(ms.ToArray());

        Assert.StartsWith("HTTP/1.1 400 Bad Request\r\n", wire);
        Assert.Contains("Content-Type: text/plain; charset=utf-8\r\n", wire);
        Assert.Contains("Content-Length: 4\r\n", wire);
        Assert.Contains("Connection: close\r\n", wire);
        Assert.EndsWith("\r\n\r\nnope", wire);
    }

    [Fact]
    public async Task WriteStatusAsync_NullBodyIsZeroLength()
    {
        using var ms = new MemoryStream();
        await WireResponse.WriteStatusAsync(ms, 502, "Bad Gateway", null, default);
        var wire = Encoding.UTF8.GetString(ms.ToArray());
        Assert.Contains("Content-Length: 0\r\n", wire);
        Assert.EndsWith("\r\n\r\n", wire);
    }
}
