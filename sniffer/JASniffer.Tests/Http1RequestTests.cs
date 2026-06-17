using System.Text;
using JASniffer.Proxy;

namespace JASniffer.Tests;

public class Http1RequestTests
{
    private static Http1Reader Reader(string data) => new(new MemoryStream(Encoding.Latin1.GetBytes(data)));

    [Fact]
    public void Parse_AbsoluteForm_PlainProxy()
    {
        var req = Http1Request.Parse("GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com", secure: false, null, 0);
        Assert.NotNull(req);
        Assert.Equal("GET", req!.Method);
        Assert.Equal("http", req.Scheme);
        Assert.Equal("example.com", req.Host);
        Assert.Equal(80, req.Port);
        Assert.Equal("/path", req.Path);
        Assert.Equal("?q=1", req.Query);
        Assert.Equal("http://example.com/path?q=1", req.Url);
    }

    [Fact]
    public void Parse_OriginForm_InsideConnectTunnel_UsesTunnelAuthority()
    {
        var req = Http1Request.Parse("GET /p HTTP/1.1\r\nHost: example.com", secure: true, "example.com", 443);
        Assert.NotNull(req);
        Assert.Equal("https", req!.Scheme);
        Assert.Equal("example.com", req.Host);
        Assert.Equal(443, req.Port);
        Assert.Equal("/p", req.Path);
        Assert.Equal("https://example.com/p", req.Url); // default port omitted
    }

    [Fact]
    public void Parse_OriginForm_NonDefaultTunnelPort_IsInUrl()
    {
        var req = Http1Request.Parse("GET /p HTTP/1.1\r\nHost: example.com", secure: true, "example.com", 8443);
        Assert.Equal(8443, req!.Port);
        Assert.Equal("https://example.com:8443/p", req.Url);
    }

    [Fact]
    public void Parse_OriginForm_PlainWithHostHeaderPort()
    {
        var req = Http1Request.Parse("GET /p HTTP/1.1\r\nHost: h.local:8080", secure: false, null, 0);
        Assert.Equal("h.local", req!.Host);
        Assert.Equal(8080, req.Port);
        Assert.Equal("http://h.local:8080/p", req.Url);
    }

    [Fact]
    public void Parse_EmptyPathBecomesSlash()
    {
        var req = Http1Request.Parse("GET  HTTP/1.1\r\nHost: example.com", secure: true, "example.com", 443);
        // "GET  HTTP/1.1" splits into 3 parts with an empty target → normalized to "/".
        Assert.Equal("/", req!.Path);
    }

    [Theory]
    [InlineData("")]
    [InlineData("GET")]
    [InlineData("GET /")]
    public void Parse_MalformedRequestLine_ReturnsNull(string line)
        => Assert.Null(Http1Request.Parse(line, secure: false, null, 0));

    [Fact]
    public void Parse_HeaderFolding_ContinuationIsJoined()
    {
        var req = Http1Request.Parse("GET / HTTP/1.1\r\nX-Long: part1\r\n\tpart2\r\nHost: x", secure: true, "x", 443);
        var value = req!.Headers.First(h => h.Name == "X-Long").Value;
        Assert.Equal("part1 part2", value);
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket")]
    [InlineData("GET / HTTP/1.1\r\nUpgrade: h2c")]
    [InlineData("GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==")]
    public void Parse_DetectsUpgrade(string block)
        => Assert.True(Http1Request.Parse(block, secure: true, "x", 443)!.IsUpgrade);

    [Fact]
    public void Parse_DetectsEventStream()
    {
        var req = Http1Request.Parse("GET / HTTP/1.1\r\nAccept: text/event-stream", secure: true, "x", 443);
        Assert.True(req!.IsEventStream);
    }

    [Fact]
    public void Parse_WantsClose_Http10DefaultsClose()
    {
        Assert.True(Http1Request.Parse("GET / HTTP/1.0\r\nHost: x", secure: true, "x", 443)!.WantsClose);
        Assert.False(Http1Request.Parse("GET / HTTP/1.1\r\nHost: x", secure: true, "x", 443)!.WantsClose);
    }

    [Fact]
    public void Parse_WantsClose_HonorsConnectionHeader()
    {
        Assert.True(Http1Request.Parse("GET / HTTP/1.1\r\nConnection: close", secure: true, "x", 443)!.WantsClose);
        Assert.False(Http1Request.Parse("GET / HTTP/1.0\r\nConnection: keep-alive", secure: true, "x", 443)!.WantsClose);
    }

    [Fact]
    public async Task ReadBody_ContentLength()
    {
        var reader = Reader("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello-extra");
        var req = Http1Request.Parse((await reader.ReadHeaderBlockAsync(default))!, secure: true, "x", 443)!;
        var body = await Http1Request.ReadBodyAsync(req, reader, default);
        Assert.Equal("hello", Encoding.Latin1.GetString(body));
    }

    [Fact]
    public async Task ReadBody_Chunked()
    {
        var reader = Reader("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
        var req = Http1Request.Parse((await reader.ReadHeaderBlockAsync(default))!, secure: true, "x", 443)!;
        var body = await Http1Request.ReadBodyAsync(req, reader, default);
        Assert.Equal("abc", Encoding.Latin1.GetString(body));
    }

    [Fact]
    public async Task ReadBody_NoneIsEmpty()
    {
        var reader = Reader("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        var req = Http1Request.Parse((await reader.ReadHeaderBlockAsync(default))!, secure: true, "x", 443)!;
        var body = await Http1Request.ReadBodyAsync(req, reader, default);
        Assert.Empty(body);
    }

    [Fact]
    public void ToRawBytes_RoundTripsRequestLineHeadersAndBody()
    {
        var req = Http1Request.Parse("POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-H: v", secure: true, "x", 443)!;
        req.Body = Encoding.Latin1.GetBytes("data");
        var raw = Encoding.Latin1.GetString(req.ToRawBytes());
        Assert.Equal("POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-H: v\r\n\r\ndata", raw);
    }
}
