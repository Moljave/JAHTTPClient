using System.Text;

namespace JASniffer.Tests.Integration;

/// <summary>
/// End-to-end tests of the plain-HTTP proxying path: a raw client speaks to the
/// MITM listener exactly as a browser configured with an HTTP proxy would
/// (absolute-form request line), and the proxy re-issues upstream through the real
/// engine to a loopback origin. Exercises Http1Reader/Http1Request/ProxyConnection/
/// UpstreamRelay/WireResponse together.
/// </summary>
[Collection("integration")]
public sealed class ProxyServerIntegrationTests
{
    private static string AbsoluteGet(LoopbackOrigin origin, string path) =>
        $"GET {origin.BaseUrl}{path} HTTP/1.1\r\nHost: 127.0.0.1:{origin.Port}\r\nConnection: close\r\n\r\n";

    [Fact]
    public async Task PlainGet_IsProxied_AndCaptured()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("body-through-proxy") };
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var response = await RawHttp.SendAsync(proxy.Port, AbsoluteGet(origin, "/page?x=1"));

        Assert.Equal(200, response.Status);
        Assert.Equal("body-through-proxy", response.BodyText);
        // Body already decoded → proxy must send an accurate Content-Length and no chunking.
        Assert.Equal("18", response.Headers["Content-Length"]);
        Assert.False(response.Headers.ContainsKey("Transfer-Encoding"));

        var session = Assert.Single(proxy.Store.Snapshot());
        Assert.Equal("GET", session.Method);
        Assert.Equal("127.0.0.1", session.Host);
        Assert.Equal(origin.Port, session.Port);
        Assert.Equal("/page", session.Path);
        Assert.Equal("?x=1", session.Query);
        Assert.Equal(200, session.StatusCode);
        Assert.True(session.UpstreamOk);
    }

    [Fact]
    public async Task PlainPost_ForwardsBodyUpstream()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("accepted") };
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var payload = Encoding.UTF8.GetBytes("hello=world&n=2");
        var request =
            $"POST {origin.BaseUrl}/form HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{origin.Port}\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            $"Content-Length: {payload.Length}\r\n" +
            "Connection: close\r\n\r\n";

        var response = await RawHttp.SendAsync(proxy.Port, request, payload);

        Assert.Equal(200, response.Status);
        Assert.True(origin.Received.TryDequeue(out var got));
        Assert.Equal("POST", got!.Method);
        Assert.Equal("hello=world&n=2", got.BodyText);
    }

    [Fact]
    public async Task UpstreamStatusAndHeaders_PassThrough()
    {
        using var origin = new LoopbackOrigin
        {
            Handler = _ => OriginResponse.Json("{\"ok\":true}", status: 404).WithHeader("X-Custom", "v1"),
        };
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var response = await RawHttp.SendAsync(proxy.Port, AbsoluteGet(origin, "/missing"));

        Assert.Equal(404, response.Status);
        Assert.Equal("v1", response.Headers["X-Custom"]);
        Assert.Contains("json", response.Headers["Content-Type"]);
        Assert.Equal("{\"ok\":true}", response.BodyText);
    }

    [Fact]
    public async Task CaptureOff_StillProxies_ButRecordsNothing()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("still served") };
        await using var proxy = new ProxyHarness(s => s.Capture = false);
        await proxy.WaitUntilReadyAsync();

        var response = await RawHttp.SendAsync(proxy.Port, AbsoluteGet(origin, "/x"));

        Assert.Equal(200, response.Status);
        Assert.Equal("still served", response.BodyText);
        Assert.Empty(proxy.Store.Snapshot()); // nothing recorded
    }

    [Fact]
    public async Task UpstreamUnreachable_ReturnsGateway502()
    {
        var deadPort = LoopbackOrigin.FreeTcpPort();
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var request = $"GET http://127.0.0.1:{deadPort}/ HTTP/1.1\r\nHost: 127.0.0.1:{deadPort}\r\nConnection: close\r\n\r\n";
        var response = await RawHttp.SendAsync(proxy.Port, request);

        Assert.Equal(502, response.Status);
        var session = Assert.Single(proxy.Store.Snapshot());
        Assert.False(session.UpstreamOk);
        Assert.Equal(502, session.StatusCode);
    }

    [Fact]
    public async Task MalformedRequestLine_GetsBadRequest()
    {
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var response = await RawHttp.SendAsync(proxy.Port, "GET\r\nConnection: close\r\n\r\n");
        Assert.Equal(400, response.Status);
    }

    [Fact]
    public async Task KeepAlive_TwoRequestsOnOneConnection()
    {
        using var origin = new LoopbackOrigin { Handler = r => OriginResponse.Text("echo:" + r.PathAndQuery) };
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        // Two pipelined keep-alive requests, then close — both must be served in order.
        var req =
            $"GET {origin.BaseUrl}/one HTTP/1.1\r\nHost: 127.0.0.1:{origin.Port}\r\n\r\n" +
            $"GET {origin.BaseUrl}/two HTTP/1.1\r\nHost: 127.0.0.1:{origin.Port}\r\nConnection: close\r\n\r\n";

        var raw = await RawHttpRaw(proxy.Port, req);
        var text = Encoding.Latin1.GetString(raw);

        Assert.Contains("echo:/one", text);
        Assert.Contains("echo:/two", text);
        Assert.Equal(2, proxy.Store.Snapshot().Count);
    }

    // Reads the entire stream (possibly several pipelined responses) until EOF.
    private static async Task<byte[]> RawHttpRaw(int port, string requestText)
    {
        using var client = new System.Net.Sockets.TcpClient();
        await client.ConnectAsync(System.Net.IPAddress.Loopback, port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.Latin1.GetBytes(requestText));
        await stream.FlushAsync();

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
