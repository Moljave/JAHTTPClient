using System.IO.Compression;
using System.Text;
using JASniffer.Core;
using JASniffer.Proxy;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Feature-level checks of the upstream leg: the smart-redirects toggle (faithful vs
/// follow) and the "body is already decoded" contract (no double Content-Encoding on
/// the browser leg).
/// </summary>
[Collection("integration")]
public sealed class UpstreamBehaviorIntegrationTests
{
    private static LoopbackOrigin RedirectingOrigin()
    {
        var origin = new LoopbackOrigin();
        origin.Handler = r => r.PathAndQuery.StartsWith("/start")
            ? new OriginResponse(302, "Found", null, []).WithHeader("Location", $"{origin.BaseUrl}/end")
            : OriginResponse.Text("final-destination");
        return origin;
    }

    [Fact]
    public async Task SmartRedirectsOff_ReturnsRawRedirect()
    {
        using var origin = RedirectingOrigin();
        var settings = new SnifferSettings { SmartRedirects = false };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/start", [], [], default);

        var session = store.Get(id)!;
        Assert.Equal(302, session.StatusCode);
        Assert.False(session.FollowedRedirects);
    }

    [Fact]
    public async Task SmartRedirectsOn_FollowsToFinalResponse()
    {
        using var origin = RedirectingOrigin();
        var settings = new SnifferSettings { SmartRedirects = true };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/start", [], [], default);

        var session = store.Get(id)!;
        Assert.Equal(200, session.StatusCode);
        Assert.Equal("final-destination", Encoding.UTF8.GetString(session.ResponseBody));
        Assert.True(session.FollowedRedirects);
        Assert.EndsWith("/end", session.FinalUrl);
    }

    [Fact]
    public async Task GzipResponse_IsDecoded_AndBrowserGetsPlainBytesWithNoContentEncoding()
    {
        var compressed = Gzip("the-decompressed-content");
        using var origin = new LoopbackOrigin
        {
            Handler = _ => new OriginResponse(200, "OK", "text/plain", compressed).WithHeader("Content-Encoding", "gzip"),
        };
        await using var proxy = new ProxyHarness();
        await proxy.WaitUntilReadyAsync();

        var request = $"GET {origin.BaseUrl}/gz HTTP/1.1\r\nHost: 127.0.0.1:{origin.Port}\r\nConnection: close\r\n\r\n";
        var response = await RawHttp.SendAsync(proxy.Port, request);

        Assert.Equal(200, response.Status);
        // The browser must receive the already-decoded body...
        Assert.Equal("the-decompressed-content", response.BodyText);
        // ...with an accurate Content-Length and WITHOUT a Content-Encoding header
        // (otherwise the browser would try to gunzip plain bytes).
        Assert.False(response.Headers.ContainsKey("Content-Encoding"));
        Assert.Equal("the-decompressed-content".Length.ToString(), response.Headers["Content-Length"]);
    }

    private static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            gz.Write(bytes, 0, bytes.Length);
        }

        return ms.ToArray();
    }
}
