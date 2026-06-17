using System.Text;
using JASniffer.Core;
using JASniffer.Core.Models;
using JASniffer.Proxy;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Exercises the upstream leg for real: <see cref="UpstreamRelay.ComposeAsync"/>
/// drives the native <c>JAHTTPClient</c> engine against a loopback origin and we
/// assert on the captured session. No external network is used.
/// </summary>
[Collection("integration")]
public sealed class UpstreamRelayIntegrationTests
{
    [Fact]
    public async Task Compose_Get_RecordsSuccessfulSession()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("hello-from-origin") };
        var settings = new SnifferSettings();
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/hi", [], [], default);

        var session = store.Get(id)!;
        Assert.True(session.UpstreamOk, session.Error);
        Assert.Equal(200, session.StatusCode);
        Assert.Equal("hello-from-origin", Encoding.UTF8.GetString(session.ResponseBody));
        Assert.Equal("hello-from-origin".Length, session.BodyLength);
        Assert.True(session.Completed);
        Assert.False(string.IsNullOrEmpty(session.ResponseHttpVersion));
    }

    [Fact]
    public async Task Compose_Post_ForwardsBodyAndCustomHeaderButNotHostVerbatim()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("got it") };
        var settings = new SnifferSettings();
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var headers = new List<HeaderEntry>
        {
            new("Host", "spoofed.example"),   // must NOT be forwarded verbatim
            new("X-Test", "marker-123"),
            new("Content-Type", "text/plain"),
        };
        var id = await relay.ComposeAsync(store, "POST", origin.BaseUrl + "/submit", headers, Encoding.UTF8.GetBytes("payload-body"), default);

        Assert.True(origin.Received.TryDequeue(out var got));
        Assert.Equal("POST", got!.Method);
        Assert.Equal("/submit", got.PathAndQuery);
        Assert.Equal("payload-body", got.BodyText);
        Assert.Equal("marker-123", got.Headers["X-Test"]);
        Assert.Equal($"127.0.0.1:{origin.Port}", got.Headers["Host"]); // rewritten to the real authority

        Assert.True(store.Get(id)!.UpstreamOk);
    }

    [Fact]
    public async Task Compose_FaithfulMode_ForwardsCookieHeaderVerbatim()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("ok") };
        var settings = new SnifferSettings { SmartRedirects = false }; // faithful (jar off)
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var headers = new List<HeaderEntry> { new("Cookie", "a=1; b=2") };
        await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/c", headers, [], default);

        Assert.True(origin.Received.TryDequeue(out var got));
        Assert.Equal("a=1; b=2", got!.Headers["Cookie"]);
    }

    [Fact]
    public async Task Compose_UpstreamError_RecordsGateway502()
    {
        // Point at a port nobody is listening on → transport failure, no HTTP response.
        var deadPort = LoopbackOrigin.FreeTcpPort();
        var settings = new SnifferSettings();
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", $"http://127.0.0.1:{deadPort}/", [], [], default);

        var session = store.Get(id)!;
        Assert.False(session.UpstreamOk);
        Assert.Equal(502, session.StatusCode);
        Assert.False(string.IsNullOrEmpty(session.Error));
    }

    [Fact]
    public async Task Compose_NonAbsoluteUrl_Throws()
    {
        var settings = new SnifferSettings();
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            relay.ComposeAsync(store, "GET", "/relative/path", [], [], default));
    }

    [Fact]
    public async Task TestProxy_UnparseableString_ReportsError()
    {
        var settings = new SnifferSettings();
        using var relay = new UpstreamRelay(settings);

        var result = await relay.TestProxyAsync("this is not a proxy", default);

        Assert.False(result.Ok);
        Assert.False(string.IsNullOrEmpty(result.Error));
    }

    [Fact]
    public void CurrentPresetLabel_ReflectsConfiguredPreset()
    {
        using var chrome = new UpstreamRelay(new SnifferSettings { FingerprintPreset = "Chrome" });
        Assert.Equal("Chrome 148", chrome.CurrentPresetLabel);

        using var firefox = new UpstreamRelay(new SnifferSettings { FingerprintPreset = "Firefox" });
        Assert.Equal("Firefox", firefox.CurrentPresetLabel);
    }
}
