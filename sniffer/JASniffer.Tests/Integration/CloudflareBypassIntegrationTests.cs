using System.Text;
using JASniffer.Core;
using JASniffer.Proxy;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Verifies Cloudflare-challenge detection and the automatic raw-tunnel bypass on the
/// real engine over loopback: a challenge response makes the host auto-bypass so the
/// browser can solve the captcha directly on reload.
/// </summary>
[Collection("integration")]
public sealed class CloudflareBypassIntegrationTests
{
    [Fact]
    public async Task CfMitigatedHeader_FlagsChallenge_AndAutoBypassesHost()
    {
        using var origin = new LoopbackOrigin
        {
            Handler = _ => OriginResponse.Text("blocked", 403)
                .WithHeader("cf-mitigated", "challenge")
                .WithHeader("cf-ray", "8abc-LHR"),
        };
        var settings = new SnifferSettings { AutoBypassCloudflare = true };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/", [], [], default);

        Assert.True(store.Get(id)!.CfChallenge);
        Assert.True(settings.IsBypassed("127.0.0.1"));        // host now tunnels directly
        Assert.True(settings.IsBypassed("sub.127.0.0.1"));    // and its subdomains
    }

    [Fact]
    public async Task InterstitialBody_FlagsChallenge()
    {
        var html = Encoding.UTF8.GetBytes(
            "<html><head><script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\"></script></head><body>Just a moment…</body></html>");
        using var origin = new LoopbackOrigin
        {
            Handler = _ => new OriginResponse(503, "Service Unavailable", "text/html", html).WithHeader("cf-ray", "8xyz-LHR"),
        };
        var settings = new SnifferSettings { AutoBypassCloudflare = true };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/", [], [], default);

        Assert.True(store.Get(id)!.CfChallenge);
        Assert.True(settings.IsBypassed("127.0.0.1"));
    }

    [Fact]
    public async Task NormalResponse_NotFlagged_NotBypassed()
    {
        using var origin = new LoopbackOrigin { Handler = _ => OriginResponse.Text("hello") };
        var settings = new SnifferSettings { AutoBypassCloudflare = true };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/", [], [], default);

        Assert.False(store.Get(id)!.CfChallenge);
        Assert.False(settings.IsBypassed("127.0.0.1"));
    }

    [Fact]
    public async Task PlainCloudflareHeaderWithoutChallenge_IsNotFlagged()
    {
        // A normal Cloudflare-fronted 200 (cf-ray present, no challenge) must NOT be treated
        // as a challenge — otherwise every CF site would stop being inspected.
        using var origin = new LoopbackOrigin
        {
            Handler = _ => OriginResponse.Json("{\"ok\":true}").WithHeader("cf-ray", "8def-LHR"),
        };
        var settings = new SnifferSettings { AutoBypassCloudflare = true };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/", [], [], default);

        Assert.False(store.Get(id)!.CfChallenge);
        Assert.False(settings.IsBypassed("127.0.0.1"));
    }

    [Fact]
    public async Task ChallengeDetected_ButToggleOff_DoesNotBypass()
    {
        using var origin = new LoopbackOrigin
        {
            Handler = _ => OriginResponse.Text("blocked", 403).WithHeader("cf-mitigated", "challenge"),
        };
        var settings = new SnifferSettings { AutoBypassCloudflare = false };
        using var relay = new UpstreamRelay(settings);
        var store = new SessionStore(settings);

        var id = await relay.ComposeAsync(store, "GET", origin.BaseUrl + "/", [], [], default);

        Assert.True(store.Get(id)!.CfChallenge);          // still surfaced for visibility
        Assert.False(settings.IsBypassed("127.0.0.1"));   // but not auto-tunneled
    }
}
