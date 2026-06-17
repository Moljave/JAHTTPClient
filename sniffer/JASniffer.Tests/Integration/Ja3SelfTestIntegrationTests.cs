using JASniffer.Core;
using JASniffer.Proxy;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Drives the loopback ClientHello self-test against the real engine and validates
/// the hand-rolled JA3 parser on a genuine Chrome ClientHello.
/// </summary>
[Collection("integration")]
public sealed class Ja3SelfTestIntegrationTests
{
    [Fact]
    public async Task SelfTest_CapturesAndParsesRealChromeClientHello()
    {
        var settings = new SnifferSettings { FingerprintPreset = "Chrome" };
        using var relay = new UpstreamRelay(settings);

        var report = await relay.CaptureClientHelloAsync(default);

        Assert.True(report.Ok, report.Error);
        Assert.Equal("Chrome 148", report.Preset);
        Assert.True(report.Bytes > 50);
        Assert.True(report.CipherCount > 0);
        Assert.True(report.ExtensionCount > 0);
        Assert.True(report.Tls13, "Chrome must advertise TLS 1.3 in supported_versions.");
        Assert.True(report.KeyShare, "Chrome must include the key_share extension.");
        Assert.True(report.Grease, "Chrome ClientHellos include GREASE values.");
        Assert.False(string.IsNullOrEmpty(report.Ja3));
        Assert.Matches("^[0-9a-f]{32}$", report.Ja3Md5);
    }

    [Fact]
    public async Task SelfTest_Firefox_AlsoParses()
    {
        var settings = new SnifferSettings { FingerprintPreset = "Firefox" };
        using var relay = new UpstreamRelay(settings);

        var report = await relay.CaptureClientHelloAsync(default);

        Assert.True(report.Ok, report.Error);
        Assert.Equal("Firefox", report.Preset);
        Assert.True(report.Tls13);
    }
}
