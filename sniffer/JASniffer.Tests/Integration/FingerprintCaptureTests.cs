using JAHTTPClient;
using JAHTTPClient.Fingerprinting;
using JASniffer.Proxy;
using JASniffer.Proxy.Fingerprint;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Proves the full-spec capture pipeline end to end against the real engine: capture a
/// ClientHello, extract a complete <c>CustomTlsClient</c> (JA3 + supported versions +
/// key-share curves + sig-algs + ALPN + cert-compression), replay it, and require the
/// reproduced ClientHello to carry the identical JA3. This is exactly what a captured
/// browser fingerprint will ride on (the browser leg is validated by the user).
/// </summary>
[Collection("integration")]
public sealed class FingerprintCaptureTests
{
    private static ChromeHttpClientOptions Preset(Ja3Preset p) => new()
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = p,
        InsecureSkipVerify = true,
        Timeout = TimeSpan.FromSeconds(3),
        MaxRetries = 0,
    };

    private static ChromeHttpClientOptions Replay(CapturedTlsFingerprint fp) => new()
    {
        EnableJa3Fingerprinting = true,
        CustomTlsClient = fp.Custom,
        InsecureSkipVerify = true,
        Timeout = TimeSpan.FromSeconds(3),
        MaxRetries = 0,
    };

    // The loopback capture is occasionally empty (accept/timing race over ephemeral
    // ports); retry a few times so a flaky miss doesn't fail the assertion. A genuine
    // spec-build failure stays empty across all attempts and still fails the test.
    private static async Task<CapturedTlsFingerprint> CaptureAsync(ChromeHttpClientOptions opts)
    {
        CapturedTlsFingerprint fp = null!;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            fp = ClientHelloFingerprint.Parse(await Ja3SelfTest.CaptureRawHelloAsync(opts, default));
            if (fp.Ok)
            {
                return fp;
            }

            await Task.Delay(150);
        }

        return fp;
    }

    [Fact]
    public async Task CapturedChromeFingerprint_ParsesAndReproducesFaithfully()
    {
        var fp1 = await CaptureAsync(Preset(Ja3Preset.Chrome));
        Assert.True(fp1.Ok, fp1.Error);
        Assert.NotNull(fp1.Custom);
        Assert.True(fp1.Tls13);
        Assert.True(fp1.CipherCount > 0 && fp1.ExtensionCount > 0);
        Assert.Matches("^[0-9a-f]{32}$", fp1.Ja3Md5);
        Assert.StartsWith("t13", fp1.Ja4);

        var fp2 = await CaptureAsync(Replay(fp1));
        Assert.True(fp2.Ok, fp2.Error);
        Assert.Equal(fp1.Ja3, fp2.Ja3);
    }

    [Fact]
    public async Task CapturedFirefoxFingerprint_ReproducesAndDiffersFromChrome()
    {
        var chrome = await CaptureAsync(Preset(Ja3Preset.Chrome));
        var ff = await CaptureAsync(Preset(Ja3Preset.Firefox));
        Assert.True(ff.Ok, ff.Error);
        Assert.NotEqual(chrome.Ja3, ff.Ja3);

        // Reproduce Firefox via the custom path; if the spec were ignored it would come
        // back as the default Chrome JA3.
        var repro = await CaptureAsync(Replay(ff));
        Assert.True(repro.Ok, repro.Error);
        Assert.Equal(ff.Ja3, repro.Ja3);
    }
}
