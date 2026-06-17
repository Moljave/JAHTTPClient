using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;
using JASniffer.Core.Certificates;
using JASniffer.Proxy;
using JASniffer.Proxy.Fingerprint;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Drives the real engine at the fingerprint-capture HTTPS endpoint (standing in for the
/// browser) and asserts the endpoint records the ClientHello and that the captured spec
/// reproduces. The live-browser leg is validated by the user; this proves the server side.
/// </summary>
[Collection("integration")]
public sealed class CaptureEndpointTests : IDisposable
{
    private readonly string _caDir = Path.Combine(Path.GetTempPath(), "JASnifferCapCA-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_caDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task CaptureEndpoint_RecordsFingerprint_AndItReproduces()
    {
        var ca = CertificateAuthority.LoadOrCreate(_caDir);
        var store = new FingerprintStore();
        var port = LoopbackOrigin.FreeTcpPort();
        var server = new FingerprintCaptureServer(store, ca, NullLogger.Instance) { Port = port, CaptureHost = "localhost" };

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = Task.Run(() => server.RunAsync(cts.Token));
        await WaitReadyAsync(port, cts.Token);

        using (var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = Ja3Preset.Chrome,
            InsecureSkipVerify = true,
            Timeout = TimeSpan.FromSeconds(10),
            MaxRetries = 0,
        }))
        {
            using var resp = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"https://127.0.0.1:{port}/"));
            Assert.Equal(200, (int)resp.StatusCode);
            var html = await resp.Content.ReadAsStringAsync();
            Assert.Contains("отпеч", html); // the confirmation page
        }

        var captured = Assert.Single(store.All());
        Assert.False(string.IsNullOrEmpty(captured.Ja3));
        Assert.StartsWith("t1", captured.Ja4);
        Assert.NotNull(captured.Spec);

        // Activate it and confirm the spec replays to the same JA3.
        Assert.True(store.SetActive(captured.Id));
        Assert.NotNull(store.ActiveSpec);

        var repro = ClientHelloFingerprint.Parse(await Ja3SelfTest.CaptureRawHelloAsync(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            CustomTlsClient = store.ActiveSpec,
            InsecureSkipVerify = true,
            Timeout = TimeSpan.FromSeconds(3),
            MaxRetries = 0,
        }, default));
        Assert.True(repro.Ok, repro.Error);
        Assert.Equal(captured.Ja3, repro.Ja3);

        cts.Cancel();
        try { await run; } catch { /* shutdown */ }
    }

    private static async Task WaitReadyAsync(int port, CancellationToken ct)
    {
        for (var i = 0; i < 100; i++)
        {
            try
            {
                using var probe = new TcpClient();
                await probe.ConnectAsync(IPAddress.Loopback, port, ct);
                return;
            }
            catch
            {
                await Task.Delay(25, ct);
            }
        }
    }
}
