using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using JASniffer.Core;
using JASniffer.Core.Certificates;
using JASniffer.Proxy;

namespace JASniffer.Tests.Integration;

/// <summary>
/// Spins up the full MITM proxy stack (settings + session store + upstream relay +
/// CA + listener) on a free loopback port, driving the real <c>JAHTTPClient</c>
/// engine on the upstream leg. Disposing tears the listener and relay down.
/// </summary>
internal sealed class ProxyHarness : IAsyncDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _run;
    private readonly string _caDir;

    public SnifferSettings Settings { get; }
    public SessionStore Store { get; }
    public UpstreamRelay Relay { get; }
    public int Port { get; }

    public ProxyHarness(Action<SnifferSettings>? configure = null)
    {
        Settings = new SnifferSettings();
        configure?.Invoke(Settings);
        Store = new SessionStore(Settings);
        Relay = new UpstreamRelay(Settings);
        _caDir = Path.Combine(Path.GetTempPath(), "JASnifferTestsCA-" + Guid.NewGuid().ToString("N"));
        var ca = CertificateAuthority.LoadOrCreate(_caDir);
        Port = LoopbackOrigin.FreeTcpPort();

        var server = new ProxyServer(Settings, Store, Relay, ca, NullLogger<ProxyServer>.Instance)
        {
            Port = Port,
            Address = IPAddress.Loopback,
        };
        _run = Task.Run(() => server.RunAsync(_cts.Token));
    }

    /// <summary>Waits until the listener accepts a TCP connection (bind completed).</summary>
    public async Task WaitUntilReadyAsync(TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var probe = new System.Net.Sockets.TcpClient();
                await probe.ConnectAsync(IPAddress.Loopback, Port).ConfigureAwait(false);
                return;
            }
            catch
            {
                await Task.Delay(25).ConfigureAwait(false);
            }
        }

        throw new TimeoutException($"Proxy did not start listening on port {Port}.");
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { await _run.ConfigureAwait(false); } catch { /* shutdown */ }
        Relay.Dispose();
        _cts.Dispose();
        try { Directory.Delete(_caDir, recursive: true); } catch { /* best effort */ }
    }
}
