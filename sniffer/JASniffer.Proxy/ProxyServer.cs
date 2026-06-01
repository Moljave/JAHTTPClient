using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using JASniffer.Core;
using JASniffer.Core.Certificates;

namespace JASniffer.Proxy;

/// <summary>
/// The MITM listener. Accepts browser connections on <c>127.0.0.1:8866</c> and
/// dispatches each to a <see cref="ProxyConnection"/>. One slow or misbehaving
/// client never blocks others: every connection is handled on its own task and a
/// failure there is logged, not fatal.
/// </summary>
public sealed class ProxyServer(
    SnifferSettings settings,
    SessionStore store,
    UpstreamRelay relay,
    CertificateAuthority ca,
    ILogger<ProxyServer> logger)
{
    /// <summary>Loopback port the proxy listens on. The browser/system proxy points here.</summary>
    public int Port { get; init; } = 8866;

    /// <summary>Address to bind. Loopback by default so the proxy is not exposed on the network.</summary>
    public IPAddress Address { get; init; } = IPAddress.Loopback;

    /// <summary>Runs the accept loop until <paramref name="ct"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(Address, Port);
        listener.Start();
        logger.LogInformation("JASniffer proxy listening on {Address}:{Port}", Address, Port);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex)
                {
                    logger.LogDebug(ex, "Accept failed; continuing.");
                    continue;
                }

                _ = HandleAsync(client, ct);
            }
        }
        finally
        {
            listener.Stop();
            logger.LogInformation("JASniffer proxy stopped.");
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            var connection = new ProxyConnection(client, settings, store, relay, ca, logger);
            await connection.ProcessAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown or client cancellation — nothing to report.
        }
        catch (IOException)
        {
            // Routine: the browser reset/closed the connection mid-exchange.
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Unhandled error while serving a proxy connection.");
        }
        finally
        {
            client.Dispose();
        }
    }
}
