using JASniffer.Proxy;

namespace JASniffer.Web;

/// <summary>
/// Runs the MITM <see cref="ProxyServer"/> for the lifetime of the web host, so a
/// single <c>dotnet run</c> brings up both the UI and the proxy in one process.
/// </summary>
public sealed class ProxyHostedService(ProxyServer server, ILogger<ProxyHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await server.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Host is shutting down.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "The MITM proxy stopped unexpectedly.");
        }
    }
}
