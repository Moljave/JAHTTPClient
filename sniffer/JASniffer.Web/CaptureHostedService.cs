using JASniffer.Proxy.Fingerprint;

namespace JASniffer.Web;

/// <summary>Runs the fingerprint-capture HTTPS endpoint for the lifetime of the host.</summary>
public sealed class CaptureHostedService(FingerprintCaptureServer server, ILogger<CaptureHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await server.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Host shutting down.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "The fingerprint capture endpoint stopped unexpectedly.");
        }
    }
}
