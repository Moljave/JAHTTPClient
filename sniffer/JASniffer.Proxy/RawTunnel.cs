using System.Buffers;
using JASniffer.Core.Models;

namespace JASniffer.Proxy;

/// <summary>
/// A transparent, uninspected byte pump between the browser leg and the origin,
/// used for traffic <c>JAHTTPClient</c> can't buffer (WebSocket / SSE / HTTP
/// upgrade, or a CONNECT to a non-HTTP port). It keeps the browser working at the
/// cost of fingerprinting/inspection for that one session.
/// </summary>
internal static class RawTunnel
{
    /// <summary>Pumps bytes both ways until either side closes, tallying volume onto the session.</summary>
    public static async Task PipeAsync(Stream browser, Stream origin, CapturedSession session, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var up = PumpAsync(browser, origin, n => session.TunnelBytesUp += n, linked.Token);
        var down = PumpAsync(origin, browser, n => session.TunnelBytesDown += n, linked.Token);

        await Task.WhenAny(up, down).ConfigureAwait(false);
        linked.Cancel();

        try
        {
            await Task.WhenAll(up, down).ConfigureAwait(false);
        }
        catch
        {
            // Either direction tearing down is the normal way a tunnel ends.
        }
    }

    private static async Task PumpAsync(Stream from, Stream to, Action<int> tally, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(32 * 1024);
        try
        {
            int read;
            while ((read = await from.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                await to.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
                tally(read);
            }
        }
        catch
        {
            // Swallow: a closed/reset peer is the expected tunnel termination.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
