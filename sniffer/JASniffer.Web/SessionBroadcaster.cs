using System.Threading.Channels;
using Microsoft.AspNetCore.SignalR;
using JASniffer.Core;
using JASniffer.Core.Models;

namespace JASniffer.Web;

/// <summary>
/// Bridges <see cref="SessionStore"/> change events onto SignalR. Updates are
/// coalesced into ~100 ms batches so a burst of traffic (a page loading dozens of
/// resources) results in a handful of pushes rather than one per request, keeping
/// the UI smooth under load.
/// </summary>
public sealed class SessionBroadcaster : BackgroundService
{
    private const int FlushIntervalMs = 100;
    private const int MaxBatch = 500;

    private readonly SessionStore _store;
    private readonly IHubContext<SessionHub> _hub;
    private readonly Channel<Signal> _channel =
        Channel.CreateUnbounded<Signal>(new UnboundedChannelOptions { SingleReader = true });

    public SessionBroadcaster(SessionStore store, IHubContext<SessionHub> hub)
    {
        _store = store;
        _hub = hub;
        _store.SessionChanged += OnSessionChanged;
    }

    private void OnSessionChanged(CapturedSession session, SessionChangeKind kind)
        => _channel.Writer.TryWrite(new Signal(session, kind));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var pending = new Dictionary<int, SessionSummaryDto>();
        var removed = new HashSet<int>();
        var reader = _channel.Reader;

        try
        {
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                pending.Clear();
                removed.Clear();
                var cleared = false;

                // Drain everything currently queued, collapsing repeated updates of
                // the same session to its latest summary. Check the cap BEFORE reading so
                // a signal is never consumed-then-dropped when the batch is full — any
                // overflow stays queued for the next cycle.
                while (pending.Count < MaxBatch && reader.TryRead(out var signal))
                {
                    switch (signal.Kind)
                    {
                        case SessionChangeKind.Cleared:
                            cleared = true;
                            pending.Clear();
                            removed.Clear();
                            break;
                        case SessionChangeKind.Removed when signal.Session is { } r:
                            pending.Remove(r.Id);
                            removed.Add(r.Id);
                            break;
                        default:
                            if (signal.Session is { } s)
                            {
                                pending[s.Id] = DtoMapper.ToSummary(s);
                                removed.Remove(s.Id);
                            }

                            break;
                    }
                }

                if (cleared)
                {
                    await _hub.Clients.All.SendAsync("cleared", stoppingToken).ConfigureAwait(false);
                }

                if (removed.Count > 0)
                {
                    await _hub.Clients.All.SendAsync("removed", removed.ToArray(), stoppingToken).ConfigureAwait(false);
                }

                if (pending.Count > 0)
                {
                    await _hub.Clients.All.SendAsync("sessions", pending.Values.ToArray(), stoppingToken).ConfigureAwait(false);
                }

                await Task.Delay(FlushIntervalMs, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    public override void Dispose()
    {
        _store.SessionChanged -= OnSessionChanged;
        base.Dispose();
    }

    private readonly record struct Signal(CapturedSession? Session, SessionChangeKind Kind);
}
