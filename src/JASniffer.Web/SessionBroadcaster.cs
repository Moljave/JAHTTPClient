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
    {
        var signal = kind == SessionChangeKind.Cleared ? Signal.Clear() : Signal.For(session);
        _channel.Writer.TryWrite(signal);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var pending = new Dictionary<int, SessionSummaryDto>();
        var reader = _channel.Reader;

        try
        {
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                pending.Clear();
                var cleared = false;

                // Drain everything currently queued, collapsing repeated updates of
                // the same session to its latest summary.
                while (reader.TryRead(out var signal) && pending.Count < MaxBatch)
                {
                    if (signal.Cleared)
                    {
                        cleared = true;
                        pending.Clear();
                    }
                    else if (signal.Session is { } s)
                    {
                        pending[s.Id] = DtoMapper.ToSummary(s);
                    }
                }

                if (cleared)
                {
                    await _hub.Clients.All.SendAsync("cleared", stoppingToken).ConfigureAwait(false);
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

    private readonly record struct Signal(CapturedSession? Session, bool Cleared)
    {
        public static Signal For(CapturedSession s) => new(s, false);
        public static Signal Clear() => new(null, true);
    }
}
