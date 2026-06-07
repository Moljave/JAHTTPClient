using System.Collections.Concurrent;
using JASniffer.Core.Models;

namespace JASniffer.Core;

/// <summary>
/// Thread-safe, in-memory store of captured sessions plus an id generator. New
/// and updated sessions are surfaced through <see cref="SessionChanged"/> so the
/// web layer can batch them onto SignalR. A bounded ring keeps memory flat over a
/// long capture: the oldest sessions are evicted once <see cref="SnifferSettings.MaxSessions"/>
/// is exceeded.
/// </summary>
public sealed class SessionStore(SnifferSettings settings)
{
    private readonly SnifferSettings _settings = settings;

    // Insertion-ordered map; the lock guards eviction + id assignment. A
    // ConcurrentDictionary alone can't give us ordered eviction, so we pair it
    // with a queue of live ids under the same lock.
    private readonly Dictionary<int, CapturedSession> _byId = [];
    private readonly Queue<int> _order = [];
    private readonly Lock _gate = new();
    private int _nextId;

    /// <summary>Raised when a session is first added and again whenever it is updated/completed.</summary>
    public event Action<CapturedSession, SessionChangeKind>? SessionChanged;

    /// <summary>Allocates the next sequential session id (1-based, matches the .saz ordinal).</summary>
    public int NextId() => Interlocked.Increment(ref _nextId);

    /// <summary>Adds a freshly created (usually still pending) session and notifies listeners.</summary>
    public void Add(CapturedSession session)
    {
        if (!_settings.Capture)
        {
            return;
        }

        lock (_gate)
        {
            _byId[session.Id] = session;
            _order.Enqueue(session.Id);
            Evict_NoLock();
        }

        SessionChanged?.Invoke(session, SessionChangeKind.Added);
    }

    /// <summary>Signals that an already-added session was mutated (response/error recorded).</summary>
    public void Update(CapturedSession session, SessionChangeKind kind = SessionChangeKind.Updated)
    {
        // The session object is shared by reference; nothing to copy. We only need
        // to confirm it is still resident (not evicted) before broadcasting.
        bool present;
        lock (_gate)
        {
            present = _byId.ContainsKey(session.Id);
        }

        if (present)
        {
            SessionChanged?.Invoke(session, kind);
        }
    }

    /// <summary>Returns a snapshot of all live sessions in capture order.</summary>
    public IReadOnlyList<CapturedSession> Snapshot()
    {
        lock (_gate)
        {
            var list = new List<CapturedSession>(_order.Count);
            foreach (var id in _order)
            {
                if (_byId.TryGetValue(id, out var s))
                {
                    list.Add(s);
                }
            }

            return list;
        }
    }

    /// <summary>Looks up a single session by id, or null if absent/evicted.</summary>
    public CapturedSession? Get(int id)
    {
        lock (_gate)
        {
            return _byId.TryGetValue(id, out var s) ? s : null;
        }
    }

    /// <summary>Removes a single session by id (UI delete). Returns false if it wasn't present.</summary>
    public bool Remove(int id)
    {
        CapturedSession? removed;
        lock (_gate)
        {
            if (!_byId.Remove(id, out removed))
            {
                return false;
            }

            // The order queue has no random removal; rebuild it without the id.
            // Cheap: this only runs on an explicit user delete, not the hot path.
            var kept = _order.Where(x => x != id).ToArray();
            _order.Clear();
            foreach (var x in kept)
            {
                _order.Enqueue(x);
            }
        }

        SessionChanged?.Invoke(removed!, SessionChangeKind.Removed);
        return true;
    }

    /// <summary>Drops every captured session (the UI "Clear" button). Id numbering continues.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _byId.Clear();
            _order.Clear();
        }

        SessionChanged?.Invoke(null!, SessionChangeKind.Cleared);
    }

    private void Evict_NoLock()
    {
        while (_order.Count > _settings.MaxSessions && _order.TryDequeue(out var oldest))
        {
            _byId.Remove(oldest);
        }
    }
}

/// <summary>Kind of change broadcast for a session.</summary>
public enum SessionChangeKind
{
    Added,
    Updated,
    Removed,
    Cleared,
}
