using JASniffer.Core;
using JASniffer.Core.Models;

namespace JASniffer.Tests;

public class SessionStoreTests
{
    private static SessionStore NewStore(int maxSessions = 20_000, bool capture = true)
        => new(new SnifferSettings { MaxSessions = maxSessions, Capture = capture });

    private static CapturedSession NewSession(int id) => new()
    {
        Id = id,
        Method = "GET",
        Scheme = "https",
        Host = "example.com",
        Path = "/",
        Url = "https://example.com/",
    };

    [Fact]
    public void NextId_IncrementsFromOne()
    {
        var store = NewStore();
        Assert.Equal(1, store.NextId());
        Assert.Equal(2, store.NextId());
        Assert.Equal(3, store.NextId());
    }

    [Fact]
    public void Add_RaisesAddedEvent_AndIsRetrievable()
    {
        var store = NewStore();
        var events = new List<SessionChangeKind>();
        store.SessionChanged += (_, kind) => events.Add(kind);

        var s = NewSession(store.NextId());
        store.Add(s);

        Assert.Equal(new[] { SessionChangeKind.Added }, events);
        Assert.Same(s, store.Get(s.Id));
        Assert.Single(store.Snapshot());
    }

    [Fact]
    public void Add_WhenCaptureOff_DoesNothing()
    {
        var store = NewStore(capture: false);
        var raised = false;
        store.SessionChanged += (_, _) => raised = true;

        store.Add(NewSession(store.NextId()));

        Assert.False(raised);
        Assert.Empty(store.Snapshot());
    }

    [Fact]
    public void Update_OnlyBroadcastsWhenPresent()
    {
        var store = NewStore();
        var updates = 0;
        store.SessionChanged += (_, kind) => { if (kind == SessionChangeKind.Updated) updates++; };

        var present = NewSession(store.NextId());
        store.Add(present);
        store.Update(present);
        Assert.Equal(1, updates);

        // A session that was never added (or already evicted) must not broadcast.
        store.Update(NewSession(9999));
        Assert.Equal(1, updates);
    }

    [Fact]
    public void Remove_DropsSession_AndRaisesRemoved()
    {
        var store = NewStore();
        var s1 = NewSession(store.NextId());
        var s2 = NewSession(store.NextId());
        store.Add(s1);
        store.Add(s2);

        SessionChangeKind? last = null;
        store.SessionChanged += (_, kind) => last = kind;

        Assert.True(store.Remove(s1.Id));
        Assert.Equal(SessionChangeKind.Removed, last);
        Assert.Null(store.Get(s1.Id));
        Assert.Equal(new[] { s2.Id }, store.Snapshot().Select(x => x.Id).ToArray());

        Assert.False(store.Remove(s1.Id)); // already gone
    }

    [Fact]
    public void Clear_EmptiesStore_AndRaisesCleared()
    {
        var store = NewStore();
        store.Add(NewSession(store.NextId()));
        store.Add(NewSession(store.NextId()));

        var cleared = false;
        store.SessionChanged += (_, kind) => cleared |= kind == SessionChangeKind.Cleared;

        store.Clear();

        Assert.True(cleared);
        Assert.Empty(store.Snapshot());
    }

    [Fact]
    public void Snapshot_PreservesInsertionOrder()
    {
        var store = NewStore();
        var ids = new List<int>();
        for (var i = 0; i < 5; i++)
        {
            var s = NewSession(store.NextId());
            ids.Add(s.Id);
            store.Add(s);
        }

        Assert.Equal(ids, store.Snapshot().Select(s => s.Id).ToList());
    }

    [Fact]
    public void Eviction_KeepsOnlyMostRecent()
    {
        var store = NewStore(maxSessions: 3);
        var ids = new List<int>();
        for (var i = 0; i < 6; i++)
        {
            var s = NewSession(store.NextId());
            ids.Add(s.Id);
            store.Add(s);
        }

        var live = store.Snapshot().Select(s => s.Id).ToArray();
        Assert.Equal(3, live.Length);
        Assert.Equal(ids.Skip(3).ToArray(), live); // oldest three evicted
        Assert.Null(store.Get(ids[0]));
    }

    [Fact]
    public void Remove_AfterEviction_StillConsistent()
    {
        var store = NewStore(maxSessions: 2);
        var a = NewSession(store.NextId());
        var b = NewSession(store.NextId());
        var c = NewSession(store.NextId());
        store.Add(a);
        store.Add(b);
        store.Add(c); // evicts a

        Assert.True(store.Remove(b.Id));
        Assert.Equal(new[] { c.Id }, store.Snapshot().Select(s => s.Id).ToArray());
    }
}
