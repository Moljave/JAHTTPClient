using System.Text.Json;

namespace JASniffer.Core;

/// <summary>
/// A user-saved (captured) TLS fingerprint. <paramref name="Preset"/> is the built-in
/// preset it was captured from; selecting the capture re-applies that preset, which
/// reproduces this exact JA3 (a JA3 string alone can't be replayed through the engine).
/// </summary>
public sealed record CapturedFingerprint(string Name, string Ja3, string Ja3Md5, string Preset);

/// <summary>
/// Thread-safe, persisted list of captured JA3 fingerprints the user saved from the
/// self-test, so they show up in the upstream-fingerprint selector and can be replayed
/// or removed. Backed by <c>fingerprints.json</c>; persistence is best-effort.
/// </summary>
public sealed class FingerprintStore
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly string _path;
    private readonly Lock _gate = new();
    private readonly List<CapturedFingerprint> _items;

    public FingerprintStore(string path)
    {
        _path = path;
        _items = Load(path);
    }

    /// <summary>Snapshot of all saved fingerprints, in insertion order.</summary>
    public IReadOnlyList<CapturedFingerprint> All()
    {
        lock (_gate)
        {
            return _items.ToArray();
        }
    }

    /// <summary>Looks up a saved fingerprint by name (case-insensitive), or null.</summary>
    public CapturedFingerprint? Get(string name)
    {
        lock (_gate)
        {
            return _items.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>Adds a saved fingerprint (replacing any with the same name) and persists.</summary>
    public void Add(CapturedFingerprint fingerprint)
    {
        lock (_gate)
        {
            _items.RemoveAll(x => string.Equals(x.Name, fingerprint.Name, StringComparison.OrdinalIgnoreCase));
            _items.Add(fingerprint);
            Save();
        }
    }

    /// <summary>Removes a saved fingerprint by name; returns whether one was removed.</summary>
    public bool Remove(string name)
    {
        lock (_gate)
        {
            var removed = _items.RemoveAll(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                Save();
            }

            return removed;
        }
    }

    private static List<CapturedFingerprint> Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return JsonSerializer.Deserialize<List<CapturedFingerprint>>(File.ReadAllText(path), Options) ?? [];
            }
        }
        catch (Exception)
        {
            // Corrupt/unreadable — start empty.
        }

        return [];
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(_items, Options));
        }
        catch (Exception)
        {
            // Read-only location — persistence is a convenience, not a requirement.
        }
    }
}
