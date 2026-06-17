using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using JAHTTPClient.Interop;

namespace JASniffer.Proxy.Fingerprint;

/// <summary>One captured browser fingerprint: display JA3/JA4 plus the engine spec to replay it.</summary>
public sealed record CapturedFingerprint(
    string Id,
    string Label,
    string Ja3,
    string Ja3Md5,
    string Ja4,
    string? UserAgent,
    string CapturedUtc,
    CustomTlsClient Spec);

/// <summary>
/// Thread-safe store of fingerprints captured from the local capture page, with one marked
/// "active" (applied to the upstream leg). Persisted to <c>fingerprints.json</c> next to the
/// CA so captures survive restarts. Best-effort persistence: a missing/corrupt file is ignored.
/// </summary>
public sealed class FingerprintStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private readonly ConcurrentDictionary<string, CapturedFingerprint> _items = new();
    private readonly List<string> _order = [];
    private readonly Lock _gate = new();
    private readonly string? _path;
    private volatile string? _activeId;

    public FingerprintStore(string? persistencePath = null)
    {
        _path = persistencePath;
        Load();
    }

    /// <summary>Stores a freshly captured fingerprint and returns the record. Newest first.</summary>
    public CapturedFingerprint Add(CapturedTlsFingerprint parsed, string? userAgent, string? label = null)
    {
        var id = Guid.NewGuid().ToString("N")[..8];
        var record = new CapturedFingerprint(
            id,
            string.IsNullOrWhiteSpace(label) ? LabelFor(userAgent) : label!,
            parsed.Ja3,
            parsed.Ja3Md5,
            parsed.Ja4,
            userAgent,
            DateTimeOffset.UtcNow.ToString("O"),
            parsed.Custom!);

        lock (_gate)
        {
            _items[id] = record;
            _order.Insert(0, id);
            Save_NoLock();
        }

        return record;
    }

    public IReadOnlyList<CapturedFingerprint> All()
    {
        lock (_gate)
        {
            return _order.Where(_items.ContainsKey).Select(id => _items[id]).ToList();
        }
    }

    public bool Remove(string id)
    {
        lock (_gate)
        {
            if (!_items.TryRemove(id, out _))
            {
                return false;
            }

            _order.Remove(id);
            if (_activeId == id)
            {
                _activeId = null;
            }

            Save_NoLock();
            return true;
        }
    }

    /// <summary>Marks a fingerprint active (or clears it with <see langword="null"/>). Returns false for an unknown id.</summary>
    public bool SetActive(string? id)
    {
        lock (_gate)
        {
            if (id is not null && !_items.ContainsKey(id))
            {
                return false;
            }

            _activeId = id;
            Save_NoLock();
            return true;
        }
    }

    public string? ActiveId => _activeId;

    /// <summary>The active fingerprint's engine spec, or null when none is selected.</summary>
    public CustomTlsClient? ActiveSpec
        => _activeId is { } id && _items.TryGetValue(id, out var f) ? f.Spec : null;

    private static string LabelFor(string? ua)
    {
        if (string.IsNullOrWhiteSpace(ua))
        {
            return "Captured fingerprint";
        }

        if (ua.Contains("Firefox/", StringComparison.OrdinalIgnoreCase)) return "Firefox";
        if (ua.Contains("Edg/", StringComparison.OrdinalIgnoreCase)) return "Edge";
        if (ua.Contains("OPR/", StringComparison.OrdinalIgnoreCase)) return "Opera";
        if (ua.Contains("Chrome/", StringComparison.OrdinalIgnoreCase)) return "Chrome";
        if (ua.Contains("Safari/", StringComparison.OrdinalIgnoreCase)) return "Safari";
        return "Captured fingerprint";
    }

    // ---- persistence -----------------------------------------------------------

    private sealed record Persisted(List<CapturedFingerprint> Items, string? ActiveId);

    private void Save_NoLock()
    {
        if (_path is null)
        {
            return;
        }

        try
        {
            var ordered = _order.Where(_items.ContainsKey).Select(id => _items[id]).ToList();
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(new Persisted(ordered, _activeId), Json));
        }
        catch (Exception)
        {
            // Persistence is a convenience, not a requirement.
        }
    }

    private void Load()
    {
        if (_path is null || !File.Exists(_path))
        {
            return;
        }

        try
        {
            var saved = JsonSerializer.Deserialize<Persisted>(File.ReadAllText(_path), Json);
            if (saved is null)
            {
                return;
            }

            foreach (var f in saved.Items)
            {
                _items[f.Id] = f;
                _order.Add(f.Id);
            }

            if (saved.ActiveId is not null && _items.ContainsKey(saved.ActiveId))
            {
                _activeId = saved.ActiveId;
            }
        }
        catch (Exception)
        {
            // Corrupt file — start empty.
        }
    }
}
