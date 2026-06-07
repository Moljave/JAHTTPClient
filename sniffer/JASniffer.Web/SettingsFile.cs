using System.Text.Json;
using JASniffer.Core;

namespace JASniffer.Web;

/// <summary>
/// Persists the user-tunable settings (fingerprint preset, force HTTP/1.1, smart
/// redirects, capture, upstream proxy) to <c>settings.json</c> next to the CA so
/// they survive restarts. Best-effort: a missing or corrupt file is ignored and the
/// defaults are used.
/// </summary>
public static class SettingsFile
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>Loads persisted values (if any) onto <paramref name="settings"/>.</summary>
    public static void Apply(SnifferSettings settings, string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var saved = JsonSerializer.Deserialize<Persisted>(File.ReadAllText(path), Options);
            if (saved is null)
            {
                return;
            }

            settings.SmartRedirects = saved.SmartRedirects;
            settings.MaxRedirects = saved.MaxRedirects <= 0 ? 10 : saved.MaxRedirects;
            settings.Capture = saved.Capture;
            settings.UpstreamProxy = saved.UpstreamProxy;
            settings.FingerprintPreset = string.IsNullOrWhiteSpace(saved.FingerprintPreset) ? "Chrome" : saved.FingerprintPreset;
            settings.ForceHttp1 = saved.ForceHttp1;
            settings.InterceptAllPorts = saved.InterceptAllPorts;
            settings.IgnoreUpstreamCertErrors = saved.IgnoreUpstreamCertErrors;
        }
        catch (Exception)
        {
            // Corrupt/unreadable settings — fall back to defaults silently.
        }
    }

    /// <summary>Writes the current settings to disk.</summary>
    public static void Save(SnifferSettings settings, string path)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var dto = new Persisted(
                settings.SmartRedirects, settings.MaxRedirects, settings.Capture,
                settings.UpstreamProxy, settings.FingerprintPreset, settings.ForceHttp1,
                settings.InterceptAllPorts, settings.IgnoreUpstreamCertErrors);
            File.WriteAllText(path, JsonSerializer.Serialize(dto, Options));
        }
        catch (Exception)
        {
            // Read-only location — persistence is a convenience, not a requirement.
        }
    }

    private sealed record Persisted(
        bool SmartRedirects, int MaxRedirects, bool Capture, string? UpstreamProxy, string FingerprintPreset, bool ForceHttp1,
        bool InterceptAllPorts = true, bool IgnoreUpstreamCertErrors = false);
}
