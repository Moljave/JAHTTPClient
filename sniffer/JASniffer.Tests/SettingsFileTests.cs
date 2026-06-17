using JASniffer.Core;
using JASniffer.Web;

namespace JASniffer.Tests;

public sealed class SettingsFileTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "JASnifferTests-settings-" + Guid.NewGuid().ToString("N") + ".json");

    public void Dispose()
    {
        try { File.Delete(_path); } catch { /* ignore */ }
    }

    [Fact]
    public void SaveThenApply_RoundTripsAllTunables()
    {
        var saved = new SnifferSettings
        {
            SmartRedirects = true,
            MaxRedirects = 7,
            Capture = false,
            UpstreamProxy = "1.2.3.4:8080:user:pass",   // canonicalized on set
            RotatingProxy = true,
            FingerprintPreset = "Firefox",
            ForceHttp1 = true,
            InterceptAllPorts = false,
            IgnoreUpstreamCertErrors = true,
            BypassHosts = "a.com, b.com",
        };
        SettingsFile.Save(saved, _path);

        var loaded = new SnifferSettings();
        SettingsFile.Apply(loaded, _path);

        Assert.True(loaded.SmartRedirects);
        Assert.Equal(7, loaded.MaxRedirects);
        Assert.False(loaded.Capture);
        Assert.Equal("http://user:pass@1.2.3.4:8080", loaded.UpstreamProxy);
        Assert.True(loaded.RotatingProxy);
        Assert.Equal("Firefox", loaded.FingerprintPreset);
        Assert.True(loaded.ForceHttp1);
        Assert.False(loaded.InterceptAllPorts);
        Assert.True(loaded.IgnoreUpstreamCertErrors);
        Assert.Equal(new[] { "a.com", "b.com" }, loaded.BypassHosts.Split('\n'));
    }

    [Fact]
    public void Apply_MissingFile_LeavesDefaults()
    {
        var settings = new SnifferSettings();
        SettingsFile.Apply(settings, _path); // file does not exist
        Assert.True(settings.Capture);          // default
        Assert.True(settings.InterceptAllPorts); // default
        Assert.Equal("Chrome", settings.FingerprintPreset);
    }

    [Fact]
    public void Apply_CorruptFile_DoesNotThrow_AndKeepsDefaults()
    {
        File.WriteAllText(_path, "{ this is not valid json ");
        var settings = new SnifferSettings();
        SettingsFile.Apply(settings, _path);
        Assert.True(settings.Capture);
    }

    [Fact]
    public void Apply_ZeroMaxRedirects_FallsBackToTen()
    {
        File.WriteAllText(_path, "{\"smartRedirects\":false,\"maxRedirects\":0,\"capture\":true,\"fingerprintPreset\":\"Chrome\",\"forceHttp1\":false}");
        var settings = new SnifferSettings();
        SettingsFile.Apply(settings, _path);
        Assert.Equal(10, settings.MaxRedirects);
    }
}
