using JASniffer.Core;

namespace JASniffer.Tests;

public class SnifferSettingsTests
{
    [Fact]
    public void BypassHosts_NormalizesWildcardsDotsAndCase()
    {
        var s = new SnifferSettings { BypassHosts = "*.Example.COM, .foo.com\nbar.com" };
        var hosts = s.BypassHosts.Split('\n');
        Assert.Contains("example.com", hosts);
        Assert.Contains("foo.com", hosts);
        Assert.Contains("bar.com", hosts);
    }

    [Fact]
    public void BypassHosts_Deduplicates()
    {
        var s = new SnifferSettings { BypassHosts = "a.com, a.com\nA.COM" };
        Assert.Single(s.BypassHosts.Split('\n', StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public void IsBypassed_ExactMatch()
    {
        var s = new SnifferSettings { BypassHosts = "example.com" };
        Assert.True(s.IsBypassed("example.com"));
        Assert.True(s.IsBypassed("EXAMPLE.COM"));
    }

    [Fact]
    public void IsBypassed_SubdomainMatch()
    {
        var s = new SnifferSettings { BypassHosts = "ls.app" };
        Assert.True(s.IsBypassed("cdn.ls.app"));
        Assert.True(s.IsBypassed("a.b.ls.app"));
    }

    [Fact]
    public void IsBypassed_DoesNotMatchUnrelatedOrSuffixCollision()
    {
        var s = new SnifferSettings { BypassHosts = "ls.app" };
        Assert.False(s.IsBypassed("notls.app"));      // not a real subdomain boundary
        Assert.False(s.IsBypassed("example.com"));
    }

    [Fact]
    public void IsBypassed_EmptyList_NeverMatches()
    {
        var s = new SnifferSettings();
        Assert.False(s.IsBypassed("anything.com"));
    }

    [Fact]
    public void MaxRedirects_IsClamped()
    {
        var s = new SnifferSettings { MaxRedirects = 0 };
        Assert.Equal(1, s.MaxRedirects);
        s.MaxRedirects = 999;
        Assert.Equal(50, s.MaxRedirects);
        s.MaxRedirects = 7;
        Assert.Equal(7, s.MaxRedirects);
    }

    [Fact]
    public void FingerprintPreset_DefaultsWhenBlank()
    {
        var s = new SnifferSettings { FingerprintPreset = "  " };
        Assert.Equal("Chrome", s.FingerprintPreset);
    }

    [Fact]
    public void UpstreamProxy_IsCanonicalizedOnSet()
    {
        var s = new SnifferSettings { UpstreamProxy = "1.2.3.4:8080:user:pass" };
        Assert.Equal("http://user:pass@1.2.3.4:8080", s.UpstreamProxy);
    }
}
