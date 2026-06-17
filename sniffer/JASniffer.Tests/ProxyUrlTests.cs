using JASniffer.Core;

namespace JASniffer.Tests;

public class ProxyUrlTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Normalize_EmptyInput_ReturnsNull(string? input)
        => Assert.Null(ProxyUrl.Normalize(input));

    [Fact]
    public void Normalize_HostPort_AssumesHttp()
        => Assert.Equal("http://1.2.3.4:8080", ProxyUrl.Normalize("1.2.3.4:8080"));

    [Fact]
    public void Normalize_KeepsExplicitScheme()
    {
        Assert.Equal("https://1.2.3.4:8080", ProxyUrl.Normalize("https://1.2.3.4:8080"));
        Assert.Equal("socks5://1.2.3.4:1080", ProxyUrl.Normalize("socks5://1.2.3.4:1080"));
    }

    [Fact]
    public void Normalize_UnknownScheme_FallsBackToHttp()
        => Assert.Equal("http://1.2.3.4:8080", ProxyUrl.Normalize("ftp://1.2.3.4:8080"));

    [Fact]
    public void Normalize_UserPassAtHost()
        => Assert.Equal("http://user:pass@1.2.3.4:8080", ProxyUrl.Normalize("http://user:pass@1.2.3.4:8080"));

    [Fact]
    public void Normalize_UserPassAtHost_NoScheme()
        => Assert.Equal("http://user:pass@1.2.3.4:8080", ProxyUrl.Normalize("user:pass@1.2.3.4:8080"));

    [Fact]
    public void Normalize_ColonFormat_HostPortUserPass()
        => Assert.Equal("http://user:pass@1.2.3.4:8080", ProxyUrl.Normalize("1.2.3.4:8080:user:pass"));

    [Fact]
    public void Normalize_ColonFormat_WithScheme()
        => Assert.Equal("socks5://user:pass@1.2.3.4:1080", ProxyUrl.Normalize("socks5://1.2.3.4:1080:user:pass"));

    [Fact]
    public void Normalize_PasswordContainingColon_IsPreserved()
        => Assert.Equal("http://user:pa%3Ass@1.2.3.4:8080", ProxyUrl.Normalize("1.2.3.4:8080:user:pa:ss"));

    [Fact]
    public void Normalize_EscapesCredentials()
    {
        // '@' and ':' in credentials must be percent-encoded so the URL stays parseable.
        var result = ProxyUrl.Normalize("http://us er:p@ss@1.2.3.4:8080");
        Assert.NotNull(result);
        Assert.StartsWith("http://", result);
        Assert.EndsWith("@1.2.3.4:8080", result);
        Assert.Contains("us%20er", result);
    }

    [Theory]
    [InlineData("justhost")]            // no port
    [InlineData("host:notaport")]       // non-numeric port
    [InlineData("1.2.3.4:0")]           // port out of range
    [InlineData("1.2.3.4:70000")]       // port out of range
    [InlineData("host:port:user")]      // 3 parts is ambiguous → rejected
    public void Normalize_Invalid_ReturnsNull(string input)
        => Assert.Null(ProxyUrl.Normalize(input));

    [Fact]
    public void Normalize_TrimsWhitespace()
        => Assert.Equal("http://1.2.3.4:8080", ProxyUrl.Normalize("  1.2.3.4:8080  "));
}
