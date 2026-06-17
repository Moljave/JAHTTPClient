using System.Text;
using JASniffer.Core.Models;
using JASniffer.Core.Parsing;

namespace JASniffer.Tests;

public class HttpParsingTests
{
    // ---- ParseQuery ----------------------------------------------------------

    [Fact]
    public void ParseQuery_Empty_ReturnsEmpty()
    {
        Assert.Empty(HttpParsing.ParseQuery(null));
        Assert.Empty(HttpParsing.ParseQuery(""));
        Assert.Empty(HttpParsing.ParseQuery("?"));
    }

    [Fact]
    public void ParseQuery_LeadingQuestionMark_IsStripped()
    {
        var p = HttpParsing.ParseQuery("?a=1&b=2");
        Assert.Equal(2, p.Count);
        Assert.Equal("a", p[0].Name);
        Assert.Equal("1", p[0].Value);
        Assert.Equal("b", p[1].Name);
        Assert.Equal("2", p[1].Value);
    }

    [Fact]
    public void ParseQuery_NoLeadingQuestionMark_Works()
    {
        var p = HttpParsing.ParseQuery("x=10");
        Assert.Single(p);
        Assert.Equal("x", p[0].Name);
        Assert.Equal("10", p[0].Value);
    }

    [Fact]
    public void ParseQuery_FlagWithoutValue_HasEmptyValue()
    {
        var p = HttpParsing.ParseQuery("flag&y=2");
        Assert.Equal(2, p.Count);
        Assert.Equal("flag", p[0].Name);
        Assert.Equal("", p[0].Value);
    }

    [Fact]
    public void ParseQuery_DecodesPercentAndPlus()
    {
        var p = HttpParsing.ParseQuery("q=hello+world&name=a%20b%26c");
        Assert.Equal("hello world", p[0].Value);
        Assert.Equal("a b&c", p[1].Value);
    }

    [Fact]
    public void ParseQuery_SkipsEmptySegments()
    {
        var p = HttpParsing.ParseQuery("a=1&&b=2");
        Assert.Equal(2, p.Count);
    }

    // ---- ParseRequestCookies -------------------------------------------------

    [Fact]
    public void ParseRequestCookies_SplitsAndTrims()
    {
        var headers = new List<HeaderEntry> { new("Cookie", "a=1; b=2;c=3") };
        var cookies = HttpParsing.ParseRequestCookies(headers);
        Assert.Equal(3, cookies.Count);
        Assert.Equal("a", cookies[0].Name);
        Assert.Equal("1", cookies[0].Value);
        Assert.Equal("c", cookies[2].Name);
        Assert.Equal("3", cookies[2].Value);
    }

    [Fact]
    public void ParseRequestCookies_MultipleHeaders_AreCombined()
    {
        var headers = new List<HeaderEntry> { new("Cookie", "a=1"), new("cookie", "b=2") };
        var cookies = HttpParsing.ParseRequestCookies(headers);
        Assert.Equal(2, cookies.Count);
    }

    [Fact]
    public void ParseRequestCookies_ValueWithEquals_KeepsRemainder()
    {
        var headers = new List<HeaderEntry> { new("Cookie", "token=ab=cd") };
        var cookies = HttpParsing.ParseRequestCookies(headers);
        Assert.Single(cookies);
        Assert.Equal("token", cookies[0].Name);
        Assert.Equal("ab=cd", cookies[0].Value);
    }

    // ---- ParseResponseCookies ------------------------------------------------

    [Fact]
    public void ParseResponseCookies_ParsesAttributes()
    {
        var headers = new List<HeaderEntry>
        {
            new("Set-Cookie", "sid=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"),
        };
        var c = Assert.Single(HttpParsing.ParseResponseCookies(headers));
        Assert.Equal("sid", c.Name);
        Assert.Equal("abc", c.Value);
        Assert.Equal("example.com", c.Domain);
        Assert.Equal("/", c.Path);
        Assert.True(c.Secure);
        Assert.True(c.HttpOnly);
        Assert.Equal("Lax", c.SameSite);
        Assert.Equal("3600", c.MaxAge);
    }

    [Fact]
    public void ParseResponseCookies_ExpiresWithComma_IsPreserved()
    {
        // The Expires date contains a comma but no semicolon, so splitting on ';' is safe.
        var headers = new List<HeaderEntry>
        {
            new("Set-Cookie", "id=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/"),
        };
        var c = Assert.Single(HttpParsing.ParseResponseCookies(headers));
        Assert.Equal("Wed, 09 Jun 2027 10:18:14 GMT", c.Expires);
        Assert.Equal("/", c.Path);
    }

    [Fact]
    public void ParseResponseCookies_MultipleSetCookie_AllParsed()
    {
        var headers = new List<HeaderEntry>
        {
            new("Set-Cookie", "a=1; Path=/"),
            new("Set-Cookie", "b=2; Secure"),
        };
        Assert.Equal(2, HttpParsing.ParseResponseCookies(headers).Count);
    }

    [Fact]
    public void ParseResponseCookies_MalformedWithoutEquals_IsSkipped()
    {
        var headers = new List<HeaderEntry> { new("Set-Cookie", "garbage") };
        Assert.Empty(HttpParsing.ParseResponseCookies(headers));
    }

    // ---- ParseAuthorization --------------------------------------------------

    [Fact]
    public void ParseAuthorization_Basic_DecodesUserAndPassword()
    {
        var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:s3cret"));
        var headers = new List<HeaderEntry> { new("Authorization", "Basic " + creds) };
        var auth = HttpParsing.ParseAuthorization(headers)!;
        Assert.Equal("Basic", auth.Scheme);
        Assert.Equal("alice", auth.Username);
        Assert.Equal("s3cret", auth.Password);
    }

    [Fact]
    public void ParseAuthorization_BasicInvalidBase64_FallsBackToToken()
    {
        var headers = new List<HeaderEntry> { new("Authorization", "Basic not_base64!!") };
        var auth = HttpParsing.ParseAuthorization(headers)!;
        Assert.Equal("Basic", auth.Scheme);
        Assert.Null(auth.Username);
        Assert.Equal("not_base64!!", auth.Token);
    }

    [Fact]
    public void ParseAuthorization_Bearer_KeepsToken()
    {
        var headers = new List<HeaderEntry> { new("Authorization", "Bearer xyz.123") };
        var auth = HttpParsing.ParseAuthorization(headers)!;
        Assert.Equal("Bearer", auth.Scheme);
        Assert.Equal("xyz.123", auth.Token);
    }

    [Fact]
    public void ParseAuthorization_None_ReturnsNull()
        => Assert.Null(HttpParsing.ParseAuthorization(new List<HeaderEntry> { new("Accept", "*/*") }));

    // ---- IsTextual / ContentKind --------------------------------------------

    [Theory]
    [InlineData("text/html", true)]
    [InlineData("application/json", true)]
    [InlineData("application/xml", true)]
    [InlineData("application/javascript", true)]
    [InlineData("application/x-www-form-urlencoded", true)]
    [InlineData("image/png", false)]
    [InlineData("application/octet-stream", false)]
    [InlineData(null, false)]
    public void IsTextual_ClassifiesCorrectly(string? ct, bool expected)
        => Assert.Equal(expected, HttpParsing.IsTextual(ct));

    [Theory]
    [InlineData("application/json", "json")]
    [InlineData("text/html; charset=utf-8", "html")]
    [InlineData("application/xml", "xml")]
    [InlineData("image/jpeg", "image")]
    [InlineData("text/css", "text")]
    [InlineData("application/octet-stream", "binary")]
    [InlineData(null, "binary")]
    public void ContentKind_ClassifiesCorrectly(string? ct, string expected)
        => Assert.Equal(expected, HttpParsing.ContentKind(ct));

    // ---- CharsetOf -----------------------------------------------------------

    [Fact]
    public void CharsetOf_DefaultsToUtf8()
        => Assert.Equal(Encoding.UTF8, HttpParsing.CharsetOf("text/html"));

    [Fact]
    public void CharsetOf_ReadsExplicitCharset()
        => Assert.Equal("iso-8859-1", HttpParsing.CharsetOf("text/plain; charset=iso-8859-1").WebName);

    [Fact]
    public void CharsetOf_QuotedCharset()
        => Assert.Equal("utf-8", HttpParsing.CharsetOf("text/plain; charset=\"utf-8\"").WebName);

    [Fact]
    public void CharsetOf_QuotedCharsetFollowedByParam_ResolvesCharset()
    {
        // Regression: trimming quotes before splitting on ';' left a stray quote and
        // silently fell back to UTF-8 instead of honoring the declared charset.
        Assert.Equal("iso-8859-1", HttpParsing.CharsetOf("text/plain; charset=\"iso-8859-1\"; x=y").WebName);
    }

    [Fact]
    public void CharsetOf_UnknownCharset_FallsBackToUtf8()
        => Assert.Equal(Encoding.UTF8, HttpParsing.CharsetOf("text/plain; charset=definitely-not-a-charset"));

    // ---- FirstHeader ---------------------------------------------------------

    [Fact]
    public void FirstHeader_IsCaseInsensitive_AndReturnsFirst()
    {
        var headers = new List<HeaderEntry> { new("X-Test", "one"), new("x-test", "two") };
        Assert.Equal("one", HttpParsing.FirstHeader(headers, "X-TEST"));
        Assert.Null(HttpParsing.FirstHeader(headers, "missing"));
    }
}
