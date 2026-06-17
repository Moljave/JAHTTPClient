using System.Text;
using JASniffer.Core.Models;
using JASniffer.Web;

namespace JASniffer.Tests;

public class DtoMapperTests
{
    private static CapturedSession Session() => new()
    {
        Id = 42,
        Method = "GET",
        Scheme = "https",
        Host = "example.com",
        Port = 443,
        Path = "/search",
        Query = "?q=hello+world&n=2",
        Url = "https://example.com/search?q=hello+world&n=2",
        RequestHeaders = new List<HeaderEntry>
        {
            new("Cookie", "sid=abc; theme=dark"),
            new("Authorization", "Bearer tok123"),
        },
        ResponseHeaders = new List<HeaderEntry> { new("Set-Cookie", "served=1; Path=/") },
        ResponseContentType = "application/json",
        ResponseBody = Encoding.UTF8.GetBytes("{\"a\":1}"),
        BodyLength = 7,
        StatusCode = 200,
        Completed = true,
        UpstreamOk = true,
    };

    [Fact]
    public void ToSummary_CopiesCoreFields()
    {
        var dto = DtoMapper.ToSummary(Session());
        Assert.Equal(42, dto.Id);
        Assert.Equal("GET", dto.Method);
        Assert.Equal("example.com", dto.Host);
        Assert.Equal(200, dto.Status);
        Assert.True(dto.UpstreamOk);
    }

    [Fact]
    public void ToDetail_ParsesQueryCookiesAndAuth()
    {
        var d = DtoMapper.ToDetail(Session());

        Assert.Collection(d.QueryParams,
            p => { Assert.Equal("q", p.Name); Assert.Equal("hello world", p.Value); },
            p => { Assert.Equal("n", p.Name); Assert.Equal("2", p.Value); });

        Assert.Equal(2, d.RequestCookies.Count);
        Assert.Equal("Bearer", d.Auth!.Scheme);
        Assert.Equal("tok123", d.Auth.Token);
        Assert.Single(d.ResponseCookies);
        Assert.Equal("served", d.ResponseCookies[0].Name);
    }

    [Fact]
    public void ToDetail_DecodesTextBody()
    {
        var d = DtoMapper.ToDetail(Session());
        Assert.True(d.ResponseBody.IsText);
        Assert.Equal("json", d.ResponseBody.Kind);
        Assert.Equal("{\"a\":1}", d.ResponseBody.Text);
        Assert.Equal(7, d.ResponseBody.Size);
    }

    [Fact]
    public void ToDetail_BinaryBody_HasNoText()
    {
        var s = Session();
        s.ResponseContentType = "image/png";
        s.ResponseBody = [0x89, 0x50, 0x4E, 0x47];
        s.BodyLength = 4;

        var d = DtoMapper.ToDetail(s);
        Assert.False(d.ResponseBody.IsText);
        Assert.Equal("image", d.ResponseBody.Kind);
        Assert.Null(d.ResponseBody.Text);
    }

    [Fact]
    public void ToDetail_EmptyBody_HasEmptyText()
    {
        var s = Session();
        s.ResponseBody = [];
        s.BodyLength = 0;
        var d = DtoMapper.ToDetail(s);
        Assert.Equal(string.Empty, d.ResponseBody.Text);
    }
}
