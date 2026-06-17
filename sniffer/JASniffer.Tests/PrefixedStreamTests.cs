using System.Text;
using JASniffer.Proxy;

namespace JASniffer.Tests;

public class PrefixedStreamTests
{
    private static async Task<string> ReadAll(Stream s)
    {
        using var ms = new MemoryStream();
        var buf = new byte[4];
        int n;
        while ((n = await s.ReadAsync(buf)) > 0)
        {
            ms.Write(buf, 0, n);
        }

        return Encoding.Latin1.GetString(ms.ToArray());
    }

    [Fact]
    public async Task ReadsPrefixThenInner()
    {
        var prefix = Encoding.Latin1.GetBytes("PRE");
        var inner = new MemoryStream(Encoding.Latin1.GetBytes("INNER"));
        var stream = new PrefixedStream(prefix, inner);
        Assert.Equal("PREINNER", await ReadAll(stream));
    }

    [Fact]
    public void SyncRead_ReturnsPrefixThenInner()
    {
        var prefix = Encoding.Latin1.GetBytes("AB");
        var inner = new MemoryStream(Encoding.Latin1.GetBytes("CD"));
        var stream = new PrefixedStream(prefix, inner);

        var buf = new byte[10];
        var total = new StringBuilder();
        int n;
        while ((n = stream.Read(buf, 0, buf.Length)) > 0)
        {
            total.Append(Encoding.Latin1.GetString(buf, 0, n));
        }

        Assert.Equal("ABCD", total.ToString());
    }

    [Fact]
    public async Task EmptyPrefix_ReadsInnerOnly()
    {
        var inner = new MemoryStream(Encoding.Latin1.GetBytes("XYZ"));
        var stream = new PrefixedStream([], inner);
        Assert.Equal("XYZ", await ReadAll(stream));
    }

    [Fact]
    public async Task WriteForwardsToInner()
    {
        var inner = new MemoryStream();
        var stream = new PrefixedStream(Encoding.Latin1.GetBytes("ignored-on-write"), inner);
        await stream.WriteAsync(Encoding.Latin1.GetBytes("hello"));
        Assert.Equal("hello", Encoding.Latin1.GetString(inner.ToArray()));
    }
}
