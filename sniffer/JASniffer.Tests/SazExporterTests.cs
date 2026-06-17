using System.IO.Compression;
using System.Text;
using JASniffer.Core.Export;
using JASniffer.Core.Models;

namespace JASniffer.Tests;

public class SazExporterTests
{
    private static CapturedSession FullSession(int id, string host = "example.com") => new()
    {
        Id = id,
        Method = "POST",
        Scheme = "https",
        Host = host,
        Port = 443,
        Path = "/submit",
        Query = "?a=1",
        Url = $"https://{host}/submit?a=1",
        RequestHeaders = new List<HeaderEntry> { new("Host", host), new("Content-Type", "application/json") },
        RequestBody = Encoding.UTF8.GetBytes("{\"x\":1}"),
        StatusCode = 200,
        ReasonPhrase = "OK",
        ResponseHeaders = new List<HeaderEntry>
        {
            new("Content-Type", "text/plain"),
            new("Content-Encoding", "gzip"),     // must be dropped (body already decoded)
            new("Content-Length", "999"),         // must be replaced
            new("Transfer-Encoding", "chunked"),  // must be dropped
        },
        ResponseBody = Encoding.UTF8.GetBytes("hello world"),
        Completed = true,
        DurationMs = 12.5,
    };

    private static Dictionary<string, byte[]> ExportAndRead(IReadOnlyList<CapturedSession> sessions)
    {
        using var ms = new MemoryStream();
        SazExporter.Export(sessions, ms);
        ms.Position = 0;
        var result = new Dictionary<string, byte[]>();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            using var s = entry.Open();
            using var copy = new MemoryStream();
            s.CopyTo(copy);
            result[entry.FullName] = copy.ToArray();
        }

        return result;
    }

    [Fact]
    public void Export_ProducesFiddlerLayout()
    {
        var entries = ExportAndRead(new[] { FullSession(1) });
        Assert.Contains("[Content_Types].xml", entries.Keys);
        Assert.Contains("_index.htm", entries.Keys);
        Assert.Contains("raw/001_c.txt", entries.Keys);
        Assert.Contains("raw/001_s.txt", entries.Keys);
        Assert.Contains("raw/001_m.xml", entries.Keys);
    }

    [Fact]
    public void Export_RequestRaw_HasRequestLineHostAndBody()
    {
        var entries = ExportAndRead(new[] { FullSession(1) });
        var raw = Encoding.Latin1.GetString(entries["raw/001_c.txt"]);
        Assert.StartsWith("POST /submit?a=1 HTTP/1.1\r\n", raw);
        Assert.Contains("Host: example.com\r\n", raw);
        Assert.EndsWith("{\"x\":1}", raw);
    }

    [Fact]
    public void Export_ResponseRaw_RecomputesContentLength_AndDropsEncodingHeaders()
    {
        var entries = ExportAndRead(new[] { FullSession(1) });
        var raw = Encoding.Latin1.GetString(entries["raw/001_s.txt"]);
        Assert.StartsWith("HTTP/1.1 200 OK\r\n", raw);
        Assert.DoesNotContain("Content-Encoding", raw);
        Assert.DoesNotContain("Transfer-Encoding", raw);
        Assert.DoesNotContain("999", raw);
        Assert.Contains("Content-Length: 11\r\n", raw); // "hello world" == 11 bytes
        Assert.EndsWith("hello world", raw);
    }

    [Fact]
    public void Export_SkipsTunneledSessions()
    {
        var tunnel = FullSession(1);
        tunnel.WasTunneled = true;
        var normal = FullSession(2);

        var entries = ExportAndRead(new[] { tunnel, normal });

        // Only one session survives, and it is renumbered to 001.
        Assert.Contains("raw/001_c.txt", entries.Keys);
        Assert.DoesNotContain("raw/002_c.txt", entries.Keys);
    }

    [Fact]
    public void Export_AddsHostHeaderWhenMissing()
    {
        var s = FullSession(1);
        s.RequestHeaders = new List<HeaderEntry> { new("Accept", "*/*") }; // no Host
        var entries = ExportAndRead(new[] { s });
        var raw = Encoding.Latin1.GetString(entries["raw/001_c.txt"]);
        Assert.Contains("Host: example.com\r\n", raw);
    }

    [Fact]
    public void Export_Metadata_IsWellFormedXml()
    {
        var entries = ExportAndRead(new[] { FullSession(1) });
        var xml = Encoding.UTF8.GetString(entries["raw/001_m.xml"]);
        var doc = System.Xml.Linq.XDocument.Parse(xml); // throws if malformed
        Assert.Equal("Session", doc.Root!.Name.LocalName);
    }

    [Fact]
    public void Export_NumberingWidthGrowsWithCount()
    {
        var many = Enumerable.Range(1, 1000).Select(i => FullSession(i)).ToArray();
        var entries = ExportAndRead(many);
        Assert.Contains("raw/0001_c.txt", entries.Keys); // width 4 for 1000 sessions
        Assert.Contains("raw/1000_c.txt", entries.Keys);
    }
}
