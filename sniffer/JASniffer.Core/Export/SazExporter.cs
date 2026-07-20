using System.IO.Compression;
using System.Text;
using System.Text.Json;
using JASniffer.Core.Models;

namespace JASniffer.Core.Export;

/// <summary>
/// Serializes captured sessions into Fiddler's <c>.saz</c> session-archive format
/// (a ZIP of raw request/response text plus per-session metadata) so a capture can
/// be re-opened in Fiddler Classic / Everywhere. The layout matches what Fiddler
/// emits: <c>[Content_Types].xml</c>, <c>_index.htm</c> and a <c>raw/</c> folder of
/// <c>NNN_c.txt</c> (request), <c>NNN_s.txt</c> (response) and <c>NNN_m.xml</c>
/// (metadata) triplets, numbered from 001.
/// </summary>
public static class SazExporter
{
    // Headers we drop from the archived response because the body is stored
    // already-decoded; we re-add an accurate Content-Length so the archive stays
    // self-consistent and re-importable.
    private static readonly HashSet<string> ResponseHeadersToReplace =
        new(StringComparer.OrdinalIgnoreCase) { "Content-Length", "Content-Encoding", "Transfer-Encoding" };

    private static readonly Encoding Latin1 = Encoding.Latin1;

    private const string ContentTypesXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="htm" ContentType="text/html" />
          <Default Extension="xml" ContentType="application/xml" />
          <Default Extension="txt" ContentType="text/plain" />
        </Types>
        """;

    /// <summary>Writes a <c>.saz</c> archive of <paramref name="sessions"/> to <paramref name="output"/>.</summary>
    public static void Export(IReadOnlyList<CapturedSession> sessions, Stream output)
    {
        using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);

        WriteText(zip, "[Content_Types].xml", ContentTypesXml);

        var width = Math.Max(3, sessions.Count.ToString().Length);
        var index = new StringBuilder();
        index.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>JASniffer capture</title></head><body><table border=\"1\" cellspacing=\"0\" cellpadding=\"3\"><tr><th>#</th><th>Result</th><th>Protocol</th><th>Host</th><th>URL</th></tr>");

        var ordinal = 0;
        foreach (var s in sessions)
        {
            if (s.WasTunneled)
            {
                // Tunneled sessions were never inspected; skip rather than emit an
                // empty/misleading exchange into the archive.
                continue;
            }

            ordinal++;
            var n = ordinal.ToString().PadLeft(width, '0');

            WriteBytes(zip, $"raw/{n}_c.txt", BuildRequestRaw(s));
            WriteBytes(zip, $"raw/{n}_s.txt", BuildResponseRaw(s));
            WriteText(zip, $"raw/{n}_m.xml", BuildMetadata(s, ordinal));

            // Full per-request upstream fingerprint (JA3/JA4 + parsed cipher/extension/curve
            // detail) as a JSON sidecar, so it survives the round-trip and the Info tab can
            // show it after import without a live scan. Omitted when unknown (e.g. tunneled).
            if (s.Fingerprint is not null)
            {
                WriteText(zip, SazFormat.FingerprintPath(n), JsonSerializer.Serialize(s.Fingerprint, SazFormat.Json));
            }

            index.Append("<tr><td>").Append(ordinal).Append("</td><td>").Append(s.StatusCode)
                 .Append("</td><td>").Append(s.Scheme).Append("</td><td>").Append(WebEncode(s.Host))
                 .Append("</td><td>").Append(WebEncode(s.Url)).Append("</td></tr>");
        }

        index.Append("</table></body></html>");
        WriteText(zip, "_index.htm", index.ToString());
    }

    private static byte[] BuildRequestRaw(CapturedSession s)
    {
        var head = new StringBuilder();
        var pathAndQuery = s.Path + s.Query;
        if (pathAndQuery.Length == 0)
        {
            pathAndQuery = "/";
        }

        // Origin-form request line; the Host header lets Fiddler restore the scheme.
        head.Append(s.Method).Append(' ').Append(pathAndQuery).Append(" HTTP/1.1\r\n");

        if (!HasHeader(s.RequestHeaders, "Host"))
        {
            head.Append("Host: ").Append(s.Host).Append("\r\n");
        }

        foreach (var h in s.RequestHeaders)
        {
            head.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
        }

        head.Append("\r\n");
        return Concat(Latin1.GetBytes(head.ToString()), s.RequestBody);
    }

    private static byte[] BuildResponseRaw(CapturedSession s)
    {
        var head = new StringBuilder();
        var reason = string.IsNullOrEmpty(s.ReasonPhrase) ? ReasonFor(s.StatusCode) : s.ReasonPhrase;
        head.Append("HTTP/1.1 ").Append(s.StatusCode).Append(' ').Append(reason).Append("\r\n");

        foreach (var h in s.ResponseHeaders)
        {
            if (ResponseHeadersToReplace.Contains(h.Name))
            {
                continue;
            }

            head.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
        }

        head.Append("Content-Length: ").Append(s.ResponseBody.Length).Append("\r\n");
        head.Append("\r\n");
        return Concat(Latin1.GetBytes(head.ToString()), s.ResponseBody);
    }

    private static string BuildMetadata(CapturedSession s, int sid)
    {
        var start = s.StartedUtc;
        var doneReq = start.AddMilliseconds(Math.Min(5, s.DurationMs));
        var beginResp = start.AddMilliseconds(Math.Max(0, s.DurationMs - 1));
        var doneResp = start.AddMilliseconds(s.DurationMs);

        static string T(DateTimeOffset t) => t.ToString("yyyy-MM-ddTHH:mm:ss.fff");

        return
            $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <Session SID="{sid}" BitFlags="0">
              <SessionTimers ClientConnected="{T(start)}"
                             ClientBeginRequest="{T(start)}"
                             ClientDoneRequest="{T(doneReq)}"
                             ServerGotRequest="{T(doneReq)}"
                             ServerBeginResponse="{T(beginResp)}"
                             ServerDoneResponse="{T(doneResp)}"
                             ClientBeginResponse="{T(beginResp)}"
                             ClientDoneResponse="{T(doneResp)}" />
              <PipeInfo />
              <SessionFlags>
                <SessionFlag N="x-clientip" V="{XmlEncode(s.ClientEndpoint ?? "127.0.0.1")}" />
                <SessionFlag N="x-hostip" V="{XmlEncode(s.HostIp ?? string.Empty)}" />
                <SessionFlag N="x-responsebodytransferlength" V="{s.ResponseBody.Length}" />
                <SessionFlag N="x-egressport" V="{s.Port}" />
            {JasnifferFlags(s)}  </SessionFlags>
            </Session>
            """;
    }

    // JASniffer-specific session metadata Fiddler's format has no slot for. Additive: a stock
    // Fiddler reader shows these as extra flags; the importer reads them to reconstruct the
    // scheme/URL/timing/fingerprint that a bare request+response can't convey.
    private static string JasnifferFlags(CapturedSession s)
    {
        var sb = new StringBuilder();
        void Flag(string name, string? value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                sb.Append("    <SessionFlag N=\"").Append(name).Append("\" V=\"").Append(XmlEncode(value)).Append("\" />\r\n");
            }
        }

        Flag(SazFormat.FlagScheme, s.Scheme);
        Flag(SazFormat.FlagHost, s.Host);
        Flag(SazFormat.FlagUrl, s.Url);
        Flag(SazFormat.FlagFinalUrl, s.FinalUrl);
        Flag(SazFormat.FlagDurationMs, s.DurationMs.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
        Flag(SazFormat.FlagReqHttp, s.RequestHttpVersion);
        Flag(SazFormat.FlagRespHttp, s.ResponseHttpVersion);
        Flag(SazFormat.FlagPreset, s.FingerprintPreset);
        Flag(SazFormat.FlagUpstreamOk, s.UpstreamOk ? "1" : "0");
        Flag(SazFormat.FlagError, s.Error);
        Flag(SazFormat.FlagTlsSummary, s.TlsSummary);

        // Fingerprint headline, kept visible in Fiddler's flag view; full detail is the sidecar.
        if (s.Fingerprint is { } fp)
        {
            Flag(SazFormat.FlagJa3, fp.Ja3);
            Flag(SazFormat.FlagJa3Md5, fp.Ja3Md5);
            Flag(SazFormat.FlagJa4, fp.Ja4);
            Flag(SazFormat.FlagTls, fp.TlsVersion);
        }

        return sb.ToString();
    }

    private static void WriteText(ZipArchive zip, string path, string content)
        => WriteBytes(zip, path, Encoding.UTF8.GetBytes(content));

    private static void WriteBytes(ZipArchive zip, string path, byte[] content)
    {
        var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content, 0, content.Length);
    }

    private static bool HasHeader(IReadOnlyList<HeaderEntry> headers, string name)
    {
        foreach (var h in headers)
        {
            if (h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        if (b.Length == 0)
        {
            return a;
        }

        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static string WebEncode(string s) => System.Net.WebUtility.HtmlEncode(s);

    private static string XmlEncode(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    private static string ReasonFor(int status) => status switch
    {
        200 => "OK", 201 => "Created", 204 => "No Content", 301 => "Moved Permanently",
        302 => "Found", 303 => "See Other", 304 => "Not Modified", 307 => "Temporary Redirect",
        308 => "Permanent Redirect", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 429 => "Too Many Requests", 500 => "Internal Server Error",
        502 => "Bad Gateway", 503 => "Service Unavailable", _ => "OK",
    };
}
