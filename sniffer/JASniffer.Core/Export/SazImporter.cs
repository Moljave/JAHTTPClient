using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using JASniffer.Core.Models;

namespace JASniffer.Core.Export;

/// <summary>
/// Reads a Fiddler <c>.saz</c> archive back into <see cref="CapturedSession"/>s — the inverse
/// of <see cref="SazExporter"/>. Each <c>raw/NNN_c.txt</c> / <c>NNN_s.txt</c> / <c>NNN_m.xml</c>
/// triplet becomes one session; when JASniffer's own extensions are present
/// (<c>x-jasniffer-*</c> flags and the <c>raw/NNN_f.json</c> sidecar) the scheme, absolute URL,
/// timing and the full upstream fingerprint are restored losslessly. A foreign archive (produced
/// by stock Fiddler, without those extensions) still imports best-effort: scheme/port are
/// inferred from the egress port and the Host header, and the fingerprint is simply absent.
/// </summary>
public static class SazImporter
{
    private static readonly Encoding Latin1 = Encoding.Latin1;
    private static readonly byte[] HeaderBodySeparator = "\r\n\r\n"u8.ToArray();

    /// <summary>
    /// Parses <paramref name="input"/> (a <c>.saz</c> ZIP stream) into sessions, assigning each a
    /// fresh id from <paramref name="nextId"/>. Malformed individual sessions are skipped rather
    /// than aborting the whole import; a stream that isn't a readable ZIP throws.
    /// </summary>
    public static IReadOnlyList<CapturedSession> Import(Stream input, Func<int> nextId)
    {
        using var zip = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);

        // Pair siblings by the ordinal token between "raw/" and "_c.txt" (e.g. "001").
        var tokens = new List<string>();
        foreach (var entry in zip.Entries)
        {
            var name = entry.FullName;
            if (name.StartsWith("raw/", StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith("_c.txt", StringComparison.OrdinalIgnoreCase))
            {
                tokens.Add(name["raw/".Length..^"_c.txt".Length]);
            }
        }

        // Numeric order when the tokens are numbers (they are, zero-padded), else ordinal.
        tokens.Sort((a, b) =>
            int.TryParse(a, out var ia) && int.TryParse(b, out var ib)
                ? ia.CompareTo(ib)
                : string.CompareOrdinal(a, b));

        var sessions = new List<CapturedSession>(tokens.Count);
        foreach (var token in tokens)
        {
            CapturedSession? session;
            try
            {
                session = BuildSession(zip, token, nextId);
            }
            catch (Exception)
            {
                session = null; // one bad triplet must not sink the whole archive
            }

            if (session is not null)
            {
                sessions.Add(session);
            }
        }

        return sessions;
    }

    private static CapturedSession? BuildSession(ZipArchive zip, string token, Func<int> nextId)
    {
        var requestBytes = ReadBytes(zip, $"raw/{token}_c.txt");
        if (requestBytes is null)
        {
            return null;
        }

        var responseBytes = ReadBytes(zip, $"raw/{token}_s.txt") ?? [];
        var metaDoc = ReadXml(zip, $"raw/{token}_m.xml");
        var flags = ReadFlags(metaDoc);
        var fingerprint = ReadFingerprint(zip, SazFormat.FingerprintPath(token));

        var (reqStart, reqHeaders, reqBody) = ParseMessage(requestBytes);
        if (reqStart.Length == 0)
        {
            return null;
        }

        // Request line: METHOD  request-target  HTTP/x.y (origin-form target).
        var reqParts = reqStart.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (reqParts.Length < 2)
        {
            return null;
        }

        var method = reqParts[0];
        var target = reqParts[1];
        var q = target.IndexOf('?');
        var path = q < 0 ? target : target[..q];
        var query = q < 0 ? string.Empty : target[q..];

        var host = Flag(flags, SazFormat.FlagHost)
                   ?? HeaderValue(reqHeaders, "Host")
                   ?? string.Empty;

        var port = ParseInt(Flag(flags, "x-egressport"));
        var scheme = Flag(flags, SazFormat.FlagScheme)
                     ?? (port == 443 ? "https" : port == 80 ? "http" : "https");
        if (port <= 0)
        {
            port = scheme == "https" ? 443 : 80;
        }

        // Host header may carry a :port; strip it for the Host field but keep it for the URL.
        var hostOnly = host;
        var hostColon = host.LastIndexOf(':');
        if (hostColon > 0 && !host.Contains(']')) // ignore IPv6 literals like [::1]
        {
            hostOnly = host[..hostColon];
        }

        var url = Flag(flags, SazFormat.FlagUrl) ?? BuildUrl(scheme, host, port, path, query);

        // Response line: HTTP/x.y  status  reason.
        var (respStart, respHeaders, respBody) = ParseMessage(responseBytes);
        var (statusCode, reason) = ParseStatusLine(respStart);

        var upstreamOkFlag = Flag(flags, SazFormat.FlagUpstreamOk);
        var upstreamOk = upstreamOkFlag is null ? statusCode > 0 : upstreamOkFlag == "1";
        var finalUrl = Flag(flags, SazFormat.FlagFinalUrl) ?? url;

        return new CapturedSession
        {
            Id = nextId(),
            StartedUtc = ParseTimestamp(metaDoc) ?? DateTimeOffset.UtcNow,
            DurationMs = ParseDouble(Flag(flags, SazFormat.FlagDurationMs)),
            Completed = true,
            Method = method,
            Scheme = scheme,
            Host = hostOnly,
            Port = port,
            Path = path,
            Query = query,
            Url = url,
            RequestHttpVersion = Flag(flags, SazFormat.FlagReqHttp) ?? "1.1",
            RequestHeaders = reqHeaders,
            RequestBody = reqBody,
            RequestContentType = HeaderValue(reqHeaders, "Content-Type"),
            StatusCode = statusCode,
            ReasonPhrase = string.IsNullOrEmpty(reason) ? null : reason,
            ResponseHttpVersion = Flag(flags, SazFormat.FlagRespHttp) ?? (statusCode > 0 ? "1.1" : string.Empty),
            ResponseHeaders = respHeaders,
            ResponseBody = respBody,
            ResponseContentType = HeaderValue(respHeaders, "Content-Type"),
            BodyLength = respBody.LongLength,
            FinalUrl = finalUrl,
            FollowedRedirects = !string.Equals(finalUrl, url, StringComparison.Ordinal),
            FingerprintPreset = Flag(flags, SazFormat.FlagPreset) ?? fingerprint?.Preset ?? "Imported",
            TlsSummary = Flag(flags, SazFormat.FlagTlsSummary),
            Fingerprint = fingerprint,
            UpstreamOk = upstreamOk,
            Error = Flag(flags, SazFormat.FlagError),
            ClientEndpoint = Flag(flags, "x-clientip"),
            HostIp = Flag(flags, "x-hostip"),
        };
    }

    // Splits a raw HTTP message (head + body) at the first CRLFCRLF. The head is Latin1 (each
    // byte = one char, matching how the exporter wrote it); the body is the remaining raw bytes.
    private static (string StartLine, List<HeaderEntry> Headers, byte[] Body) ParseMessage(byte[] message)
    {
        if (message.Length == 0)
        {
            return (string.Empty, [], []);
        }

        var sep = IndexOf(message, HeaderBodySeparator);
        var headLen = sep < 0 ? message.Length : sep;
        var head = Latin1.GetString(message, 0, headLen);
        var body = sep < 0 ? [] : message[(sep + HeaderBodySeparator.Length)..];

        var lines = head.Split("\r\n");
        if (lines.Length == 0)
        {
            return (string.Empty, [], body);
        }

        var headers = new List<HeaderEntry>(lines.Length - 1);
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0)
            {
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].TrimStart();
            headers.Add(new HeaderEntry(name, value));
        }

        return (lines[0], headers, body);
    }

    private static (int Status, string Reason) ParseStatusLine(string line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return (0, string.Empty);
        }

        // HTTP/x.y SP status SP reason
        var parts = line.Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var status))
        {
            return (0, string.Empty);
        }

        return (status, parts.Length >= 3 ? parts[2] : string.Empty);
    }

    private static byte[]? ReadBytes(ZipArchive zip, string name)
    {
        var entry = zip.GetEntry(name);
        if (entry is null)
        {
            return null;
        }

        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static XDocument? ReadXml(ZipArchive zip, string name)
    {
        var bytes = ReadBytes(zip, name);
        if (bytes is null)
        {
            return null;
        }

        try
        {
            return XDocument.Parse(Encoding.UTF8.GetString(bytes));
        }
        catch (Exception)
        {
            return null; // unparseable metadata — proceed without it
        }
    }

    private static Dictionary<string, string> ReadFlags(XDocument? doc)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (doc is null)
        {
            return result;
        }

        foreach (var flag in doc.Descendants("SessionFlag"))
        {
            var n = flag.Attribute("N")?.Value;
            var v = flag.Attribute("V")?.Value;
            if (!string.IsNullOrEmpty(n) && v is not null)
            {
                result[n] = v;
            }
        }

        return result;
    }

    private static SessionFingerprint? ReadFingerprint(ZipArchive zip, string name)
    {
        var bytes = ReadBytes(zip, name);
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<SessionFingerprint>(bytes, SazFormat.Json);
        }
        catch (Exception)
        {
            return null;
        }
    }

    // Recovers the original capture time from <SessionTimers ClientBeginRequest="...">, which the
    // exporter wrote as a zoneless UTC wall-clock ("yyyy-MM-ddTHH:mm:ss.fff"); parse it back as UTC.
    private static DateTimeOffset? ParseTimestamp(XDocument? doc)
    {
        var raw = doc?.Descendants("SessionTimers").FirstOrDefault()?.Attribute("ClientBeginRequest")?.Value;
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        return DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto)
            ? dto
            : null;
    }

    private static string? Flag(Dictionary<string, string> flags, string name)
        => flags.TryGetValue(name, out var v) && v.Length > 0 ? v : null;

    private static string? HeaderValue(List<HeaderEntry> headers, string name)
    {
        foreach (var h in headers)
        {
            if (h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    private static string BuildUrl(string scheme, string host, int port, string path, string query)
    {
        var defaultPort = scheme == "https" ? 443 : 80;
        var authority = host.Contains(':') || port == defaultPort ? host : $"{host}:{port}";
        var p = string.IsNullOrEmpty(path) ? "/" : path;
        return $"{scheme}://{authority}{p}{query}";
    }

    private static int ParseInt(string? s)
        => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;

    private static double ParseDouble(string? s)
        => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;

    // Locates the first occurrence of needle in haystack; -1 if absent.
    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
        {
            return -1;
        }

        var last = haystack.Length - needle.Length;
        for (var i = 0; i <= last; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}
