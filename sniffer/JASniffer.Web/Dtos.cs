using System.Text;
using JASniffer.Core;
using JASniffer.Core.Models;
using JASniffer.Core.Parsing;

namespace JASniffer.Web;

/// <summary>Compact row shown in the live session grid and pushed over SignalR.</summary>
public sealed record SessionSummaryDto(
    int Id,
    string StartedUtc,
    double DurationMs,
    bool Completed,
    string Method,
    string Scheme,
    string Host,
    int Port,
    string Path,
    string Query,
    string Url,
    int Status,
    string? Reason,
    string RequestHttpVersion,
    string ResponseHttpVersion,
    string? ResponseContentType,
    long BodyLength,
    bool WasTunneled,
    bool FollowedRedirects,
    string? FinalUrl,
    string? Error,
    bool UpstreamOk,
    string FingerprintPreset,
    long TunnelBytesUp,
    long TunnelBytesDown,
    bool IsUdp);

public sealed record HeaderDto(string Name, string Value);

public sealed record BodyDto(string Kind, long Size, bool Truncated, bool IsText, string? Text, string? ContentType);

/// <summary>Everything the inspectors need for one session.</summary>
public sealed record SessionDetailDto(
    SessionSummaryDto Summary,
    IReadOnlyList<HeaderDto> RequestHeaders,
    IReadOnlyList<HeaderDto> ResponseHeaders,
    IReadOnlyList<QueryParam> QueryParams,
    IReadOnlyList<RequestCookie> RequestCookies,
    IReadOnlyList<ResponseCookie> ResponseCookies,
    AuthInfo? Auth,
    BodyDto RequestBody,
    BodyDto ResponseBody,
    string? TlsSummary,
    string? HostIp,
    string? ClientEndpoint);

/// <summary>Settings echoed to / accepted from the UI.</summary>
public sealed record SettingsDto(
    bool SmartRedirects,
    int MaxRedirects,
    bool Capture,
    string? UpstreamProxy,
    string FingerprintPreset,
    bool ForceHttp1);

/// <summary>One-shot status the UI shows in the header / CA panel.</summary>
public sealed record StatusDto(
    int ProxyPort,
    int UiPort,
    string CaSubject,
    string CaThumbprint,
    string CaStoreDirectory,
    string Platform,
    bool SystemProxySupported,
    bool SystemProxyEnabled,
    bool UdpSupported,
    bool UdpRunning,
    bool WinDivertInstalled);

/// <summary>Maps capture models to the wire DTOs, decoding textual bodies for display.</summary>
public static class DtoMapper
{
    private const int TextDisplayCap = 2 * 1024 * 1024;

    public static SessionSummaryDto ToSummary(CapturedSession s) => new(
        s.Id,
        s.StartedUtc.ToString("O"),
        Math.Round(s.DurationMs, 1),
        s.Completed,
        s.Method,
        s.Scheme,
        s.Host,
        s.Port,
        s.Path,
        s.Query,
        s.Url,
        s.StatusCode,
        s.ReasonPhrase,
        s.RequestHttpVersion,
        s.ResponseHttpVersion,
        s.ResponseContentType,
        s.BodyLength,
        s.WasTunneled,
        s.FollowedRedirects,
        s.FinalUrl,
        s.Error,
        s.UpstreamOk,
        s.FingerprintPreset,
        s.TunnelBytesUp,
        s.TunnelBytesDown,
        s.IsUdp);

    public static SessionDetailDto ToDetail(CapturedSession s) => new(
        ToSummary(s),
        ToHeaderDtos(s.RequestHeaders),
        ToHeaderDtos(s.ResponseHeaders),
        HttpParsing.ParseQuery(s.Query),
        HttpParsing.ParseRequestCookies(s.RequestHeaders),
        HttpParsing.ParseResponseCookies(s.ResponseHeaders),
        HttpParsing.ParseAuthorization(s.RequestHeaders),
        ToBody(s.RequestBody, s.RequestContentType, s.RequestBodyTruncated, s.RequestBody.LongLength),
        ToBody(s.ResponseBody, s.ResponseContentType, s.ResponseBodyTruncated, s.BodyLength),
        s.TlsSummary,
        s.HostIp,
        s.ClientEndpoint);

    private static List<HeaderDto> ToHeaderDtos(IReadOnlyList<HeaderEntry> headers)
    {
        var list = new List<HeaderDto>(headers.Count);
        foreach (var h in headers)
        {
            list.Add(new HeaderDto(h.Name, h.Value));
        }

        return list;
    }

    private static BodyDto ToBody(byte[] body, string? contentType, bool storedTruncated, long fullSize)
    {
        var kind = HttpParsing.ContentKind(contentType);
        var isText = HttpParsing.IsTextual(contentType) || (kind is "json" or "html" or "xml" or "text");

        if (!isText || body.Length == 0)
        {
            return new BodyDto(kind, fullSize, storedTruncated, isText, body.Length == 0 ? string.Empty : null, contentType);
        }

        var encoding = HttpParsing.CharsetOf(contentType);
        var text = encoding.GetString(body);
        var displayTruncated = false;
        if (text.Length > TextDisplayCap)
        {
            text = text[..TextDisplayCap];
            displayTruncated = true;
        }

        return new BodyDto(kind, fullSize, storedTruncated || displayTruncated, true, text, contentType);
    }
}
