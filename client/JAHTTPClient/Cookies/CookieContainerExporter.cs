using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JAHTTPClient.Cookies;

/// <summary>
/// Serialises cookies into the JSON shape consumed by popular browser cookie
/// extensions (Cookie-Editor / EditThisCookie), so a captured session can be
/// exported, stored on disk, and later re-imported into a browser or another
/// client. Expired cookies are dropped.
/// </summary>
/// <remarks>
/// This is the symmetric counterpart to <see cref="ChromeCookieContainer.Import"/>:
/// <see cref="ChromeCookieContainer.GetCookiesJson()"/> exports the live session
/// jar through this serializer.
/// </remarks>
public static class CookieContainerExporter
{
    // Source-generated metadata keeps the export trim/AOT friendly, consistent
    // with the rest of the interop layer. The relaxed encoder mirrors what the
    // browser extensions emit (no over-escaping of '/', '&', etc.).
    private static readonly JsonSerializerOptions CompactOptions = new(CookieJsonContext.Default.Options)
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly JsonSerializerOptions IndentedOptions = new(CompactOptions)
    {
        WriteIndented = true,
    };

    /// <summary>
    /// Serialises every cookie held by <paramref name="container"/> to a JSON
    /// array in browser-extension format. Expired cookies are skipped.
    /// </summary>
    public static string ToJson(CookieContainer container, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(container);
        return ToJson(container.GetAllCookies(), indented);
    }

    /// <summary>
    /// Serialises an explicit cookie sequence (e.g. the cookies applicable to a
    /// single URL) to a JSON array in browser-extension format.
    /// </summary>
    public static string ToJson(IEnumerable<Cookie> cookies, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(cookies);

        var now = DateTime.UtcNow;

        var dtos = cookies
            .Where(c => !IsExpired(c, now))
            .Select(ToDto)
            .ToList();

        return JsonSerializer.Serialize(dtos, indented ? IndentedOptions : CompactOptions);
    }

    private static bool IsExpired(Cookie c, DateTime nowUtc)
    {
        if (c.Expired) return true;
        // Session cookies (Expires == DateTime.MinValue) never count as expired.
        if (c.Expires == DateTime.MinValue) return false;
        return c.Expires.ToUniversalTime() <= nowUtc;
    }

    private static CookieDto ToDto(Cookie c)
    {
        bool isSession = c.Expires == DateTime.MinValue;

        double? expiration = isSession
            ? null
            : new DateTimeOffset(c.Expires.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000.0;

        // In a CookieContainer a leading dot in Domain means "not host-only" (RFC 6265).
        bool hostOnly = !c.Domain.StartsWith('.');

        return new CookieDto
        {
            Domain = c.Domain,
            ExpirationDate = expiration,
            HostOnly = hostOnly,
            HttpOnly = c.HttpOnly,
            Name = c.Name,
            Path = string.IsNullOrEmpty(c.Path) ? "/" : c.Path,
            Secure = c.Secure,
            Session = isSession,
            SourceScheme = c.Secure ? "secure" : "nonsecure",
            SourcePort = c.Secure ? 443 : 80,
            Value = c.Value,
        };
    }
}

/// <summary>JSON DTO matching the browser cookie-extension export schema.</summary>
internal sealed class CookieDto
{
    [JsonPropertyName("domain")]
    public required string Domain { get; init; }

    [JsonPropertyName("expirationDate")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? ExpirationDate { get; init; }

    [JsonPropertyName("hostOnly")]
    public bool HostOnly { get; init; }

    [JsonPropertyName("httpOnly")]
    public bool HttpOnly { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("priority")]
    public string Priority { get; init; } = "medium";

    [JsonPropertyName("sameSite")]
    public string SameSite { get; init; } = "unspecified";

    [JsonPropertyName("secure")]
    public bool Secure { get; init; }

    [JsonPropertyName("session")]
    public bool Session { get; init; }

    [JsonPropertyName("sourcePort")]
    public int SourcePort { get; init; }

    [JsonPropertyName("sourceScheme")]
    public string SourceScheme { get; init; } = "secure";

    [JsonPropertyName("storeId")]
    public string StoreId { get; init; } = "0";

    [JsonPropertyName("value")]
    public required string Value { get; init; }
}

/// <summary>Source-generated serializer context for the cookie export DTO.</summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Default)]
[JsonSerializable(typeof(List<CookieDto>))]
internal partial class CookieJsonContext : JsonSerializerContext
{
}
