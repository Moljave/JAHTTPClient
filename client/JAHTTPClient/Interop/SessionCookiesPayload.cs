using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>Payload for <c>getCookiesFromSession</c> / <c>addCookiesToSession</c>.</summary>
public sealed class SessionCookiesPayload
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("cookies")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<TlsCookie>? Cookies { get; set; }
}

/// <summary>Payload for <c>destroySession</c>.</summary>
public sealed class DestroySessionPayload
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = string.Empty;
}
