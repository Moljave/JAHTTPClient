using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// Wire representation of a cookie exchanged with the native tls-client library
/// (used both for request cookies and for <c>addCookiesToSession</c>).
/// </summary>
public sealed class TlsCookie
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }

    [JsonPropertyName("domain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Domain { get; set; }

    /// <summary>Unix expiry (seconds). 0/absent = session cookie.</summary>
    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public long Expires { get; set; }
}
