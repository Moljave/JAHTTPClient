using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// JSON response returned by the native <c>request</c> function.
/// </summary>
/// <remarks>
/// <see cref="Id"/> identifies the native memory backing this response; it MUST
/// be passed to <c>freeMemory</c> once the response has been read, otherwise the
/// native side leaks. <see cref="JAHTTPClient.Native.TlsClientNative"/> does this
/// automatically.
/// </remarks>
public sealed class TlsResponsePayload
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("sessionId")]
    public string? SessionId { get; set; }

    [JsonPropertyName("status")]
    public int Status { get; set; }

    /// <summary>Final URL the request landed on (the native side only follows redirects if asked).</summary>
    [JsonPropertyName("target")]
    public string? Target { get; set; }

    /// <summary>Response body (base64 when the request set isByteResponse).</summary>
    [JsonPropertyName("body")]
    public string? Body { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, List<string>>? Headers { get; set; }

    [JsonPropertyName("cookies")]
    public Dictionary<string, string>? Cookies { get; set; }

    [JsonPropertyName("usedProtocol")]
    public string? UsedProtocol { get; set; }
}
