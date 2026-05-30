using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// Maps to the native tls-client <c>transportOptions</c> object. Controls the Go
/// HTTP transport's connection pooling. The defaults (all zero/false) leave the
/// native library's own defaults untouched.
/// </summary>
/// <remarks>
/// The key knob for rotating proxies is <see cref="DisableKeepAlives"/>: pooled
/// keep-alive connections are bound to a single proxy exit IP, so once the proxy
/// rotates, a reused connection is already dead and the next request fails with
/// <c>EOF</c>. Disabling keep-alives forces a fresh dial per request.
/// </remarks>
public sealed class TransportOptions
{
    [JsonPropertyName("disableKeepAlives")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableKeepAlives { get; set; }

    [JsonPropertyName("disableCompression")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool DisableCompression { get; set; }

    [JsonPropertyName("maxIdleConns")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int MaxIdleConns { get; set; }

    [JsonPropertyName("maxIdleConnsPerHost")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int MaxIdleConnsPerHost { get; set; }

    [JsonPropertyName("maxConnsPerHost")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int MaxConnsPerHost { get; set; }
}
