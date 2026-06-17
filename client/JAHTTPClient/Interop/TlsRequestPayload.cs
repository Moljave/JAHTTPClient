using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// JSON payload sent to the native <c>request</c> function. Field names match the
/// bogdanfinn/tls-client CFFI contract exactly.
/// </summary>
public sealed class TlsRequestPayload
{
    /// <summary>
    /// Stable per-client GUID. Reusing it across requests preserves the cookie
    /// jar and connection pool (and therefore Akamai/Cloudflare tokens).
    /// </summary>
    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = string.Empty;

    /// <summary>Built-in browser profile, e.g. <c>chrome_133</c>. Mutually exclusive with <see cref="CustomTlsClient"/>.</summary>
    [JsonPropertyName("tlsClientIdentifier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TlsClientIdentifier { get; set; }

    [JsonPropertyName("customTlsClient")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CustomTlsClient? CustomTlsClient { get; set; }

    [JsonPropertyName("requestUrl")]
    public string RequestUrl { get; set; } = string.Empty;

    [JsonPropertyName("requestMethod")]
    public string RequestMethod { get; set; } = "GET";

    /// <summary>Request body. For binary bodies set <see cref="IsByteRequest"/> and base64-encode.</summary>
    [JsonPropertyName("requestBody")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestBody { get; set; }

    [JsonPropertyName("isByteRequest")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsByteRequest { get; set; }

    /// <summary>Return the body base64-encoded (lets us preserve binary responses losslessly).</summary>
    [JsonPropertyName("isByteResponse")]
    public bool IsByteResponse { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>Explicit header emission order — critical for fingerprint fidelity.</summary>
    [JsonPropertyName("headerOrder")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? HeaderOrder { get; set; }

    [JsonPropertyName("requestCookies")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<TlsCookie>? RequestCookies { get; set; }

    /// <summary>We always handle redirects in managed code, so this stays false.</summary>
    [JsonPropertyName("followRedirects")]
    public bool FollowRedirects { get; set; }

    [JsonPropertyName("insecureSkipVerify")]
    public bool InsecureSkipVerify { get; set; }

    /// <summary>Use the per-session persistent cookie jar.</summary>
    [JsonPropertyName("withDefaultCookieJar")]
    public bool WithDefaultCookieJar { get; set; } = true;

    [JsonPropertyName("withoutCookieJar")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool WithoutCookieJar { get; set; }

    /// <summary>Chrome permutes its ClientHello extensions; this reproduces that.</summary>
    [JsonPropertyName("withRandomTLSExtensionOrder")]
    public bool WithRandomTlsExtensionOrder { get; set; } = true;

    [JsonPropertyName("forceHttp1")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ForceHttp1 { get; set; }

    [JsonPropertyName("timeoutMilliseconds")]
    public int TimeoutMilliseconds { get; set; }

    [JsonPropertyName("proxyUrl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProxyUrl { get; set; }

    [JsonPropertyName("isRotatingProxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsRotatingProxy { get; set; }

    /// <summary>Connection-pool tuning. Null = leave the native defaults in place.</summary>
    [JsonPropertyName("transportOptions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TransportOptions? TransportOptions { get; set; }
}
