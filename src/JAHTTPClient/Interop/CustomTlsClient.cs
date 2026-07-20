using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// Fully custom TLS/HTTP2 fingerprint definition for the native tls-client.
/// Only used when a caller wants to override the built-in browser profile
/// (e.g. to pin an exact Chrome 148 JA3 string instead of relying on the
/// <c>chrome_133</c>/<c>chrome_146</c> identifier).
/// </summary>
/// <remarks>
/// A request payload must specify <em>either</em>
/// <see cref="TlsRequestPayload.TlsClientIdentifier"/> <em>or</em>
/// <see cref="TlsRequestPayload.CustomTlsClient"/>, never both.
/// </remarks>
public sealed class CustomTlsClient
{
    /// <summary>JA3 string without GREASE values (the library injects GREASE).</summary>
    [JsonPropertyName("ja3String")]
    public string Ja3String { get; set; } = string.Empty;

    /// <summary>HTTP/2 SETTINGS values, keyed by name (e.g. HEADER_TABLE_SIZE).</summary>
    [JsonPropertyName("h2Settings")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, int>? H2Settings { get; set; }

    /// <summary>Order in which the HTTP/2 SETTINGS are emitted.</summary>
    [JsonPropertyName("h2SettingsOrder")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? H2SettingsOrder { get; set; }

    /// <summary>Order of HTTP/2 pseudo headers: :method, :authority, :scheme, :path.</summary>
    [JsonPropertyName("pseudoHeaderOrder")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? PseudoHeaderOrder { get; set; }

    /// <summary>Connection-level WINDOW_UPDATE flow increment.</summary>
    [JsonPropertyName("connectionFlow")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ConnectionFlow { get; set; }

    [JsonPropertyName("supportedSignatureAlgorithms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? SupportedSignatureAlgorithms { get; set; }

    [JsonPropertyName("supportedVersions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? SupportedVersions { get; set; }

    [JsonPropertyName("keyShareCurves")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? KeyShareCurves { get; set; }

    [JsonPropertyName("certCompressionAlgos")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CertCompressionAlgo { get; set; }

    [JsonPropertyName("alpnProtocols")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? AlpnProtocols { get; set; }
}
