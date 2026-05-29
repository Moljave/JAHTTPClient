using System.Text.Json;
using System.Text.Json.Serialization;

namespace JAHTTPClient.Interop;

/// <summary>
/// Source-generated <see cref="JsonSerializerContext"/> for all interop DTOs.
/// Using the source generator avoids reflection-based (de)serialization, which
/// matters under heavy concurrency (thousands of requests/sec) and keeps the
/// library trim/AOT friendly.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    GenerationMode = JsonSourceGenerationMode.Default)]
[JsonSerializable(typeof(TlsRequestPayload))]
[JsonSerializable(typeof(TlsResponsePayload))]
[JsonSerializable(typeof(CustomTlsClient))]
[JsonSerializable(typeof(TlsCookie))]
[JsonSerializable(typeof(SessionCookiesPayload))]
[JsonSerializable(typeof(DestroySessionPayload))]
public partial class TlsJsonContext : JsonSerializerContext
{
}
