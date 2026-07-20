namespace JASniffer.Core.Models;

/// <summary>
/// One intercepted HTTP(S) exchange: everything the proxy observed on the client
/// leg (the browser's request) plus the upstream leg (the response produced by
/// re-issuing that request through <c>JAHTTPClient</c> with a Chrome fingerprint).
/// </summary>
/// <remarks>
/// A session is created the moment the request line is parsed (so it appears in
/// the UI immediately, before the upstream call returns) and then mutated in
/// place when the response — or an error — arrives. All mutation goes through the
/// owning <see cref="SessionStore"/> under its lock, so individual fields are not
/// independently synchronized here.
/// </remarks>
public sealed class CapturedSession
{
    /// <summary>Sequential id assigned by the store; also the <c>.saz</c> ordinal.</summary>
    public required int Id { get; init; }

    /// <summary>When the request was received by the proxy.</summary>
    public DateTimeOffset StartedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Total round-trip time once the response (or error) is recorded.</summary>
    public double DurationMs { get; set; }

    /// <summary><c>true</c> once a response or error has been recorded.</summary>
    public bool Completed { get; set; }

    // ---- request (client leg, always HTTP/1.1 over the browser↔proxy link) ----

    public required string Method { get; set; }
    public required string Scheme { get; init; }
    public required string Host { get; init; }
    public int Port { get; init; }
    public required string Path { get; init; }
    public string Query { get; init; } = string.Empty;

    /// <summary>Absolute request URL, e.g. <c>https://host:443/path?q</c> (default port omitted).</summary>
    public required string Url { get; init; }

    /// <summary>Protocol on the browser↔proxy leg. Always <c>1.1</c> by design (ALPN offers only http/1.1).</summary>
    public string RequestHttpVersion { get; init; } = "1.1";

    public IReadOnlyList<HeaderEntry> RequestHeaders { get; set; } = [];
    public byte[] RequestBody { get; set; } = [];
    public bool RequestBodyTruncated { get; set; }
    public string? RequestContentType { get; set; }

    // ---- response (upstream leg, protocol negotiated by JAHTTPClient) ----------

    public int StatusCode { get; set; }
    public string? ReasonPhrase { get; set; }

    /// <summary>Protocol actually negotiated upstream (from <c>response.Version</c>): <c>2.0</c> or <c>1.1</c>.</summary>
    public string ResponseHttpVersion { get; set; } = string.Empty;

    public IReadOnlyList<HeaderEntry> ResponseHeaders { get; set; } = [];

    /// <summary>Response body, already decoded (gzip/br/zstd removed) by the upstream client.</summary>
    public byte[] ResponseBody { get; set; } = [];
    public bool ResponseBodyTruncated { get; set; }
    public string? ResponseContentType { get; set; }

    /// <summary>Decoded response body length in bytes (what the UI shows as "BODY: …").</summary>
    public long BodyLength { get; set; }

    // ---- meta ------------------------------------------------------------------

    /// <summary>Final URL after upstream redirect following (smart redirects on); equals <see cref="Url"/> otherwise.</summary>
    public string? FinalUrl { get; set; }

    /// <summary>Whether the upstream client followed the redirect chain for this session.</summary>
    public bool FollowedRedirects { get; set; }

    /// <summary>Human label for the emulated fingerprint, e.g. <c>Chrome 148</c>.</summary>
    public string FingerprintPreset { get; set; } = "Chrome 148";

    /// <summary>
    /// Honest TLS hint derived from the active preset and the negotiated protocol,
    /// e.g. <c>Chrome 148 · TLS 1.3 (assumed)</c>. The upstream client does not
    /// surface the real negotiated TLS version, so this is explicitly marked.
    /// </summary>
    public string? TlsSummary { get; set; }

    /// <summary>
    /// Full TLS fingerprint (JA3/JA4 + parsed cipher/extension/curve/ALPN detail) of the
    /// upstream leg for this request, captured over loopback for the active preset. Stored
    /// per request so it survives a <c>.saz</c> export/import and is shown in the Info tab
    /// even for archives opened on a machine that never ran a live scan. Null when the
    /// engine couldn't be self-tested, or for tunneled/UDP flows that never used it.
    /// </summary>
    public SessionFingerprint? Fingerprint { get; set; }

    /// <summary><c>true</c> only when the upstream handshake/exchange completed without a transport error.</summary>
    public bool UpstreamOk { get; set; }

    public string? ClientEndpoint { get; set; }
    public string? HostIp { get; set; }

    /// <summary>Transport-level error message when the upstream call failed (no HTTP response).</summary>
    public string? Error { get; set; }

    /// <summary>
    /// <c>true</c> for raw byte tunnels (WebSocket/SSE/HTTP-upgrade or CONNECT to a
    /// non-HTTP port) that <c>JAHTTPClient</c> cannot buffer, so they are passed
    /// through uninspected to keep the browser working.
    /// </summary>
    public bool WasTunneled { get; set; }

    /// <summary>
    /// <c>true</c> for passively-captured UDP flows (DNS/QUIC) observed via WinDivert.
    /// These are read-only: they are never relayed or re-fingerprinted (the upstream
    /// engine is TCP/TLS only), just summarized for visibility.
    /// </summary>
    public bool IsUdp { get; set; }

    /// <summary>Datagrams seen in each direction for a tunneled/UDP flow.</summary>
    public long Packets { get; set; }

    /// <summary>Bytes shuttled in each direction (client→server, server→client) for a tunneled/UDP flow.</summary>
    public long TunnelBytesUp { get; set; }
    public long TunnelBytesDown { get; set; }
}
