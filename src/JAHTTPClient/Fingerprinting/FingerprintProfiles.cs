using JAHTTPClient.Interop;

namespace JAHTTPClient.Fingerprinting;

/// <summary>
/// Concrete fingerprint definition: the native TLS profile identifier and the
/// HTTP-layer hints (User-Agent / client hints / canonical header order) that
/// must accompany it so the TLS layer and the application layer tell the same
/// story to the server.
/// </summary>
public sealed record FingerprintProfile(
    string TlsIdentifier,
    string UserAgent,
    string SecChUa,
    string SecChUaMobile,
    string SecChUaPlatform,
    IReadOnlyList<string> HeaderOrder)
{
    /// <summary>
    /// When set, the native request uses a fully custom TLS+H2 specification
    /// instead of a named <see cref="TlsIdentifier"/> profile. The <see cref="TlsIdentifier"/>
    /// is ignored in this case. Use for presets where no built-in identifier matches
    /// (e.g. Chrome Android, which differs from desktop Chrome in cipher order, H2
    /// window size, and pseudo-header order).
    /// </summary>
    public CustomTlsClient? CustomTlsSpec { get; init; }
}

/// <summary>Resolves a <see cref="Ja3Preset"/> to a concrete <see cref="FingerprintProfile"/>.</summary>
public static class FingerprintProfiles
{
    /// <summary>
    /// Canonical Chrome header order. The native library uses this to sort the
    /// real (non-pseudo) headers; the HTTP/2 pseudo-header order comes from the
    /// TLS profile itself.
    /// </summary>
    private static readonly string[] ChromeHeaderOrder =
    [
        "host",
        "connection",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
        "cookie",
    ];

    private static readonly string[] FirefoxHeaderOrder =
    [
        "host", "user-agent", "accept", "accept-language", "accept-encoding",
        "referer", "connection", "upgrade-insecure-requests",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "cookie",
    ];

    /// <summary>
    /// Resolves a preset. When <paramref name="tlsIdentifierOverride"/> is set
    /// (from <c>ChromeHttpClientOptions.TlsIdentifier</c>) it replaces the
    /// preset's default native profile while keeping the matching headers.
    /// </summary>
    public static FingerprintProfile Resolve(Ja3Preset preset, string? tlsIdentifierOverride = null)
    {
        var profile = preset switch
        {
            Ja3Preset.Chrome => Chrome148(),
            Ja3Preset.ChromeLatest => ChromeLatest(),
            Ja3Preset.Edge => Edge(),
            Ja3Preset.Firefox => Firefox(),
            Ja3Preset.Safari => Safari(),
            Ja3Preset.AndroidChrome => AndroidChrome133(),
            _ => Chrome148(),
        };

        return string.IsNullOrWhiteSpace(tlsIdentifierOverride)
            ? profile
            : profile with { TlsIdentifier = tlsIdentifierOverride };
    }

    // Chrome 148 desktop (Windows). TLS/H2 fingerprint is taken from the
    // chrome_133 native profile — its ClientHello (cipher order, GREASE,
    // extension permutation, X25519MLKEM768 key share) and HTTP/2 settings are
    // identical to Chrome 148; only the UA/client-hint version strings differ.
    private static FingerprintProfile Chrome148() => new(
        TlsIdentifier: "chrome_133",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        SecChUa: "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
        SecChUaMobile: "?0",
        SecChUaPlatform: "\"Windows\"",
        HeaderOrder: ChromeHeaderOrder);

    private static FingerprintProfile ChromeLatest() => Chrome148() with
    {
        TlsIdentifier = "chrome_146",
    };

    private static FingerprintProfile Edge() => new(
        TlsIdentifier: "chrome_133",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
        SecChUa: "\"Chromium\";v=\"148\", \"Microsoft Edge\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
        SecChUaMobile: "?0",
        SecChUaPlatform: "\"Windows\"",
        HeaderOrder: ChromeHeaderOrder);

    private static FingerprintProfile Firefox() => new(
        TlsIdentifier: "firefox_135",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        SecChUa: string.Empty,
        SecChUaMobile: string.Empty,
        SecChUaPlatform: string.Empty,
        HeaderOrder: FirefoxHeaderOrder);

    private static FingerprintProfile Safari() => new(
        TlsIdentifier: "safari_18_0",
        UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        SecChUa: string.Empty,
        SecChUaMobile: string.Empty,
        SecChUaPlatform: string.Empty,
        HeaderOrder: ChromeHeaderOrder);

    // Chrome 133 on Android. Uses CustomTlsSpec with the EXACT ClientHello captured from
    // a real Android Chrome (tls.peet.ws), since Android Chrome differs from desktop:
    //   • Cipher order: 4866 (CHACHA) before 4867 (AES-256) — opposite of desktop
    //   • Extra ECDSA-CBC ciphers (49162, 49161) not in desktop
    //   • 7 curves instead of 4 (P-521, ffdhe2048, ffdhe3072)
    //   • Extensions: record_size_limit(28), delegated_credentials(34) present;
    //     no session_ticket(35)/psk_key_exchange_modes(45)/application_settings(17613)
    //   • H2: INITIAL_WINDOW_SIZE=131072 (128KB vs desktop 6MB), pseudo-order m,p,a,s
    //   • No GREASE in supported_versions or curves
    // JA3: 05d763dd92dbfd8857b606c7ee5279ba
    private static FingerprintProfile AndroidChrome133() => new(
        TlsIdentifier: string.Empty,
        UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        SecChUa: "\"Chromium\";v=\"133\", \"Google Chrome\";v=\"133\", \"Not/A)Brand\";v=\"99\"",
        SecChUaMobile: "?1",
        SecChUaPlatform: "\"Android\"",
        HeaderOrder: ChromeHeaderOrder)
    {
        CustomTlsSpec = new CustomTlsClient
        {
            Ja3String = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,27-13-23-18-11-51-10-16-28-5-65037-34-43-0-65281,4588-29-23-24-25-256-257,0",
            // H2 SETTINGS: Akamai fingerprint 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
            H2Settings = new Dictionary<string, int>
            {
                ["HEADER_TABLE_SIZE"] = 65536,
                ["ENABLE_PUSH"] = 0,
                ["INITIAL_WINDOW_SIZE"] = 131072,
                ["MAX_HEADER_LIST_SIZE"] = 16384,
            },
            H2SettingsOrder = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE"],
            ConnectionFlow = 12517377,
            // Android Chrome uses :method,:path,:authority,:scheme — desktop uses m,a,s,p
            PseudoHeaderOrder = [":method", ":path", ":authority", ":scheme"],
            // Only X25519MLKEM768 + X25519 actually send key material (supported_groups has 7)
            KeyShareCurves = ["X25519MLKEM768", "X25519"],
            SupportedVersions = ["TLSv1.3", "TLSv1.2"],
            CertCompressionAlgo = "brotli",
            AlpnProtocols = ["h2", "http/1.1"],
        },
    };
}
