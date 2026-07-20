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
    IReadOnlyList<string> HeaderOrder);

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

    // Chrome 133 on Android. Uses the same chrome_133 BoringSSL TLS stack (X25519MLKEM768,
    // ECH, cipher/extension order) with mobile UA and sec-ch-ua-mobile: ?1 so the HTTP
    // layer matches what the browser actually sends on the JA3 captured below.
    // JA3 (captured from tls.peet.ws on Android Chrome):
    //   05d763dd92dbfd8857b606c7ee5279ba
    //   771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,
    //   27-13-23-18-11-51-10-16-28-5-65037-34-43-0-65281,4588-29-23-24-25-256-257,0
    private static FingerprintProfile AndroidChrome133() => new(
        TlsIdentifier: "chrome_133",
        UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
        SecChUa: "\"Chromium\";v=\"133\", \"Google Chrome\";v=\"133\", \"Not/A)Brand\";v=\"99\"",
        SecChUaMobile: "?1",
        SecChUaPlatform: "\"Android\"",
        HeaderOrder: ChromeHeaderOrder);
}
