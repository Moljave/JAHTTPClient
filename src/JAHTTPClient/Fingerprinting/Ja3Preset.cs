namespace JAHTTPClient.Fingerprinting;

/// <summary>
/// Browser fingerprint presets. Each maps to a native tls-client profile plus a
/// matching set of client hint headers (User-Agent, sec-ch-ua, platform).
/// </summary>
public enum Ja3Preset
{
    /// <summary>Chrome 148 desktop on Windows (TLS profile chrome_133 — structurally identical JA3/H2).</summary>
    Chrome,

    /// <summary>Newest Chrome profile available in the bundled native library (chrome_146).</summary>
    ChromeLatest,

    /// <summary>Microsoft Edge desktop on Windows.</summary>
    Edge,

    /// <summary>Firefox desktop on Windows.</summary>
    Firefox,

    /// <summary>Safari on macOS.</summary>
    Safari,

    /// <summary>Chrome on Android (mobile UA, sec-ch-ua-mobile: ?1). TLS profile is chrome_133 — same BoringSSL stack as Chrome 133 Android.</summary>
    AndroidChrome,
}
