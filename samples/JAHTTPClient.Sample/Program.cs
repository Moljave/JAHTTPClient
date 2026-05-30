using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;

// =============================================================================
// JAHTTPClient sample — Chrome 148 TLS (JA3/JA4) + HTTP/2 impersonation.
//
// Requires the native tls-client library to be present (see /native build
// scripts). Without it, requests throw a DllNotFoundException.
// =============================================================================

// Modes:
//   (no args)         -> JA3 check + ExecuteShortWEBRequestAsync demo
//   --probe [url]     -> hit a real anti-bot target at 3 redirect levels and
//                        report whether it blocked (default: kleinanzeigen login)
//   --load [count]    -> high-concurrency smoke test (default 5000 POSTs)
if (args.Length > 0 && args[0] == "--probe")
{
    var url = args.Length > 1 ? args[1] : "https://www.kleinanzeigen.de/m-einloggen.html?targetUrl=/";
    await ProbeTargetAsync(url);
    return;
}

if (args.Length > 0 && args[0] == "--load")
{
    var count = args.Length > 1 && int.TryParse(args[1], out var n) ? n : 5000;
    await ConcurrencySmokeTestAsync(count);
    return;
}

// 1) ---- Verify the TLS fingerprint against scrapfly --------------------------
await VerifyFingerprintAsync();

// 2) ---- Verify a real Akamai-protected target (kleinanzeigen login) ----------
await VerifyKleinanzeigenAsync();

// 3) ---- Demonstrate the HttpClient-style migration helper --------------------
await DemonstrateExecuteShortWebRequestAsync();

// 4) ---- Demonstrate runtime redirect toggle + cookie export ------------------
await DemonstrateCookieExportAndRedirectToggleAsync();

return;

static async Task VerifyFingerprintAsync()
{
    Console.WriteLine("== JA3 fingerprint check (tools.scrapfly.io) ==");

    using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = Ja3Preset.Chrome,   // Chrome 148
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 10,
    });

    using var request = new HttpRequestMessage(HttpMethod.Get, "https://tools.scrapfly.io/api/fp/ja3");
    request.Headers.TryAddWithoutValidation("Accept", "application/json");

    using var response = await client.SendAsync(request);
    var json = await response.Content.ReadAsStringAsync();

    Console.WriteLine($"Status     : {(int)response.StatusCode} {response.StatusCode}");
    Console.WriteLine($"Final URL  : {response.RequestMessage?.RequestUri}");
    Console.WriteLine($"Body       : {json}");
    Console.WriteLine("Compare the reported ja3 with a real Chrome 148 fingerprint.");
    Console.WriteLine();
}

// Hits the Akamai-protected kleinanzeigen login (SSO) endpoint with the proven
// configuration (Chrome JA3 + HTTP/1.1) and follows the redirect chain. On a
// clean IP this lands on https://login.kleinanzeigen.de/.../identifier (200);
// a 403 "IP-Bereich gesperrt" means the TLS fingerprint or the IP was rejected.
static async Task VerifyKleinanzeigenAsync()
{
    const string url = "https://www.kleinanzeigen.de/m-einloggen-sso.html";
    Console.WriteLine("== Kleinanzeigen login check (Akamai) ==");

    using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = Ja3Preset.Chrome,
        ForceHttp1 = true,               // Chrome-JA3 over HTTP/1.1 is the proven config
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 15,
        Timeout = TimeSpan.FromSeconds(30),
        // Proxy = "http://user:pass@host:port", // use a clean/residential proxy if your IP is flagged
    });

    using var request = new HttpRequestMessage(HttpMethod.Get, url);
    request.Headers.TryAddWithoutValidation("Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    request.Headers.TryAddWithoutValidation("Accept-Language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7");
    request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br, zstd");
    request.Headers.TryAddWithoutValidation("Upgrade-Insecure-Requests", "1");
    request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "none");
    request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
    request.Headers.TryAddWithoutValidation("Sec-Fetch-User", "?1");
    request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "document");

    try
    {
        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? string.Empty;
        var reachedLogin = finalUrl.Contains("login.kleinanzeigen.de", StringComparison.OrdinalIgnoreCase);
        var banned = (int)response.StatusCode is 403 or 429 or 503
                     || body.Contains("IP-Bereich", StringComparison.OrdinalIgnoreCase)
                     || body.Contains("gesperrt", StringComparison.OrdinalIgnoreCase);

        Console.WriteLine($"Status     : {(int)response.StatusCode} {response.StatusCode}  (HTTP/{response.Version})");
        Console.WriteLine($"Final URL  : {finalUrl}");
        Console.WriteLine($"Body len   : {body.Length}");
        Console.WriteLine(reachedLogin ? "Verdict    : ✅ PASSED (reached login.kleinanzeigen.de)"
                         : banned       ? "Verdict    : ❌ BLOCKED (IP-ban / fingerprint rejected)"
                                        : "Verdict    : ⚠️ inconclusive");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Verdict    : 💥 {ex.GetType().Name}: {ex.Message}");
    }

    Console.WriteLine();
}

static async Task DemonstrateExecuteShortWebRequestAsync()
{
    Console.WriteLine("== ExecuteShortWEBRequestAsync demo ==");

    using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = Ja3Preset.Chrome,
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 1, // stop after the first redirect ("проверка" step)
    });

    var result = await ExecuteShortWebRequestAsync(client, HttpMethod.Get, "https://tools.scrapfly.io/api/fp/ja3");

    Console.WriteLine($"success={result.success}  status={(int)result.statusCode}  url={result.requestUrl}");
    Console.WriteLine($"location='{result.location}'");
    Console.WriteLine($"body[0..120]={Truncate(result.body, 120)}");
    Console.WriteLine();
}

// Shows (a) flipping AllowAutoRedirect at runtime — no need to rebuild the
// client — and (b) exporting the accumulated session cookies as JSON in the
// browser cookie-extension format for saving/replaying later.
static async Task DemonstrateCookieExportAndRedirectToggleAsync()
{
    Console.WriteLine("== Runtime redirect toggle + cookie export ==");

    using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = Ja3Preset.Chrome,
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 10,
    });

    // Flip the policy on the fly: capture the raw 3xx instead of following it.
    ChangeRedirectionState(client, enabled: false);
    using (var raw = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://httpbin.org/redirect/2")))
    {
        Console.WriteLine($"AllowAutoRedirect=false -> status {(int)raw.StatusCode} (Location: {raw.Headers.Location})");
    }

    // Re-enable and follow the whole chain, picking up cookies along the way.
    ChangeRedirectionState(client, enabled: true);
    using (var followed = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://httpbin.org/cookies/set?demo=jahttpclient")))
    {
        Console.WriteLine($"AllowAutoRedirect=true  -> final URL {followed.RequestMessage?.RequestUri}");
    }

    // Export every cookie observed this session (browser-extension JSON shape).
    var json = client.Cookies.GetCookiesJson(indented: true);
    Console.WriteLine("Exported cookies (client.Cookies.GetCookiesJson):");
    Console.WriteLine(json);

    // Hot-swap the egress proxy at runtime (cookies/session are preserved).
    ChangeProxy(client, "http://user:pass@proxy.example.com:8000");
    Console.WriteLine($"Proxy after SetProxy : {client.Proxy}");
    ChangeProxy(client, null); // back to direct egress
    Console.WriteLine($"Proxy after reset    : {client.Proxy ?? "(direct)"}");
    Console.WriteLine();
}

// The on-the-fly redirect switch requested in the task: no client rebuild needed.
static void ChangeRedirectionState(ChromeHttpClient client, bool enabled) => client.AllowAutoRedirect = enabled;

// Hot-swap the proxy at runtime: client.SetProxy(...). Pass null to go direct.
static void ChangeProxy(ChromeHttpClient client, string? proxyUrl) => client.SetProxy(proxyUrl);

// Drop-in replacement for the user's existing helper, now running over the
// browser-impersonating client. Same tuple shape; uses HttpRequestMessage /
// HttpResponseMessage / CancellationToken exactly like the original.
static async Task<(bool success, bool successStatusCode, string body, string errorMessage,
    string location, HttpStatusCode statusCode, string requestUrl, Stream? bodyStream,
    HttpResponseHeaders headers)> ExecuteShortWebRequestAsync(
        ChromeHttpClient client,
        HttpMethod method,
        string url,
        StringContent? stringContent = null,
        FormUrlEncodedContent? formContent = null,
        string? customHeaders = null,
        Dictionary<string, string>? multipartContent = null,
        string? additionalHeaders = null,
        CancellationToken cancellationToken = default)
{
    var errorMessage = string.Empty;
    try
    {
        using var request = new HttpRequestMessage(method, url);
        if (stringContent is not null) request.Content = stringContent;

        if (multipartContent is not null)
        {
            var boundary = $"----WebKitFormBoundary{Guid.NewGuid():N}";
            var form = new MultipartFormDataContent(boundary);
            form.Headers.Remove("Content-Type");
            form.Headers.TryAddWithoutValidation("Content-Type", $"multipart/form-data; boundary={boundary}");
            foreach (var (key, value) in multipartContent)
            {
                var part = new StringContent(value);
                part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = $"\"{key}\"" };
                part.Headers.ContentType = null;
                form.Add(part);
            }

            request.Content = form;
        }

        if (formContent is not null) request.Content = formContent;
        AddHeaders(request, customHeaders);
        AddHeaders(request, additionalHeaders);

        var response = await client.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var location = response.Headers.Location?.ToString() ?? string.Empty;

        return (true, response.IsSuccessStatusCode, content, errorMessage, location,
            response.StatusCode, response.RequestMessage?.RequestUri?.ToString() ?? string.Empty,
            null, response.Headers);
    }
    catch (Exception ex)
    {
        errorMessage = ex.Message;
        return (false, false, string.Empty, errorMessage, string.Empty,
            HttpStatusCode.NetworkAuthenticationRequired, string.Empty, null,
            new HttpResponseMessage().Headers);
    }
}

// Minimal stand-in for the user's HttpRequestMessage.AddHeaders extension:
// parses a "Name: Value" per-line block and preserves order.
static void AddHeaders(HttpRequestMessage request, string? block)
{
    if (string.IsNullOrWhiteSpace(block))
    {
        return;
    }

    foreach (var line in block.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        var idx = line.IndexOf(':');
        if (idx <= 0)
        {
            continue;
        }

        var name = line[..idx].Trim();
        var value = line[(idx + 1)..].Trim();
        request.Headers.TryAddWithoutValidation(name, value);
    }
}

static async Task ConcurrencySmokeTestAsync(int requests)
{
    Console.WriteLine($"== Concurrency smoke test ({requests} POSTs) ==");

    using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
    {
        EnableJa3Fingerprinting = true,
        FingerprintPreset = Ja3Preset.Chrome,
        // Proxy = "http://user:pass@host:port",
        // MaxConcurrency = 1000, // uncomment to bound memory under extreme fan-out
    });

    var sw = Stopwatch.StartNew();
    var ok = 0;
    var failed = 0;

    var tasks = Enumerable.Range(0, requests).Select(async i =>
    {
        try
        {
            var content = new StringContent("{\"ping\":true}", Encoding.UTF8, "application/json");
            using var resp = await client.PostAsync("https://tools.scrapfly.io/api/fp/ja3", content);
            await resp.Content.ReadAsStringAsync();
            Interlocked.Increment(ref ok);
        }
        catch
        {
            Interlocked.Increment(ref failed);
        }
    });

    await Task.WhenAll(tasks);
    sw.Stop();

    Console.WriteLine($"ok={ok} failed={failed} elapsed={sw.Elapsed.TotalSeconds:F1}s");
}

// Probe a real anti-bot protected target (e.g. Akamai) at three redirect levels.
// On a clean/residential IP with direct egress this should NOT show the IP-ban
// page: the first hop is a 3xx into the login flow.
static async Task ProbeTargetAsync(string url)
{
    Console.WriteLine($"== Probe: {url} ==\n");

    foreach (var (label, redirect, max) in new[]
    {
        ("AllowAutoRedirect=false (raw first hop)", false, 0),
        ("Max=1 (catch the first redirect)", true, 1),
        ("Max=10 (follow the whole chain)", true, 10),
    })
    {
        Console.WriteLine($"----- {label} -----");
        try
        {
            using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
            {
                EnableJa3Fingerprinting = true,
                FingerprintPreset = Ja3Preset.Chrome,
                // Chrome-JA3 over HTTP/1.1 is the configuration proven to pass
                // Akamai on kleinanzeigen (the reference uTLS test forces h1 to
                // avoid the extra HTTP/2 fingerprint vector). Drop this to use h2.
                ForceHttp1 = true,
                AllowAutoRedirect = redirect,
                MaxAutomaticRedirections = max,
                Timeout = TimeSpan.FromSeconds(30),
                // Proxy = "http://user:pass@host:port", // recommended: clean/residential proxy
            });

            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
            req.Headers.TryAddWithoutValidation("Accept-Language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7");
            req.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br, zstd");
            req.Headers.TryAddWithoutValidation("Upgrade-Insecure-Requests", "1");
            req.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "none");
            req.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
            req.Headers.TryAddWithoutValidation("Sec-Fetch-User", "?1");
            req.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "document");

            using var resp = await client.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            var loc = resp.Headers.Location?.ToString() ?? "(none)";
            var banned = (int)resp.StatusCode is 403 or 429 or 503
                         || body.Contains("IP-Bereich", StringComparison.OrdinalIgnoreCase)
                         || body.Contains("gesperrt", StringComparison.OrdinalIgnoreCase);

            Console.WriteLine($"  status   : {(int)resp.StatusCode} {resp.StatusCode}");
            Console.WriteLine($"  finalUrl : {resp.RequestMessage?.RequestUri}");
            Console.WriteLine($"  location : {loc}");
            Console.WriteLine($"  bodyLen  : {body.Length}");
            Console.WriteLine($"  body     : {Truncate(body.Replace('\n', ' '), 200)}");
            Console.WriteLine(banned ? "  VERDICT  : ❌ BLOCKED (IP-ban / fingerprint detected)\n"
                                     : "  VERDICT  : ✅ NOT blocked (passed)\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}\n");
        }
    }
}

static string Truncate(string value, int max)
    => string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max];
