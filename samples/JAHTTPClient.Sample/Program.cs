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

// 1) ---- Verify the TLS fingerprint against scrapfly --------------------------
await VerifyFingerprintAsync();

// 2) ---- Demonstrate the HttpClient-style migration helper --------------------
await DemonstrateExecuteShortWebRequestAsync();

// 3) ---- (Optional) high-concurrency smoke test -------------------------------
//    Uncomment to drive thousands of concurrent requests.
// await ConcurrencySmokeTestAsync(requests: 5000);

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

    var tasks = Enumerable.Range(0, requests).Select(async _ =>
    {
        try
        {
            var content = new StringContent("{\"ping\":true}", Encoding.UTF8, "application/json");
            using var resp = await client.PostAsync("https://tools.scrapfly.io/api/fp/ja3", content);
            _ = await resp.Content.ReadAsStringAsync();
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

static string Truncate(string value, int max)
    => string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max];
