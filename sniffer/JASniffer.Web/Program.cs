using System.Net;
using JASniffer.Core;
using JASniffer.Core.Certificates;
using JASniffer.Core.Export;
using JASniffer.Core.Models;
using JASniffer.Web;
using JASniffer.Proxy;
using JASniffer.Proxy.Udp;

var builder = WebApplication.CreateBuilder(args);

// Ports (overridable via config/env: JASniffer__UiPort / JASniffer__ProxyPort).
var uiPort = builder.Configuration.GetValue("JASniffer:UiPort", 8888);
var proxyPort = builder.Configuration.GetValue("JASniffer:ProxyPort", 8866);
var caDir = builder.Configuration.GetValue<string?>("JASniffer:CaDirectory", null);

builder.WebHost.UseUrls($"http://localhost:{uiPort}");

// ---- services --------------------------------------------------------------
var settings = new SnifferSettings { SelfUiPort = uiPort };
var settingsPath = Path.Combine(caDir ?? CertificateAuthority.DefaultStoreDirectory, "settings.json");
SettingsFile.Apply(settings, settingsPath); // restore persisted preset/redirects/etc.
builder.Services.AddSingleton(settings);
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddSingleton(CertificateAuthority.LoadOrCreate(caDir));
builder.Services.AddSingleton<UpstreamRelay>();
builder.Services.AddSingleton<SystemProxy>();
builder.Services.AddSingleton<UdpCaptureService>();
var winDivertUrl = builder.Configuration.GetValue("JASniffer:WinDivertUrl", WinDivertInstaller.DefaultUrl)!;
var winDivertSha = builder.Configuration.GetValue("JASniffer:WinDivertSha256", WinDivertInstaller.DefaultSha256)!;
builder.Services.AddSingleton(sp => new WinDivertInstaller(sp.GetRequiredService<ILogger<WinDivertInstaller>>())
{
    DownloadUrl = winDivertUrl,
    ExpectedSha256 = winDivertSha,
});
builder.Services.AddSingleton(sp => new ProxyServer(
    sp.GetRequiredService<SnifferSettings>(),
    sp.GetRequiredService<SessionStore>(),
    sp.GetRequiredService<UpstreamRelay>(),
    sp.GetRequiredService<CertificateAuthority>(),
    sp.GetRequiredService<ILogger<ProxyServer>>())
{
    Port = proxyPort,
    Address = IPAddress.Loopback,
});

builder.Services.AddHostedService<ProxyHostedService>();
builder.Services.AddHostedService<SessionBroadcaster>();
builder.Services.AddSignalR();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// ---- REST API --------------------------------------------------------------
var api = app.MapGroup("/api");

api.MapGet("/status", (CertificateAuthority ca, SystemProxy systemProxy, UdpCaptureService udp, WinDivertInstaller windivert) => new StatusDto(
    proxyPort,
    uiPort,
    ca.Subject,
    ca.Thumbprint,
    CertificateAuthority.DefaultStoreDirectory,
    System.Runtime.InteropServices.RuntimeInformation.OSDescription,
    systemProxy.Supported,
    systemProxy.Enabled,
    udp.Supported,
    udp.Running,
    windivert.IsInstalled));

api.MapGet("/settings", (SnifferSettings s) => Settings(s));

api.MapPost("/settings", (SettingsDto dto, SnifferSettings s, UpstreamRelay relay) =>
{
    s.SmartRedirects = dto.SmartRedirects;
    s.MaxRedirects = dto.MaxRedirects;
    s.Capture = dto.Capture;
    s.UpstreamProxy = dto.UpstreamProxy;
    s.FingerprintPreset = dto.FingerprintPreset;
    s.ForceHttp1 = dto.ForceHttp1;
    relay.Reconfigure(s.FingerprintPreset, s.ForceHttp1); // rebuilds the upstream clients only if these changed
    SettingsFile.Save(s, settingsPath);
    return Settings(s);
});

api.MapGet("/sessions", (SessionStore store) =>
    store.Snapshot().Select(DtoMapper.ToSummary).ToArray());

api.MapGet("/sessions/{id:int}", (int id, SessionStore store) =>
{
    var session = store.Get(id);
    return session is null ? Results.NotFound() : Results.Ok(DtoMapper.ToDetail(session));
});

api.MapGet("/sessions/{id:int}/request-body", (int id, SessionStore store, bool download = false) =>
{
    var session = store.Get(id);
    return session is null
        ? Results.NotFound()
        : ServeBody(session.RequestBody, session.RequestContentType, $"request-{id}", download);
});

api.MapGet("/sessions/{id:int}/response-body", (int id, SessionStore store, bool download = false) =>
{
    var session = store.Get(id);
    return session is null
        ? Results.NotFound()
        : ServeBody(session.ResponseBody, session.ResponseContentType, $"response-{id}", download);
});

api.MapDelete("/sessions/{id:int}", (int id, SessionStore store) =>
    store.Remove(id) ? Results.NoContent() : Results.NotFound());

api.MapPost("/clear", (SessionStore store) =>
{
    store.Clear();
    return Results.NoContent();
});

api.MapGet("/ca.cer", (CertificateAuthority ca) =>
    Results.File(ca.ExportCaCertificateDer(), "application/x-x509-ca-cert", "JASniffer-rootCA.cer"));

api.MapPost("/install-ca", (CertificateAuthority ca) =>
{
    var (ok, message) = ca.InstallToUserTrustStore();
    return Results.Ok(new { ok, message });
});

api.MapGet("/export.saz", (string? ids, SessionStore store) =>
{
    var all = store.Snapshot();
    IReadOnlyList<JASniffer.Core.Models.CapturedSession> chosen = all;

    if (!string.IsNullOrWhiteSpace(ids))
    {
        var wanted = ids.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => int.TryParse(x, out var n) ? n : -1)
            .Where(n => n >= 0)
            .ToHashSet();
        chosen = all.Where(s => wanted.Contains(s.Id)).ToList();
    }

    using var buffer = new MemoryStream();
    SazExporter.Export(chosen, buffer);
    return Results.File(buffer.ToArray(), "application/octet-stream",
        $"JASniffer-{DateTime.Now:yyyyMMdd-HHmmss}.saz");
});

api.MapPost("/system-proxy", (SystemProxyRequest body, SystemProxy systemProxy) =>
{
    var ok = body.Enabled ? systemProxy.Enable(proxyPort) : systemProxy.Disable();
    return Results.Ok(new { supported = systemProxy.Supported, enabled = systemProxy.Enabled, applied = ok });
});

api.MapPost("/udp-capture", (UdpToggle body, UdpCaptureService udp) =>
{
    if (body.Enabled)
    {
        udp.Start();
    }
    else
    {
        udp.Stop();
    }

    return Results.Ok(new { supported = udp.Supported, running = udp.Running, error = udp.LastError });
});

api.MapPost("/install-windivert", async (WinDivertInstaller installer, CancellationToken ct) =>
{
    var (ok, message) = await installer.EnsureInstalledAsync(ct);
    return Results.Ok(new { ok, message, installed = installer.IsInstalled });
});

// Composer: build a request and send it upstream through JAHTTPClient (Chrome
// fingerprint, current settings); it is recorded like any captured session.
api.MapPost("/compose", async (ComposeRequest body, UpstreamRelay relay, SessionStore store, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(body.Url))
    {
        return Results.BadRequest(new { error = "URL is required." });
    }

    try
    {
        var headers = ParseHeaderBlock(body.Headers);
        byte[] payload = string.IsNullOrEmpty(body.Body) ? [] : System.Text.Encoding.UTF8.GetBytes(body.Body);
        var id = await relay.ComposeAsync(store, body.Method ?? "GET", body.Url!, headers, payload, ct);
        return Results.Ok(new { id });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// Local, interception-proof JA3 self-test: captures the engine's real ClientHello
// over loopback and reports its fingerprint for the active preset.
api.MapGet("/fingerprint-selftest", async (UpstreamRelay relay, CancellationToken ct) =>
    Results.Ok(await relay.CaptureClientHelloAsync(ct)));

app.MapHub<SessionHub>("/hub/sessions");
app.MapFallbackToFile("index.html");

// ---- startup banner + open the UI ------------------------------------------
var uiUrl = $"http://localhost:{uiPort}";
app.Lifetime.ApplicationStarted.Register(() =>
{
    var ca = app.Services.GetRequiredService<CertificateAuthority>();
    var log = app.Services.GetRequiredService<ILogger<Program>>();
    log.LogInformation("JASniffer UI    : {Url}", uiUrl);
    log.LogInformation("JASniffer proxy : 127.0.0.1:{Port}", proxyPort);
    log.LogInformation("Root CA         : {Subject}", ca.Subject);
    log.LogInformation("CA store        : {Dir} (install rootCA.cer as a trusted root, or use the UI button)", CertificateAuthority.DefaultStoreDirectory);
    BrowserLauncher.Open(uiUrl);
});

app.Run();
return;

// Serves a stored body with its real content type (so images/HTML render inline);
// nosniff keeps the browser from re-interpreting it, and ?download=1 forces a save.
static IResult ServeBody(byte[] body, string? contentType, string name, bool download)
{
    var type = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType;
    if (download)
    {
        return Results.File(body, "application/octet-stream", $"{name}.bin");
    }

    return Results.Bytes(body, type);
}

static SettingsDto Settings(SnifferSettings s) =>
    new(s.SmartRedirects, s.MaxRedirects, s.Capture, s.UpstreamProxy, s.FingerprintPreset, s.ForceHttp1);

// Parses a "Name: Value" per-line header block (as typed in the Requester) into
// ordered header entries.
static List<HeaderEntry> ParseHeaderBlock(string? block)
{
    var headers = new List<HeaderEntry>();
    if (string.IsNullOrWhiteSpace(block))
    {
        return headers;
    }

    foreach (var raw in block.Split('\n'))
    {
        var line = raw.Trim();
        var colon = line.IndexOf(':');
        if (colon <= 0)
        {
            continue;
        }

        headers.Add(new HeaderEntry(line[..colon].Trim(), line[(colon + 1)..].Trim()));
    }

    return headers;
}

internal sealed record SystemProxyRequest(bool Enabled);

internal sealed record UdpToggle(bool Enabled);

internal sealed record ComposeRequest(string? Method, string? Url, string? Headers, string? Body);
