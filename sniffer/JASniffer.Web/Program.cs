using System.Net;
using JASniffer.Core;
using JASniffer.Core.Certificates;
using JASniffer.Core.Export;
using JASniffer.Web;
using JASniffer.Proxy;

var builder = WebApplication.CreateBuilder(args);

// Ports (overridable via config/env: JASniffer__UiPort / JASniffer__ProxyPort).
var uiPort = builder.Configuration.GetValue("JASniffer:UiPort", 8888);
var proxyPort = builder.Configuration.GetValue("JASniffer:ProxyPort", 8866);
var caDir = builder.Configuration.GetValue<string?>("JASniffer:CaDirectory", null);

builder.WebHost.UseUrls($"http://localhost:{uiPort}");

// ---- services --------------------------------------------------------------
var settings = new SnifferSettings();
builder.Services.AddSingleton(settings);
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddSingleton(CertificateAuthority.LoadOrCreate(caDir));
builder.Services.AddSingleton<UpstreamRelay>();
builder.Services.AddSingleton<SystemProxy>();
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

api.MapGet("/status", (CertificateAuthority ca, SystemProxy systemProxy) => new StatusDto(
    proxyPort,
    uiPort,
    ca.Subject,
    ca.Thumbprint,
    CertificateAuthority.DefaultStoreDirectory,
    System.Runtime.InteropServices.RuntimeInformation.OSDescription,
    systemProxy.Supported,
    systemProxy.Enabled));

api.MapGet("/settings", (SnifferSettings s) =>
    new SettingsDto(s.SmartRedirects, s.MaxRedirects, s.Capture, s.UpstreamProxy));

api.MapPost("/settings", (SettingsDto dto, SnifferSettings s) =>
{
    s.SmartRedirects = dto.SmartRedirects;
    s.MaxRedirects = dto.MaxRedirects;
    s.Capture = dto.Capture;
    s.UpstreamProxy = dto.UpstreamProxy;
    return new SettingsDto(s.SmartRedirects, s.MaxRedirects, s.Capture, s.UpstreamProxy);
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

api.MapPost("/clear", (SessionStore store) =>
{
    store.Clear();
    return Results.NoContent();
});

api.MapGet("/ca.cer", (CertificateAuthority ca) =>
    Results.File(ca.ExportCaCertificateDer(), "application/x-x509-ca-cert", "JASniffer-rootCA.cer"));

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

internal sealed record SystemProxyRequest(bool Enabled);
