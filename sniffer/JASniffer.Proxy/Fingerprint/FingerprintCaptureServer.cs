using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.Extensions.Logging;
using JASniffer.Core.Certificates;
using JASniffer.Core.Parsing;

namespace JASniffer.Proxy.Fingerprint;

/// <summary>
/// A small HTTPS endpoint the user points their browser at to capture its real TLS
/// fingerprint. It peeks the raw ClientHello off the socket (before handing the bytes to
/// <see cref="SslStream"/>), parses it into a <see cref="CapturedTlsFingerprint"/>, reads the
/// HTTP request for the User-Agent, stores it, and returns a small confirmation page.
/// Because the browser connects directly (not through the MITM proxy), this is the browser's
/// genuine ClientHello.
/// </summary>
public sealed class FingerprintCaptureServer(
    FingerprintStore store,
    CertificateAuthority ca,
    ILogger logger)
{
    public int Port { get; init; } = 8867;
    public IPAddress Address { get; init; } = IPAddress.Loopback;

    /// <summary>Host the capture leaf is minted for; the UI opens <c>https://{host}:{Port}/</c>.</summary>
    public string CaptureHost { get; init; } = "localhost";

    public async Task RunAsync(CancellationToken ct)
    {
        TcpListener listener;
        try
        {
            listener = new TcpListener(Address, Port);
            listener.Start();
        }
        catch (SocketException ex)
        {
            logger.LogWarning(ex, "Fingerprint capture endpoint could not bind {Host}:{Port}.", Address, Port);
            return;
        }

        logger.LogInformation("Fingerprint capture endpoint on https://{Host}:{Port}/", CaptureHost, Port);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (Exception) when (ct.IsCancellationRequested)
                {
                    break;
                }

                _ = HandleAsync(client, ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                var net = client.GetStream();

                var hello = await ReadClientHelloAsync(net, ct).ConfigureAwait(false);
                if (hello is null)
                {
                    return;
                }

                var fp = ClientHelloFingerprint.Parse(hello);

                await using var tls = new SslStream(new PrefixedStream(hello, net), leaveInnerStreamOpen: false);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = ca.GetServerCertificate(CaptureHost),
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                }, ct).ConfigureAwait(false);

                var reader = new Http1Reader(tls);
                var head = await reader.ReadHeaderBlockAsync(ct).ConfigureAwait(false);
                var (userAgent, path) = ParseRequest(head);

                CapturedFingerprint? saved = null;
                if (fp.Ok && !path.StartsWith("/favicon", StringComparison.OrdinalIgnoreCase))
                {
                    saved = store.Add(fp, userAgent);
                    logger.LogInformation("Captured fingerprint {Label}: JA3 {Md5}", saved.Label, saved.Ja3Md5);
                }

                await WritePageAsync(tls, fp, saved, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Fingerprint capture connection failed.");
            }
        }
    }

    // Reads exactly the first TLS record (the ClientHello) so it can be parsed and then
    // replayed to SslStream verbatim via PrefixedStream.
    private static async Task<byte[]?> ReadClientHelloAsync(Stream s, CancellationToken ct)
    {
        var header = await ReadExactAsync(s, 5, ct).ConfigureAwait(false);
        if (header is null || header[0] != 0x16)
        {
            return null; // not a TLS handshake record
        }

        var len = (header[3] << 8) | header[4];
        if (len is <= 0 or > 0x4000)
        {
            return null;
        }

        var body = await ReadExactAsync(s, len, ct).ConfigureAwait(false);
        if (body is null)
        {
            return null;
        }

        var all = new byte[5 + len];
        header.CopyTo(all.AsSpan());
        body.CopyTo(all.AsSpan(5));
        return all;
    }

    private static async Task<byte[]?> ReadExactAsync(Stream s, int count, CancellationToken ct)
    {
        var buf = new byte[count];
        var got = 0;
        while (got < count)
        {
            var n = await s.ReadAsync(buf.AsMemory(got), ct).ConfigureAwait(false);
            if (n == 0)
            {
                return null;
            }

            got += n;
        }

        return buf;
    }

    private static (string? UserAgent, string Path) ParseRequest(string? headerBlock)
    {
        if (string.IsNullOrEmpty(headerBlock))
        {
            return (null, "/");
        }

        var lines = headerBlock.Split("\r\n");
        var path = lines[0].Split(' ').ElementAtOrDefault(1) ?? "/";
        var headers = new List<JASniffer.Core.Models.HeaderEntry>();
        for (var i = 1; i < lines.Length; i++)
        {
            var c = lines[i].IndexOf(':');
            if (c > 0)
            {
                headers.Add(new JASniffer.Core.Models.HeaderEntry(lines[i][..c].Trim(), lines[i][(c + 1)..].Trim()));
            }
        }

        return (HttpParsing.FirstHeader(headers, "User-Agent"), path);
    }

    private static async Task WritePageAsync(Stream tls, CapturedTlsFingerprint fp, CapturedFingerprint? saved, CancellationToken ct)
    {
        var body = saved is not null
            ? $$"""
              <!doctype html><html lang="ru"><head><meta charset="utf-8"><title>JASniffer · отпечаток снят</title>
              <style>body{font:14px/1.5 system-ui,sans-serif;background:#0f1115;color:#e6e6e6;margin:0;padding:40px}
              .card{max-width:680px;margin:0 auto;background:#171a21;border:1px solid #262b36;border-radius:12px;padding:28px}
              h1{font-size:18px;margin:0 0 4px}.ok{color:#46d369}.k{color:#8a93a6}code{color:#7cc7ff;word-break:break-all}
              .row{margin:10px 0}</style></head><body><div class="card">
              <h1><span class="ok">✓</span> Отпечаток снят и сохранён</h1>
              <div class="k">Метка: <b>{{Esc(saved.Label)}}</b></div>
              <div class="row"><div class="k">JA3</div><code>{{Esc(saved.Ja3Md5)}}</code></div>
              <div class="row"><div class="k">JA4</div><code>{{Esc(saved.Ja4)}}</code></div>
              <div class="row"><div class="k">JA3 string</div><code>{{Esc(saved.Ja3)}}</code></div>
              <div class="row"><div class="k">User-Agent</div><code>{{Esc(saved.UserAgent ?? "—")}}</code></div>
              <p class="k">Вернитесь в JASniffer → вкладка «Отпечатки» и нажмите «Использовать». Эту вкладку можно закрыть.</p>
              </div></body></html>
              """
            : $$"""
              <!doctype html><html lang="ru"><head><meta charset="utf-8"><title>JASniffer</title>
              <style>body{font:14px/1.5 system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:40px}</style></head>
              <body><h1>Не удалось разобрать ClientHello</h1><p>{{Esc(fp.Error ?? "")}}</p></body></html>
              """;

        var bytes = Encoding.UTF8.GetBytes(body);
        var head = new StringBuilder()
            .Append("HTTP/1.1 200 OK\r\n")
            .Append("Content-Type: text/html; charset=utf-8\r\n")
            .Append("Content-Length: ").Append(bytes.Length).Append("\r\n")
            .Append("Connection: close\r\n\r\n")
            .ToString();

        await tls.WriteAsync(Encoding.Latin1.GetBytes(head), ct).ConfigureAwait(false);
        await tls.WriteAsync(bytes, ct).ConfigureAwait(false);
        await tls.FlushAsync(ct).ConfigureAwait(false);
    }

    private static string Esc(string s) => WebUtility.HtmlEncode(s);
}
