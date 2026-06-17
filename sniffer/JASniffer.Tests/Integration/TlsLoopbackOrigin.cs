using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace JASniffer.Tests.Integration;

/// <summary>
/// A loopback HTTPS origin presenting a self-signed certificate (SAN 127.0.0.1).
/// The proxy's upstream leg reaches it with cert verification disabled
/// (<c>IgnoreUpstreamCertErrors</c>). Speaks one HTTP/1.1 request/response per
/// connection over TLS.
/// </summary>
internal sealed class TlsLoopbackOrigin : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly X509Certificate2 _cert;

    public int Port { get; }
    public string BaseUrl => $"https://127.0.0.1:{Port}";
    public Func<string, OriginResponse> Handler { get; set; } = _ => OriginResponse.Text("tls-ok");

    /// <summary>Decrypted requests the origin received (target + body) — what the proxy forwarded.</summary>
    public ConcurrentQueue<(string Target, byte[] Body)> Received { get; } = new();

    public TlsLoopbackOrigin()
    {
        _cert = CreateSelfSigned();
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        try
        {
            using (client)
            await using (var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false))
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _cert,
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                }, _cts.Token).ConfigureAwait(false);

                // Minimal HTTP/1.1 request read: headers, then body by Content-Length.
                var (head, leftover) = await ReadHeadAsync(tls).ConfigureAwait(false);
                if (head is null)
                {
                    return;
                }

                var lines = head.Split("\r\n");
                var target = lines[0].Split(' ').ElementAtOrDefault(1) ?? "/";

                // Read the full request body (Content-Length) before replying — otherwise
                // responding early can race the proxy's in-flight body write into an RST.
                // Capturing it also lets tests assert the proxy forwarded the body.
                var requestBody = await ReadBodyAsync(tls, lines, leftover).ConfigureAwait(false);
                Received.Enqueue((target, requestBody));

                var response = Handler(target);
                var sb = new StringBuilder();
                sb.Append("HTTP/1.1 ").Append(response.Status).Append(' ').Append(response.Reason).Append("\r\n");
                if (response.ContentType is not null)
                {
                    sb.Append("Content-Type: ").Append(response.ContentType).Append("\r\n");
                }

                foreach (var (n, v) in response.Headers)
                {
                    sb.Append(n).Append(": ").Append(v).Append("\r\n");
                }

                sb.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
                sb.Append("Connection: close\r\n\r\n");

                await tls.WriteAsync(Encoding.Latin1.GetBytes(sb.ToString())).ConfigureAwait(false);
                await tls.WriteAsync(response.Body).ConfigureAwait(false);
                await tls.FlushAsync().ConfigureAwait(false);
            }
        }
        catch
        {
            // torn connection — ignore
        }
    }

    private static async Task<byte[]> ReadBodyAsync(Stream s, string[] headerLines, byte[] leftover)
    {
        var length = 0;
        foreach (var line in headerLines)
        {
            var c = line.IndexOf(':');
            if (c > 0 && line[..c].Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(line[(c + 1)..].Trim(), out var n))
            {
                length = n;
                break;
            }
        }

        if (length <= 0)
        {
            return [];
        }

        using var ms = new MemoryStream(length);
        ms.Write(leftover, 0, Math.Min(leftover.Length, length));
        var buf = new byte[8192];
        while (ms.Length < length)
        {
            var want = Math.Min(buf.Length, length - (int)ms.Length);
            var read = await s.ReadAsync(buf.AsMemory(0, want)).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            ms.Write(buf, 0, read);
        }

        return ms.ToArray();
    }

    private static async Task<(string? Head, byte[] Leftover)> ReadHeadAsync(Stream s)
    {
        var buf = new byte[8192];
        using var ms = new MemoryStream();
        while (true)
        {
            var n = await s.ReadAsync(buf).ConfigureAwait(false);
            if (n == 0)
            {
                return (null, []);
            }

            ms.Write(buf, 0, n);
            var text = Encoding.Latin1.GetString(ms.ToArray());
            var idx = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (idx >= 0)
            {
                return (text[..idx], Encoding.Latin1.GetBytes(text[(idx + 4)..]));
            }
        }
    }

    private static X509Certificate2 CreateSelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var made = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Round-trip through PKCS#12 so the private key is usable as a server credential.
        return X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* ignore */ }
        _cert.Dispose();
    }
}
