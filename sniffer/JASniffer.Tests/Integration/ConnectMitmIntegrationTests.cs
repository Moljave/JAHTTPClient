using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace JASniffer.Tests.Integration;

/// <summary>
/// End-to-end HTTPS interception: a client opens a CONNECT tunnel through the proxy,
/// completes TLS against the proxy's on-the-fly leaf certificate, and sends an HTTP
/// request which the proxy decrypts, re-issues upstream (real engine) to a TLS
/// origin, and returns. Exercises the headline MITM feature, leaf-cert minting,
/// PrefixedStream and ALPN.
/// </summary>
[Collection("integration")]
public sealed class ConnectMitmIntegrationTests
{
    [Fact]
    public async Task Connect_MitmDecryptsAndRelays_Https()
    {
        using var origin = new TlsLoopbackOrigin { Handler = target => OriginResponse.Text("secret:" + target) };
        await using var proxy = new ProxyHarness(s => s.IgnoreUpstreamCertErrors = true);
        await proxy.WaitUntilReadyAsync();

        var (status, body, leafCn) = await MitmSendAsync(proxy.Port, "127.0.0.1", origin.Port, "/secure?z=9");

        Assert.Equal(200, status);
        Assert.Equal("secret:/secure?z=9", body);
        // The proxy presented a leaf minted for the requested host.
        Assert.Contains("127.0.0.1", leafCn);

        var session = Assert.Single(proxy.Store.Snapshot());
        Assert.Equal("https", session.Scheme);
        Assert.Equal("127.0.0.1", session.Host);
        Assert.Equal(origin.Port, session.Port);
        Assert.Equal("/secure", session.Path);
        Assert.True(session.UpstreamOk);
        Assert.False(session.WasTunneled);
    }

    [Fact]
    public async Task Connect_BypassedHost_IsTunneledNotDecrypted()
    {
        using var origin = new TlsLoopbackOrigin { Handler = _ => OriginResponse.Text("direct-tls") };
        await using var proxy = new ProxyHarness(s =>
        {
            s.IgnoreUpstreamCertErrors = true;
            s.BypassHosts = "127.0.0.1"; // force a raw tunnel, no interception
        });
        await proxy.WaitUntilReadyAsync();

        // Because the host is bypassed, the proxy raw-tunnels: TLS terminates at the
        // ORIGIN, so the cert we see is the origin's own self-signed cert (CN=127.0.0.1),
        // and the session is recorded as tunneled (uninspected).
        var (status, body, _) = await MitmSendAsync(proxy.Port, "127.0.0.1", origin.Port, "/x", trustAnything: true);

        Assert.Equal(200, status);
        Assert.Equal("direct-tls", body);

        var session = Assert.Single(proxy.Store.Snapshot());
        Assert.True(session.WasTunneled);
    }

    [Fact]
    public async Task Connect_MitmForwardsRequestBody_OverHttps()
    {
        using var origin = new TlsLoopbackOrigin { Handler = _ => OriginResponse.Text("accepted") };
        await using var proxy = new ProxyHarness(s => s.IgnoreUpstreamCertErrors = true);
        await proxy.WaitUntilReadyAsync();

        var (status, body, _) = await MitmSendAsync(
            proxy.Port, "127.0.0.1", origin.Port, "/upload",
            method: "POST", body: Encoding.UTF8.GetBytes("mitm-body-payload"), contentType: "application/octet-stream");

        Assert.Equal(200, status);
        Assert.Equal("accepted", body);

        // The decrypted request body must have been re-issued upstream intact.
        Assert.True(origin.Received.TryDequeue(out var got));
        Assert.Equal("/upload", got.Target);
        Assert.Equal("mitm-body-payload", Encoding.UTF8.GetString(got.Body));

        var session = Assert.Single(proxy.Store.Snapshot());
        Assert.Equal("POST", session.Method);
        Assert.True(session.UpstreamOk);
    }

    /// <summary>
    /// Opens a CONNECT tunnel to <paramref name="host"/>:<paramref name="port"/> through the
    /// proxy, does the TLS handshake, sends a request, and returns (status, body, leaf-cert subject).
    /// </summary>
    private static async Task<(int Status, string Body, string LeafSubject)> MitmSendAsync(
        int proxyPort, string host, int port, string path,
        string method = "GET", byte[]? body = null, string? contentType = null, bool trustAnything = true)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxyPort);
        var net = client.GetStream();

        // CONNECT handshake.
        var connect = $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n";
        await net.WriteAsync(Encoding.Latin1.GetBytes(connect));
        await net.FlushAsync();
        var established = await ReadUntilDoubleCrlfAsync(net);
        Assert.Contains("200", established);

        // TLS to the proxy (which presents a minted leaf for `host`).
        var leafSubject = string.Empty;
        await using var tls = new SslStream(net, leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, cert, _, _) =>
            {
                leafSubject = cert?.Subject ?? string.Empty;
                return trustAnything;
            });
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
        });

        var head = new StringBuilder();
        head.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
        head.Append("Host: ").Append(host).Append(':').Append(port).Append("\r\n");
        if (contentType is not null)
        {
            head.Append("Content-Type: ").Append(contentType).Append("\r\n");
        }

        if (body is { Length: > 0 })
        {
            head.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        }

        head.Append("Connection: close\r\n\r\n");
        await tls.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()));
        if (body is { Length: > 0 })
        {
            await tls.WriteAsync(body);
        }

        await tls.FlushAsync();

        var resp = RawResponse.Parse(await RawHttp.ReadToEndAsync(tls));
        return (resp.Status, resp.BodyText, leafSubject);
    }

    private static async Task<string> ReadUntilDoubleCrlfAsync(Stream s)
    {
        using var ms = new MemoryStream();
        var one = new byte[1];
        while (true)
        {
            var n = await s.ReadAsync(one);
            if (n == 0)
            {
                break;
            }

            ms.WriteByte(one[0]);
            var text = Encoding.Latin1.GetString(ms.ToArray());
            if (text.EndsWith("\r\n\r\n", StringComparison.Ordinal))
            {
                return text;
            }
        }

        return Encoding.Latin1.GetString(ms.ToArray());
    }
}
