using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.Extensions.Logging;
using JASniffer.Core;
using JASniffer.Core.Certificates;
using JASniffer.Core.Models;
using JASniffer.Core.Parsing;

namespace JASniffer.Proxy;

/// <summary>
/// Handles one accepted browser connection end-to-end: plain-HTTP proxying,
/// HTTPS interception via <c>CONNECT</c> (terminating TLS with a per-host leaf
/// cert and offering only <c>http/1.1</c> in ALPN so the browser leg stays simple),
/// and transparent raw tunneling for anything that can't be buffered.
/// </summary>
internal sealed class ProxyConnection(
    TcpClient client,
    SnifferSettings settings,
    SessionStore store,
    UpstreamRelay relay,
    CertificateAuthority ca,
    ILogger logger)
{
    private static readonly HashSet<int> MitmPorts = [443, 8443];

    private readonly string _clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "unknown";

    public async Task ProcessAsync(CancellationToken ct)
    {
        client.NoDelay = true;
        var stream = client.GetStream();
        var reader = new Http1Reader(stream);

        var head = await reader.ReadHeaderBlockAsync(ct).ConfigureAwait(false);
        if (head is null)
        {
            return;
        }

        if (head.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
        {
            await HandleConnectAsync(stream, reader, head, ct).ConfigureAwait(false);
        }
        else
        {
            await HandlePlainAsync(stream, reader, head, ct).ConfigureAwait(false);
        }
    }

    // ---- plain HTTP (browser sends absolute-form targets to the proxy) ---------

    private async Task HandlePlainAsync(Stream stream, Http1Reader reader, string firstHead, CancellationToken ct)
    {
        var head = firstHead;
        while (true)
        {
            var request = Http1Request.Parse(head, secure: false, tunnelHost: null, tunnelPort: 0);
            if (request is null)
            {
                await WireResponse.WriteStatusAsync(stream, 400, "Bad Request", "Malformed request line.", ct).ConfigureAwait(false);
                return;
            }

            if (request.IsUpgrade)
            {
                // ws:// upgrade: hand the whole conversation to a raw TCP tunnel.
                await TunnelPlainAsync(stream, reader, request, ct).ConfigureAwait(false);
                return;
            }

            request.Body = await Http1Request.ReadBodyAsync(request, reader, ct).ConfigureAwait(false);
            await ExchangeAsync(stream, request, ct).ConfigureAwait(false);

            if (request.WantsClose)
            {
                return;
            }

            var next = await reader.ReadHeaderBlockAsync(ct).ConfigureAwait(false);
            if (next is null)
            {
                return;
            }

            head = next;
        }
    }

    // ---- HTTPS via CONNECT -----------------------------------------------------

    private async Task HandleConnectAsync(Stream stream, Http1Reader reader, string head, CancellationToken ct)
    {
        var firstLine = head.Split("\r\n")[0];
        var parts = firstLine.Split(' ');
        if (parts.Length < 2)
        {
            await WireResponse.WriteStatusAsync(stream, 400, "Bad Request", null, ct).ConfigureAwait(false);
            return;
        }

        var (host, port) = SplitHostPort(parts[1]);

        await stream.WriteAsync(Encoding.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        if (!MitmPorts.Contains(port))
        {
            // Non-HTTP port (or opaque): raw tunnel, no inspection.
            await TunnelRawAsync(stream, reader, host, port, "CONNECT", ct).ConfigureAwait(false);
            return;
        }

        SslStream tls;
        try
        {
            tls = new SslStream(new PrefixedStream(reader.DrainBuffered(), stream), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = ca.GetServerCertificate(host),
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = false,
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "TLS handshake with the browser failed for {Host}", host);
            return;
        }

        await using (tls)
        {
            await PumpMitmAsync(tls, host, port, ct).ConfigureAwait(false);
        }
    }

    private async Task PumpMitmAsync(SslStream tls, string host, int port, CancellationToken ct)
    {
        var reader = new Http1Reader(tls);
        while (true)
        {
            var head = await reader.ReadHeaderBlockAsync(ct).ConfigureAwait(false);
            if (head is null)
            {
                return;
            }

            var request = Http1Request.Parse(head, secure: true, tunnelHost: host, tunnelPort: port);
            if (request is null)
            {
                await WireResponse.WriteStatusAsync(tls, 400, "Bad Request", "Malformed request line.", ct).ConfigureAwait(false);
                return;
            }

            if (request.IsUpgrade || request.IsEventStream)
            {
                // WebSocket/SSE inside TLS: re-establish TLS to the origin and pass
                // the (already-decrypted) stream straight through, uninspected.
                await TunnelTlsAsync(tls, reader, request, host, port, ct).ConfigureAwait(false);
                return;
            }

            request.Body = await Http1Request.ReadBodyAsync(request, reader, ct).ConfigureAwait(false);
            await ExchangeAsync(tls, request, ct).ConfigureAwait(false);

            if (request.WantsClose)
            {
                return;
            }
        }
    }

    // ---- shared inspected exchange --------------------------------------------

    private async Task ExchangeAsync(Stream clientStream, ProxyRequest request, CancellationToken ct)
    {
        var session = NewSession(request);
        store.Add(session);

        var result = await relay.RelayAsync(request, session, ct).ConfigureAwait(false);
        store.Update(session);

        await WireResponse.WriteAsync(clientStream, result, keepAlive: !request.WantsClose, ct).ConfigureAwait(false);
    }

    private CapturedSession NewSession(ProxyRequest request)
    {
        var body = CapBody(request.Body, out var truncated);
        return new CapturedSession
        {
            Id = store.NextId(),
            Method = request.Method,
            Scheme = request.Scheme,
            Host = request.Host,
            Port = request.Port,
            Path = request.Path,
            Query = request.Query,
            Url = request.Url,
            RequestHttpVersion = "1.1",
            RequestHeaders = request.Headers,
            RequestBody = body,
            RequestBodyTruncated = truncated,
            RequestContentType = HttpParsing.FirstHeader(request.Headers, "Content-Type"),
            ClientEndpoint = _clientEndpoint,
            FingerprintPreset = "Chrome 148",
        };
    }

    // ---- tunneling -------------------------------------------------------------

    private async Task TunnelPlainAsync(Stream clientStream, Http1Reader reader, ProxyRequest request, CancellationToken ct)
    {
        var session = NewTunnelSession(request.Method, request.Host, request.Port, request.Scheme, request.Url);
        store.Add(session);

        try
        {
            using var origin = new TcpClient { NoDelay = true };
            await origin.ConnectAsync(request.Host, request.Port, ct).ConfigureAwait(false);
            var originStream = origin.GetStream();

            await originStream.WriteAsync(request.ToRawBytes(), ct).ConfigureAwait(false);
            var buffered = reader.DrainBuffered();
            if (buffered.Length > 0)
            {
                await originStream.WriteAsync(buffered, ct).ConfigureAwait(false);
            }

            await RawTunnel.PipeAsync(clientStream, originStream, session, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            session.Error = ex.Message;
        }
        finally
        {
            session.Completed = true;
            store.Update(session);
        }
    }

    private async Task TunnelRawAsync(Stream clientStream, Http1Reader reader, string host, int port, string method, CancellationToken ct)
    {
        var url = $"{host}:{port}";
        var session = NewTunnelSession(method, host, port, "tunnel", url);
        store.Add(session);

        try
        {
            using var origin = new TcpClient { NoDelay = true };
            await origin.ConnectAsync(host, port, ct).ConfigureAwait(false);
            var originStream = origin.GetStream();

            var buffered = reader.DrainBuffered();
            if (buffered.Length > 0)
            {
                await originStream.WriteAsync(buffered, ct).ConfigureAwait(false);
            }

            await RawTunnel.PipeAsync(clientStream, originStream, session, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            session.Error = ex.Message;
        }
        finally
        {
            session.Completed = true;
            store.Update(session);
        }
    }

    private async Task TunnelTlsAsync(SslStream clientTls, Http1Reader reader, ProxyRequest request, string host, int port, CancellationToken ct)
    {
        var session = NewTunnelSession(request.Method, host, port, "https", request.Url);
        store.Add(session);

        try
        {
            using var origin = new TcpClient { NoDelay = true };
            await origin.ConnectAsync(host, port, ct).ConfigureAwait(false);

            var originTls = new SslStream(origin.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: static (_, _, _, _) => true);
            await using (originTls)
            {
                await originTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                }, ct).ConfigureAwait(false);

                await originTls.WriteAsync(request.ToRawBytes(), ct).ConfigureAwait(false);
                var buffered = reader.DrainBuffered();
                if (buffered.Length > 0)
                {
                    await originTls.WriteAsync(buffered, ct).ConfigureAwait(false);
                }

                await RawTunnel.PipeAsync(clientTls, originTls, session, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            session.Error = ex.Message;
        }
        finally
        {
            session.Completed = true;
            store.Update(session);
        }
    }

    private CapturedSession NewTunnelSession(string method, string host, int port, string scheme, string url) => new()
    {
        Id = store.NextId(),
        Method = method,
        Scheme = scheme,
        Host = host,
        Port = port,
        Path = "/",
        Url = url,
        RequestHttpVersion = "1.1",
        ClientEndpoint = _clientEndpoint,
        WasTunneled = true,
        FingerprintPreset = "—",
        ResponseHttpVersion = string.Empty,
    };

    private byte[] CapBody(byte[] body, out bool truncated)
    {
        if (body.Length <= settings.MaxBodyBytes)
        {
            truncated = false;
            return body;
        }

        truncated = true;
        return body[..settings.MaxBodyBytes];
    }

    private static (string host, int port) SplitHostPort(string authority)
    {
        if (authority.StartsWith('['))
        {
            var end = authority.IndexOf(']');
            if (end > 0)
            {
                var h = authority[1..end];
                var rest = authority[(end + 1)..];
                return rest.StartsWith(':') && int.TryParse(rest[1..], out var p6) ? (h, p6) : (h, 443);
            }
        }

        var colon = authority.LastIndexOf(':');
        if (colon > 0 && int.TryParse(authority[(colon + 1)..], out var p))
        {
            return (authority[..colon], p);
        }

        return (authority, 443);
    }
}
