using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
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

            if (request.IsUpgrade || request.IsEventStream)
            {
                // ws:// upgrade or text/event-stream (SSE): both are long-lived/streaming
                // and can't be buffered, so hand the whole conversation to a raw TCP tunnel
                // (mirrors the HTTPS path in PumpMitmAsync).
                await TunnelPlainAsync(stream, reader, request, ct).ConfigureAwait(false);
                return;
            }

            // A request addressed to the proxy's OWN loopback port (e.g. navigating to
            // http://127.0.0.1:8866/api/fingerprint-scan) is answered by the proxy itself
            // rather than relayed back to itself.
            if (IsProxySelfDiag(request))
            {
                await ServeSelfDiagAsync(stream, request, ct).ConfigureAwait(false);
                return;
            }

            if (request.ExpectsContinue)
            {
                await WireResponse.WriteContinueAsync(stream, ct).ConfigureAwait(false);
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

        // CONNECT to the proxy's own loopback port: read the inner request on the
        // plain (non-TLS) stream and self-serve diagnostics without a TLS handshake.
        if (IsLoopbackHost(host) && port == settings.ProxyPort && settings.ProxyPort != 0)
        {
            await ServeSelfDiagFromTunnelAsync(stream, ct).ConfigureAwait(false);
            return;
        }

        if (settings.IsBypassed(host) || (!MitmPorts.Contains(port) && !settings.InterceptAllPorts))
        {
            // Pass-through (bypass list, or a non-HTTP port with all-port interception off):
            // raw tunnel, no inspection — but still recorded so the host stays visible.
            await TunnelRawAsync(stream, reader, host, port, "CONNECT", ct).ConfigureAwait(false);
            return;
        }

        var tls = new SslStream(new PrefixedStream(reader.DrainBuffered(), stream), leaveInnerStreamOpen: false);
        try
        {
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
            // The browser aborted the TLS handshake (often because it raced to HTTP/3,
            // or pins this host). Dispose the half-open stream, record it so the host is
            // visible, then drop the conn.
            await tls.DisposeAsync().ConfigureAwait(false);
            logger.LogDebug(ex, "TLS handshake with the browser failed for {Host}", host);
            RecordConnectFailure(host, port, ex.InnerException?.Message ?? ex.Message);
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
        try
        {
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

                if (IsProxySelfDiag(request))
                {
                    await ServeSelfDiagAsync(tls, request, ct).ConfigureAwait(false);
                    return;
                }

                if (request.ExpectsContinue)
                {
                    await WireResponse.WriteContinueAsync(tls, ct).ConfigureAwait(false);
                }

                request.Body = await Http1Request.ReadBodyAsync(request, reader, ct).ConfigureAwait(false);
                await ExchangeAsync(tls, request, ct).ConfigureAwait(false);

                if (request.WantsClose)
                {
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // The browser reset/closed the tunnel mid-stream — a normal end of
            // connection for a proxy; handled here so it doesn't surface as unhandled.
        }
    }

    // ---- shared inspected exchange --------------------------------------------

    private async Task ExchangeAsync(Stream clientStream, ProxyRequest request, CancellationToken ct)
    {
        // Relay (so the UI keeps working) but don't record the tool's own traffic.
        var capture = !IsSelfUi(request.Host, request.Port);
        var session = NewSession(request);
        if (capture)
        {
            store.Add(session);
        }

        var result = await relay.RelayAsync(request, session, ct).ConfigureAwait(false);
        if (capture)
        {
            store.Update(session);
        }

        await WireResponse.WriteAsync(clientStream, result, keepAlive: !request.WantsClose, ct).ConfigureAwait(false);
    }

    /// <summary>True for loopback traffic to the sniffer's own UI port — proxied, never recorded.</summary>
    private bool IsSelfUi(string host, int port)
        => settings.SelfUiPort != 0 && port == settings.SelfUiPort && IsLoopbackHost(host);

    private static bool IsLoopbackHost(string host)
        => host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
           || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));

    private static readonly JsonSerializerOptions SelfDiagJson =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>
    /// True for a GET addressed to the proxy's OWN loopback port on a self-served diagnostic
    /// path — so <c>http://127.0.0.1:{ProxyPort}/api/fingerprint-scan</c> (or
    /// <c>/api/fingerprint-selftest</c>) is answered locally instead of relayed to itself.
    /// </summary>
    private bool IsProxySelfDiag(ProxyRequest request)
    {
        if (settings.ProxyPort == 0 || request.Port != settings.ProxyPort)
        {
            return false;
        }

        if (!request.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) || !IsLoopbackHost(request.Host))
        {
            return false;
        }

        return IsSelfDiagPath(request.Path);
    }

    /// <summary>
    /// Runs the requested fingerprint diagnostic in-engine and writes it back as JSON, so the
    /// scan/self-test is reachable straight from the proxy port without opening the UI.
    /// </summary>
    private async Task ServeSelfDiagAsync(Stream stream, ProxyRequest request, CancellationToken ct)
    {
        try
        {
            object payload;
            if (request.Path.StartsWith("/api/fingerprint-selftest", StringComparison.OrdinalIgnoreCase))
            {
                payload = await relay.CaptureClientHelloAsync(ct).ConfigureAwait(false);
            }
            else
            {
                payload = await relay.CaptureAllFingerprintsAsync(ct).ConfigureAwait(false);
            }

            var body = JsonSerializer.SerializeToUtf8Bytes(payload, SelfDiagJson);
            await WireResponse.WriteInlineAsync(stream, 200, "OK", "application/json; charset=utf-8", body, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Self-served fingerprint diagnostic failed for {Path}.", request.Path);
            var body = Encoding.UTF8.GetBytes($"{{\"ok\":false,\"error\":{JsonSerializer.Serialize(ex.Message)}}}");
            await WireResponse.WriteInlineAsync(stream, 500, "Internal Server Error", "application/json; charset=utf-8", body, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Handles a CONNECT tunnel to the proxy's own port: reads the first inner HTTP
    /// request on the raw (non-TLS) stream and serves diagnostics if it matches, or
    /// returns 404. This avoids a pointless TLS handshake for self-targeted CONNECT.
    /// </summary>
    private async Task ServeSelfDiagFromTunnelAsync(Stream stream, CancellationToken ct)
    {
        var reader = new Http1Reader(stream);
        var head = await reader.ReadHeaderBlockAsync(ct).ConfigureAwait(false);
        if (head is null)
        {
            return;
        }

        // We already know from the CONNECT target that this is the proxy's own port,
        // so parse with the known authority to avoid port-mismatch when the inner Host
        // header omits the port (origin-form defaults to 80).
        var request = Http1Request.Parse(head, secure: false,
            tunnelHost: "127.0.0.1", tunnelPort: settings.ProxyPort);
        if (request is null)
        {
            await WireResponse.WriteStatusAsync(stream, 400, "Bad Request", null, ct).ConfigureAwait(false);
            return;
        }

        if (IsSelfDiagPath(request.Path) && request.Method.Equals("GET", StringComparison.OrdinalIgnoreCase))
        {
            await ServeSelfDiagAsync(stream, request, ct).ConfigureAwait(false);
        }
        else
        {
            await WireResponse.WriteStatusAsync(stream, 404, "Not Found", "This proxy port only self-serves /api/fingerprint-scan and /api/fingerprint-selftest.", ct).ConfigureAwait(false);
        }
    }

    private static bool IsSelfDiagPath(string path)
        => path.StartsWith("/api/fingerprint-scan", StringComparison.OrdinalIgnoreCase)
           || path.StartsWith("/api/fingerprint-selftest", StringComparison.OrdinalIgnoreCase);

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
            FingerprintPreset = relay.CurrentPresetLabel,
        };
    }

    // ---- tunneling -------------------------------------------------------------

    private async Task TunnelPlainAsync(Stream clientStream, Http1Reader reader, ProxyRequest request, CancellationToken ct)
    {
        var capture = !IsSelfUi(request.Host, request.Port);
        var session = NewTunnelSession(request.Method, request.Host, request.Port, request.Scheme, request.Url);
        if (capture)
        {
            store.Add(session);
        }

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
            if (capture)
            {
                store.Update(session);
            }
        }
    }

    private async Task TunnelRawAsync(Stream clientStream, Http1Reader reader, string host, int port, string method, CancellationToken ct)
    {
        var url = $"{host}:{port}";
        var capture = !IsSelfUi(host, port);
        var session = NewTunnelSession(method, host, port, "tunnel", url);
        if (capture)
        {
            store.Add(session);
        }

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
            if (capture)
            {
                store.Update(session);
            }
        }
    }

    private async Task TunnelTlsAsync(SslStream clientTls, Http1Reader reader, ProxyRequest request, string host, int port, CancellationToken ct)
    {
        var capture = !IsSelfUi(host, port);
        var session = NewTunnelSession(request.Method, host, port, "https", request.Url);
        if (capture)
        {
            store.Add(session);
        }

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
            if (capture)
            {
                store.Update(session);
            }
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

    // Records a CONNECT whose TLS interception failed, so a problematic host (pinned,
    // or one the browser dropped to use HTTP/3) is still visible in the list.
    private void RecordConnectFailure(string host, int port, string reason)
    {
        if (IsSelfUi(host, port))
        {
            return;
        }

        var session = NewTunnelSession("CONNECT", host, port, "tunnel", $"{host}:{port}");
        session.Error = reason;
        session.Completed = true;
        store.Add(session);
        store.Update(session);
    }

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
