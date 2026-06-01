using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using JASniffer.Core;
using JASniffer.Core.Models;

namespace JASniffer.Proxy.Udp;

/// <summary>
/// Passive UDP capture via the WinDivert kernel driver (Windows only). It sniffs
/// DNS (:53) and QUIC (:443/udp) datagrams without diverting them, aggregates each
/// 4-tuple into a read-only flow session, and surfaces it in the same list as HTTP
/// traffic. UDP is never relayed or re-fingerprinted — the upstream engine is
/// TCP/TLS only — this is visibility, not interception.
/// </summary>
/// <remarks>
/// Requires WinDivert (WinDivert.dll + WinDivert64.sys) next to the app and
/// Administrator rights. If any of that is missing, <see cref="Start"/> fails
/// gracefully with <see cref="LastError"/> set and the rest of the sniffer keeps
/// working.
/// </remarks>
public sealed partial class UdpCaptureService(
    SessionStore store,
    SnifferSettings settings,
    ILogger<UdpCaptureService> logger) : IDisposable
{
    // DNS + QUIC only, both directions, so the flow list stays meaningful.
    private const string Filter =
        "udp and (udp.DstPort == 53 or udp.SrcPort == 53 or udp.DstPort == 443 or udp.SrcPort == 443)";

    private const int LayerNetwork = 0;
    private const ulong FlagSniff = 0x0001;
    private const ulong FlagRecvOnly = 0x0008;
    private static readonly nint InvalidHandle = -1;

    private readonly ConcurrentDictionary<string, int> _flows = new();
    private readonly Lock _gate = new();

    private nint _handle;
    private Thread? _worker;
    private volatile bool _running;

    /// <summary>UDP capture is only available on Windows (WinDivert).</summary>
    public bool Supported => OperatingSystem.IsWindows();

    /// <summary>Whether the capture loop is currently running.</summary>
    public bool Running => _running;

    /// <summary>Why the last <see cref="Start"/> attempt failed, if any.</summary>
    public string? LastError { get; private set; }

    /// <summary>Opens WinDivert in sniff mode and starts the receive loop. Idempotent.</summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_running)
            {
                return true;
            }

            if (!OperatingSystem.IsWindows())
            {
                LastError = "UDP capture (WinDivert) is only available on Windows.";
                return false;
            }

            try
            {
                _handle = WinDivertOpen(Filter, LayerNetwork, 0, FlagSniff | FlagRecvOnly);
            }
            catch (DllNotFoundException)
            {
                LastError = "WinDivert.dll was not found next to the app. Download WinDivert and place WinDivert.dll + WinDivert64.sys beside JASniffer.Web.";
                logger.LogWarning("{Error}", LastError);
                return false;
            }
            catch (Exception ex)
            {
                LastError = $"WinDivert load failed: {ex.Message}";
                logger.LogWarning(ex, "WinDivert load failed.");
                return false;
            }

            if (_handle == InvalidHandle || _handle == 0)
            {
                var code = Marshal.GetLastPInvokeError();
                LastError = code == 5
                    ? "Access denied — run JASniffer as Administrator to capture UDP."
                    : $"WinDivertOpen failed (Win32 error {code}). Requires admin + WinDivert driver.";
                logger.LogWarning("{Error}", LastError);
                _handle = 0;
                return false;
            }

            LastError = null;
            _running = true;
            _worker = new Thread(ReceiveLoop) { IsBackground = true, Name = "JASniffer-UDP" };
            _worker.Start();
            logger.LogInformation("UDP capture started (WinDivert, DNS + QUIC).");
            return true;
        }
    }

    /// <summary>Stops the receive loop and releases the WinDivert handle. Idempotent.</summary>
    public void Stop()
    {
        Thread? worker;
        lock (_gate)
        {
            if (!_running)
            {
                return;
            }

            _running = false;
            if (_handle != 0 && _handle != InvalidHandle && OperatingSystem.IsWindows())
            {
                WinDivertClose(_handle); // unblocks the pending recv
            }

            _handle = 0;
            worker = _worker;
            _worker = null;
            _flows.Clear();
        }

        worker?.Join(TimeSpan.FromSeconds(2));
        logger.LogInformation("UDP capture stopped.");
    }

    private unsafe void ReceiveLoop()
    {
        var packet = new byte[65535];
        var address = new byte[64]; // WINDIVERT_ADDRESS; we don't parse it
        fixed (byte* pPacket = packet)
        fixed (byte* pAddress = address)
        {
            while (_running)
            {
                uint recvLen = 0;
                bool ok = WinDivertRecv(_handle, pPacket, (uint)packet.Length, &recvLen, pAddress);
                if (!ok)
                {
                    if (!_running)
                    {
                        break; // closed during shutdown
                    }

                    Thread.Sleep(5); // transient error — avoid hot-spinning
                    continue;
                }

                if (recvLen > 0)
                {
                    try
                    {
                        Record(packet.AsSpan(0, (int)recvLen));
                    }
                    catch (Exception ex)
                    {
                        logger.LogDebug(ex, "Failed to parse a UDP packet.");
                    }
                }
            }
        }
    }

    private void Record(ReadOnlySpan<byte> p)
    {
        if (!TryParse(p, out var src, out var srcPort, out var dst, out var dstPort, out var payloadStart, out var payloadLen))
        {
            return;
        }

        // The well-known port (53/443) identifies the server side, which fixes the
        // flow direction so client→server and server→client bytes are tallied right.
        var srcIsServer = srcPort is 53 or 443;
        var (clientIp, clientPort, serverIp, serverPort, clientToServer) = srcIsServer
            ? (dst, dstPort, src, srcPort, false)
            : (src, srcPort, dst, dstPort, true);

        var key = $"{clientIp}:{clientPort}>{serverIp}:{serverPort}";
        var session = GetOrCreateFlow(key, clientIp, clientPort, serverIp, serverPort, p.Slice(payloadStart, payloadLen));

        session.Packets++;
        if (clientToServer)
        {
            session.TunnelBytesUp += payloadLen;
        }
        else
        {
            session.TunnelBytesDown += payloadLen;
        }

        store.Update(session); // coalesced into ~100ms SignalR batches by the broadcaster
    }

    private CapturedSession GetOrCreateFlow(
        string key, string clientIp, int clientPort, string serverIp, int serverPort, ReadOnlySpan<byte> firstPayload)
    {
        if (_flows.TryGetValue(key, out var existingId) && store.Get(existingId) is { } existing)
        {
            return existing;
        }

        var scheme = serverPort == 53 ? "dns" : serverPort == 443 ? "quic" : "udp";
        var host = serverIp;
        var path = scheme == "quic" ? "/QUIC" : "/";

        if (serverPort == 53 && TryParseDnsQuestion(firstPayload) is { } name)
        {
            host = name;
            path = "/DNS " + name;
        }

        var session = new CapturedSession
        {
            Id = store.NextId(),
            Method = "UDP",
            Scheme = scheme,
            Host = host,
            Port = serverPort,
            Path = path,
            Url = $"udp://{serverIp}:{serverPort}",
            RequestHttpVersion = string.Empty,
            ResponseHttpVersion = string.Empty,
            IsUdp = true,
            Completed = true,
            FingerprintPreset = "—",
            HostIp = serverIp,
            ClientEndpoint = $"{clientIp}:{clientPort}",
            RequestContentType = "application/octet-stream",
            RequestBody = Cap(firstPayload),
        };

        store.Add(session);
        _flows[key] = session.Id;
        return session;
    }

    private byte[] Cap(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            return [];
        }

        var len = Math.Min(payload.Length, settings.MaxBodyBytes);
        return payload[..len].ToArray();
    }

    /// <summary>Parses an IPv4/IPv6 + UDP packet into endpoints and the payload range.</summary>
    private static bool TryParse(
        ReadOnlySpan<byte> p, out string src, out int srcPort, out string dst, out int dstPort,
        out int payloadStart, out int payloadLen)
    {
        src = dst = string.Empty;
        srcPort = dstPort = payloadStart = payloadLen = 0;

        if (p.Length < 1)
        {
            return false;
        }

        var version = p[0] >> 4;
        int udpStart;

        if (version == 4)
        {
            if (p.Length < 20)
            {
                return false;
            }

            var ihl = (p[0] & 0x0F) * 4;
            if (ihl < 20 || p.Length < ihl + 8 || p[9] != 17 /* UDP */)
            {
                return false;
            }

            src = new IPAddress(p.Slice(12, 4)).ToString();
            dst = new IPAddress(p.Slice(16, 4)).ToString();
            udpStart = ihl;
        }
        else if (version == 6)
        {
            // Treat the fixed header's Next Header as the protocol (skip the rare
            // extension-header case rather than misparse it).
            if (p.Length < 48 || p[6] != 17 /* UDP */)
            {
                return false;
            }

            src = new IPAddress(p.Slice(8, 16)).ToString();
            dst = new IPAddress(p.Slice(24, 16)).ToString();
            udpStart = 40;
        }
        else
        {
            return false;
        }

        var udp = p[udpStart..];
        if (udp.Length < 8)
        {
            return false;
        }

        srcPort = (udp[0] << 8) | udp[1];
        dstPort = (udp[2] << 8) | udp[3];
        var udpLen = (udp[4] << 8) | udp[5];

        payloadStart = udpStart + 8;
        payloadLen = Math.Max(0, Math.Min(udpLen - 8, p.Length - payloadStart));
        return true;
    }

    /// <summary>Extracts the first question name from a DNS message, e.g. <c>example.com</c>.</summary>
    private static string? TryParseDnsQuestion(ReadOnlySpan<byte> dns)
    {
        if (dns.Length < 13 || ((dns[4] << 8) | dns[5]) < 1)
        {
            return null;
        }

        var i = 12;
        var sb = new StringBuilder();
        while (i < dns.Length)
        {
            int len = dns[i++];
            if (len == 0)
            {
                break;
            }

            if ((len & 0xC0) != 0 || i + len > dns.Length) // compression/overrun — bail
            {
                return null;
            }

            if (sb.Length > 0)
            {
                sb.Append('.');
            }

            for (var j = 0; j < len; j++)
            {
                var b = dns[i + j];
                sb.Append(b is >= 32 and < 127 ? (char)b : '?');
            }

            i += len;
        }

        return sb.Length > 0 ? sb.ToString() : null;
    }

    public void Dispose() => Stop();

    // ---- WinDivert P/Invoke (Windows) -----------------------------------------

    [LibraryImport("WinDivert.dll", EntryPoint = "WinDivertOpen", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial nint WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [LibraryImport("WinDivert.dll", EntryPoint = "WinDivertRecv", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool WinDivertRecv(nint handle, byte* pPacket, uint packetLen, uint* pRecvLen, byte* pAddr);

    [LibraryImport("WinDivert.dll", EntryPoint = "WinDivertClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WinDivertClose(nint handle);
}
