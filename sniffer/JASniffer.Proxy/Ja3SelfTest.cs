using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;

namespace JASniffer.Proxy;

/// <summary>Result of a local ClientHello self-test.</summary>
public sealed record Ja3Report(
    string Preset,
    bool Ok,
    string? Error,
    int Bytes,
    int CipherCount,
    int ExtensionCount,
    bool Tls13,
    bool KeyShare,
    bool Grease,
    string Ja3,
    string Ja3Md5);

/// <summary>
/// Captures the engine's actual TLS ClientHello over loopback and computes its
/// JA3. This is the only way to verify the upstream fingerprint from a host whose
/// outbound TLS is intercepted by an inspecting proxy (corporate gateway, cloud
/// sandbox, …): such a proxy re-originates TLS, so external fingerprint sites only
/// ever see the proxy's ClientHello — never the engine's. Loopback is never
/// intercepted, so what we read here is exactly what the engine emits.
/// </summary>
public static class Ja3SelfTest
{
    public static async Task<Ja3Report> CaptureAsync(Ja3Preset preset, bool forceHttp1, string presetLabel, CancellationToken ct)
    {
        var hello = await CaptureRawHelloAsync(
            new ChromeHttpClientOptions
            {
                EnableJa3Fingerprinting = true,
                FingerprintPreset = preset,
                ForceHttp1 = forceHttp1,
                InsecureSkipVerify = true,
                Timeout = TimeSpan.FromSeconds(3),
                MaxRetries = 0,
            },
            ct).ConfigureAwait(false);

        if (hello.Length < 50 || hello[0] != 0x16)
        {
            return new Ja3Report(presetLabel, false, "ClientHello не получен (порт занят?)", hello.Length, 0, 0, false, false, false, string.Empty, string.Empty);
        }

        try
        {
            return Parse(presetLabel, hello);
        }
        catch (Exception ex)
        {
            return new Ja3Report(presetLabel, false, "Не удалось разобрать ClientHello: " + ex.Message, hello.Length, 0, 0, false, false, false, string.Empty, string.Empty);
        }
    }

    /// <summary>
    /// Dials loopback with a client built from <paramref name="options"/> (a preset or a
    /// custom fingerprint) and returns the raw ClientHello bytes it emits. The handshake is
    /// never completed — we only want the hello. Returns an empty array if none arrived.
    /// </summary>
    internal static async Task<byte[]> CaptureRawHelloAsync(ChromeHttpClientOptions options, CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var capture = AcceptHelloAsync(listener, ct);
        var client = new TlsClientChromeHttpClient(options);
        var send = Task.Run(() => client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"https://127.0.0.1:{port}/"), ct), ct);
        _ = send.ContinueWith(static t => { _ = t.Exception; }, TaskScheduler.Default);

        try
        {
            return await capture.ConfigureAwait(false);
        }
        finally
        {
            listener.Stop();
            client.Dispose();
        }
    }

    private static async Task<byte[]> AcceptHelloAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            using var socket = await listener.AcceptSocketAsync(ct).ConfigureAwait(false);
            var buffer = new byte[8192];
            for (var i = 0; socket.Available == 0 && i < 40; i++)
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }

            var n = socket.Available > 0 ? socket.Receive(buffer) : 0;
            return buffer[..n];
        }
        catch (Exception)
        {
            return [];
        }
    }

    // GREASE values (RFC 8701): both bytes equal and of the form 0x?A?A.
    private static bool IsGrease(int v) => (v & 0x0f0f) == 0x0a0a && ((v >> 8) & 0xff) == (v & 0xff);

    private static Ja3Report Parse(string presetLabel, byte[] p)
    {
        var i = 5 + 4;                                   // TLS record header + handshake header
        var version = (p[i] << 8) | p[i + 1];
        i += 2 + 32;                                     // client_version + random
        i += 1 + p[i];                                   // session id

        var cipherLen = (p[i] << 8) | p[i + 1]; i += 2;
        var ciphers = new List<int>();
        var greaseSeen = false;
        for (var end = i + cipherLen; i < end; i += 2)
        {
            var c = (p[i] << 8) | p[i + 1];
            if (IsGrease(c)) { greaseSeen = true; continue; }
            ciphers.Add(c);
        }

        i += 1 + p[i];                                   // compression methods
        var extTotal = (p[i] << 8) | p[i + 1]; i += 2;

        var exts = new List<int>();
        var curves = new List<int>();
        var points = new List<int>();
        bool tls13 = false, keyShare = false;
        for (var end = i + extTotal; i + 4 <= end;)
        {
            var t = (p[i] << 8) | p[i + 1];
            var l = (p[i + 2] << 8) | p[i + 3];
            i += 4;
            if (IsGrease(t)) { greaseSeen = true; }
            else { exts.Add(t); }

            switch (t)
            {
                case 0x2b: // supported_versions
                    for (var k = i + 1; k + 1 < i + l; k += 2)
                    {
                        if (((p[k] << 8) | p[k + 1]) == 0x0304) tls13 = true;
                    }
                    break;
                case 0x33: keyShare = true; break;
                case 0x0a: // supported_groups
                    var gl = (p[i] << 8) | p[i + 1];
                    for (var k = i + 2; k + 1 < i + 2 + gl; k += 2)
                    {
                        var g = (p[k] << 8) | p[k + 1];
                        if (!IsGrease(g)) curves.Add(g);
                    }
                    break;
                case 0x0b: // ec_point_formats
                    var pl = p[i];
                    for (var k = i + 1; k < i + 1 + pl; k++) points.Add(p[k]);
                    break;
            }

            i += l;
        }

        var ja3 = $"{version},{string.Join('-', ciphers)},{string.Join('-', exts)},{string.Join('-', curves)},{string.Join('-', points)}";
        var md5 = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3))).ToLowerInvariant();
        return new Ja3Report(presetLabel, true, null, p.Length, ciphers.Count, exts.Count, tls13, keyShare, greaseSeen, ja3, md5);
    }
}
