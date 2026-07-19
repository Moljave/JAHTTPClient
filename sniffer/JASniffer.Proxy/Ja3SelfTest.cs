using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;

namespace JASniffer.Proxy;

/// <summary>Result of a local ClientHello self-test — the actual TLS fingerprint the engine emits.</summary>
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
    string Ja3Md5,
    // Deeper detail (populated on success) for the full-scan endpoint / request Info tab.
    string Ja4 = "",
    string? TlsVersion = null,
    bool Sni = false,
    bool ForceHttp1 = false,
    int[]? Ciphers = null,
    int[]? Extensions = null,
    int[]? Curves = null,
    int[]? PointFormats = null,
    int[]? SupportedVersions = null,
    int[]? SignatureAlgorithms = null,
    string[]? Alpn = null);

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
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var capture = AcceptHelloAsync(listener, ct);
        var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
        {
            EnableJa3Fingerprinting = true,
            FingerprintPreset = preset,
            ForceHttp1 = forceHttp1,
            InsecureSkipVerify = true,
            Timeout = TimeSpan.FromSeconds(3),
            MaxRetries = 0,
        });

        // Fire the request: the engine dials loopback and sends its ClientHello,
        // which we read. The handshake never completes (we don't reply), so the
        // request fails — that's fine, we only wanted the ClientHello.
        var send = Task.Run(() => client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"https://127.0.0.1:{port}/"), ct), ct);
        _ = send.ContinueWith(static t => { _ = t.Exception; }, TaskScheduler.Default);

        byte[] hello;
        try
        {
            hello = await capture.ConfigureAwait(false);
        }
        finally
        {
            listener.Stop();
            client.Dispose();
        }

        if (hello.Length < 50 || hello[0] != 0x16)
        {
            return new Ja3Report(presetLabel, false, "ClientHello не получен (порт занят?)", hello.Length, 0, 0, false, false, false, string.Empty, string.Empty);
        }

        try
        {
            return Parse(presetLabel, hello) with { ForceHttp1 = forceHttp1 };
        }
        catch (Exception ex)
        {
            return new Ja3Report(presetLabel, false, "Не удалось разобрать ClientHello: " + ex.Message, hello.Length, 0, 0, false, false, false, string.Empty, string.Empty);
        }
    }

    private static async Task<byte[]> AcceptHelloAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            using var socket = await listener.AcceptSocketAsync(ct).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));

            // Read the *whole* first TLS record, not just the first segment. The 5-byte
            // record header carries its length; a modern ClientHello (X25519MLKEM768 /
            // ECH) is ~1.5–2 KB and spans several TCP segments, so a single receive
            // truncates it and the parser never reaches the trailing extensions
            // (key_share, supported_versions) — which is exactly what made the self-test
            // report TLS1.3/key_share as absent and "fail".
            var buffer = new byte[18 * 1024]; // a TLS record maxes at 16 KB + header
            var total = 0;
            var need = 5;
            while (total < need)
            {
                int n;
                try
                {
                    n = await socket.ReceiveAsync(buffer.AsMemory(total), timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (n == 0)
                {
                    break; // peer closed
                }

                total += n;
                if (total >= 5)
                {
                    var recordLen = (buffer[3] << 8) | buffer[4];
                    need = Math.Min(5 + recordLen, buffer.Length);
                }
            }

            return buffer[..total];
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
        var supportedVersions = new List<int>();
        var sigAlgs = new List<int>();
        var alpn = new List<string>();
        bool tls13 = false, keyShare = false, sni = false;
        for (var end = i + extTotal; i + 4 <= end;)
        {
            var t = (p[i] << 8) | p[i + 1];
            var l = (p[i + 2] << 8) | p[i + 3];
            i += 4;
            if (IsGrease(t)) { greaseSeen = true; }
            else { exts.Add(t); }

            switch (t)
            {
                case 0x00: sni = true; break;            // server_name
                case 0x2b: // supported_versions
                    for (var k = i + 1; k + 1 < i + l; k += 2)
                    {
                        var vv = (p[k] << 8) | p[k + 1];
                        if (IsGrease(vv)) continue;
                        supportedVersions.Add(vv);
                        if (vv == 0x0304) tls13 = true;
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
                case 0x0d: // signature_algorithms
                    var sal = (p[i] << 8) | p[i + 1];
                    for (var k = i + 2; k + 1 < i + 2 + sal && k + 1 < i + l; k += 2)
                    {
                        sigAlgs.Add((p[k] << 8) | p[k + 1]);
                    }
                    break;
                case 0x10: // application_layer_protocol_negotiation (ALPN)
                    var listLen = (p[i] << 8) | p[i + 1];
                    var ap = i + 2;
                    var apEnd = Math.Min(i + 2 + listLen, i + l);
                    while (ap < apEnd)
                    {
                        int plen = p[ap++];
                        if (plen <= 0 || ap + plen > apEnd) break;
                        alpn.Add(Encoding.ASCII.GetString(p, ap, plen));
                        ap += plen;
                    }
                    break;
            }

            i += l;
        }

        var ja3 = $"{version},{string.Join('-', ciphers)},{string.Join('-', exts)},{string.Join('-', curves)},{string.Join('-', points)}";
        var md5 = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3))).ToLowerInvariant();
        var maxVer = supportedVersions.Count > 0 ? supportedVersions.Max() : version;
        var ja4 = ComputeJa4(maxVer, sni, ciphers, exts, alpn, sigAlgs);

        return new Ja3Report(
            presetLabel, true, null, p.Length, ciphers.Count, exts.Count, tls13, keyShare, greaseSeen, ja3, md5,
            Ja4: ja4, TlsVersion: VersionName(maxVer), Sni: sni,
            Ciphers: ciphers.ToArray(), Extensions: exts.ToArray(), Curves: curves.ToArray(),
            PointFormats: points.ToArray(), SupportedVersions: supportedVersions.ToArray(),
            SignatureAlgorithms: sigAlgs.ToArray(), Alpn: alpn.ToArray());
    }

    private static string VersionName(int v) => v switch
    {
        0x0304 => "TLS 1.3", 0x0303 => "TLS 1.2", 0x0302 => "TLS 1.1", 0x0301 => "TLS 1.0", _ => $"0x{v:x4}",
    };

    // JA4 TLS client fingerprint (FoxIO spec): ja4_a_ja4_b_ja4_c.
    //  a = t + tlsver + (d|i for SNI) + cipherCount(2) + extCount(2) + first/last char of first ALPN
    //  b = sha256(sorted cipher hex list)[:12]
    //  c = sha256(sorted ext hex list, excl. SNI(0000)+ALPN(0010), + "_" + sig-alg hex list in order)[:12]
    private static string ComputeJa4(int maxVer, bool sni, List<int> ciphers, List<int> exts, List<string> alpn, List<int> sigAlgs)
    {
        var ver = maxVer switch { 0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10", _ => "00" };
        var cc = Math.Min(ciphers.Count, 99).ToString("D2");
        var ec = Math.Min(exts.Count, 99).ToString("D2");
        string alpnPair = "00";
        if (alpn.Count > 0 && alpn[0].Length > 0)
        {
            var a = alpn[0];
            alpnPair = $"{a[0]}{a[^1]}";
        }

        var a1 = $"t{ver}{(sni ? "d" : "i")}{cc}{ec}{alpnPair}";

        var cipherHex = ciphers.Select(c => c.ToString("x4")).OrderBy(h => h, StringComparer.Ordinal);
        var b = ciphers.Count == 0 ? "000000000000" : Sha12(string.Join(',', cipherHex));

        var extHex = exts.Where(e => e is not (0x0000 or 0x0010)).Select(e => e.ToString("x4")).OrderBy(h => h, StringComparer.Ordinal);
        var sigHex = sigAlgs.Select(s => s.ToString("x4"));
        var c = Sha12(string.Join(',', extHex) + "_" + string.Join(',', sigHex));

        return $"{a1}_{b}_{c}";
    }

    private static string Sha12(string s)
        => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(s)))[..12].ToLowerInvariant();
}
