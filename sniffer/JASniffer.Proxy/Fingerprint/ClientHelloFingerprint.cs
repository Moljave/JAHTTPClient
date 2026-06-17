using System.Security.Cryptography;
using System.Text;
using JAHTTPClient.Interop;

namespace JASniffer.Proxy.Fingerprint;

/// <summary>The result of parsing a captured TLS ClientHello.</summary>
public sealed record CapturedTlsFingerprint(
    bool Ok,
    string? Error,
    string Ja3,        // standard JA3 (GREASE stripped), for display
    string Ja3Md5,
    string Ja4,        // JA4 fingerprint (display)
    int CipherCount,
    int ExtensionCount,
    bool Tls13,
    CustomTlsClient? Custom);  // the engine spec that reproduces this ClientHello

/// <summary>
/// Parses a raw TLS ClientHello into both a display fingerprint (JA3 / JA4) and a
/// fully-populated <see cref="CustomTlsClient"/> that the engine can replay verbatim:
/// the JA3 string keeps GREASE placeholders at their captured positions (so the
/// library re-emits GREASE), and the extension contents (supported versions, key-share
/// curves, signature algorithms, ALPN, cert-compression) are mapped to the exact
/// vocabulary bogdanfinn/tls-client accepts. Defensive: malformed input yields
/// <see cref="CapturedTlsFingerprint.Ok"/> = false rather than throwing.
/// </summary>
public static class ClientHelloFingerprint
{
    // bogdanfinn/tls-client accepted vocabulary (see its mapper.go). IDs not present
    // here are still kept in the JA3 string (so the structure/order matches) but are
    // not emitted as typed extension contents.
    private static readonly Dictionary<int, string> Versions = new()
    {
        [0x0304] = "1.3", [0x0303] = "1.2", [0x0302] = "1.1", [0x0301] = "1.0",
    };

    private static readonly Dictionary<int, string> Curves = new()
    {
        [23] = "P256", [24] = "P384", [25] = "P521", [29] = "X25519",
        [0x11EC] = "X25519MLKEM768", [0x6399] = "X25519Kyber768Old", [0x639A] = "X25519Kyber768",
        [0x2F39] = "X25519Kyber512D", [0x2F3A] = "P256Kyber768",
    };

    private static readonly Dictionary<int, string> SigAlgs = new()
    {
        [0x0401] = "PKCS1WithSHA256", [0x0501] = "PKCS1WithSHA384", [0x0601] = "PKCS1WithSHA512",
        [0x0804] = "PSSWithSHA256", [0x0805] = "PSSWithSHA384", [0x0806] = "PSSWithSHA512",
        [0x0403] = "ECDSAWithP256AndSHA256", [0x0503] = "ECDSAWithP384AndSHA384", [0x0603] = "ECDSAWithP521AndSHA512",
        [0x0201] = "PKCS1WithSHA1", [0x0203] = "ECDSAWithSHA1", [0x0807] = "Ed25519",
        [0x0301] = "SHA224_RSA", [0x0303] = "SHA224_ECDSA",
    };

    private static readonly Dictionary<int, string> CertCompression = new()
    {
        [1] = "zlib", [2] = "brotli", [3] = "zstd",
    };

    // bogdanfinn's GREASE placeholder token used inside a custom JA3 string.
    private const int GreasePlaceholder = 0x0A0A;

    /// <summary>GREASE values per RFC 8701: 0x?a?a with both bytes equal.</summary>
    private static bool IsGrease(int v) => (v & 0x0f0f) == 0x0a0a && ((v >> 8) & 0xff) == (v & 0xff);

    public static CapturedTlsFingerprint Parse(ReadOnlySpan<byte> p)
    {
        try
        {
            return ParseCore(p);
        }
        catch (Exception ex)
        {
            return new CapturedTlsFingerprint(false, "Не удалось разобрать ClientHello: " + ex.Message, "", "", "", 0, 0, false, null);
        }
    }

    private static CapturedTlsFingerprint ParseCore(ReadOnlySpan<byte> p)
    {
        if (p.Length < 50 || p[0] != 0x16)
        {
            return new CapturedTlsFingerprint(false, "Не похоже на TLS ClientHello.", "", "", "", 0, 0, false, null);
        }

        var i = 5 + 4;                              // TLS record header + handshake header
        var version = (p[i] << 8) | p[i + 1];
        i += 2 + 32;                                // legacy_version + random
        i += 1 + p[i];                              // session id

        var cipherLen = (p[i] << 8) | p[i + 1]; i += 2;
        var ciphersDisplay = new List<int>();       // GREASE stripped (JA3/JA4)
        var ciphersRepro = new List<int>();         // GREASE kept as placeholder (engine)
        for (var end = i + cipherLen; i < end; i += 2)
        {
            var c = (p[i] << 8) | p[i + 1];
            if (IsGrease(c)) { ciphersRepro.Add(GreasePlaceholder); continue; }
            ciphersDisplay.Add(c);
            ciphersRepro.Add(c);
        }

        i += 1 + p[i];                              // compression methods
        var extTotal = (p[i] << 8) | p[i + 1]; i += 2;

        var extsDisplay = new List<int>();
        var extsRepro = new List<int>();
        var curvesDisplay = new List<int>();
        var curvesRepro = new List<int>();
        var points = new List<int>();
        var versions = new List<string>();
        var keyShares = new List<string>();
        var sigAlgs = new List<string>();
        var alpn = new List<string>();
        string? certCompression = null;
        var tls13 = false;
        string? firstAlpn = null;
        var sniPresent = false;

        for (var end = i + extTotal; i + 4 <= end;)
        {
            var t = (p[i] << 8) | p[i + 1];
            var l = (p[i + 2] << 8) | p[i + 3];
            i += 4;
            var body = p.Slice(i, l);

            if (IsGrease(t))
            {
                extsRepro.Add(GreasePlaceholder);
            }
            else
            {
                extsDisplay.Add(t);
                extsRepro.Add(t);
            }

            switch (t)
            {
                case 0x0000: sniPresent = true; break;
                case 0x002b: // supported_versions
                    for (var k = 1; k + 1 < body.Length; k += 2)
                    {
                        var v = (body[k] << 8) | body[k + 1];
                        if (v == 0x0304) tls13 = true;
                        versions.Add(IsGrease(v) ? "GREASE" : (Versions.TryGetValue(v, out var vn) ? vn : v.ToString()));
                    }
                    break;
                case 0x000a: // supported_groups
                    var gl = (body[0] << 8) | body[1];
                    for (var k = 2; k + 1 < 2 + gl && k + 1 < body.Length; k += 2)
                    {
                        var g = (body[k] << 8) | body[k + 1];
                        if (IsGrease(g)) { curvesRepro.Add(GreasePlaceholder); continue; }
                        curvesDisplay.Add(g);
                        curvesRepro.Add(g);
                    }
                    break;
                case 0x0033: // key_share
                    var ksl = (body[0] << 8) | body[1];
                    for (var k = 2; k + 3 < 2 + ksl && k + 3 < body.Length;)
                    {
                        var group = (body[k] << 8) | body[k + 1];
                        var keyLen = (body[k + 2] << 8) | body[k + 3];
                        if (!IsGrease(group))
                        {
                            keyShares.Add(Curves.TryGetValue(group, out var cn) ? cn : group.ToString());
                        }
                        else
                        {
                            keyShares.Add("GREASE");
                        }

                        k += 4 + keyLen;
                    }
                    break;
                case 0x000d: // signature_algorithms
                    var sl = (body[0] << 8) | body[1];
                    for (var k = 2; k + 1 < 2 + sl && k + 1 < body.Length; k += 2)
                    {
                        var s = (body[k] << 8) | body[k + 1];
                        if (SigAlgs.TryGetValue(s, out var sn)) sigAlgs.Add(sn);
                    }
                    break;
                case 0x0010: // ALPN
                    var apl = (body[0] << 8) | body[1];
                    for (var k = 2; k < 2 + apl && k < body.Length;)
                    {
                        var len = body[k]; k++;
                        if (k + len > body.Length) break;
                        var proto = Encoding.ASCII.GetString(body.Slice(k, len));
                        alpn.Add(proto);
                        firstAlpn ??= proto;
                        k += len;
                    }
                    break;
                case 0x000b: // ec_point_formats
                    var pl = body[0];
                    for (var k = 1; k < 1 + pl && k < body.Length; k++) points.Add(body[k]);
                    break;
                case 0x001b: // compress_certificate
                    var cl = body[0];
                    if (cl >= 2)
                    {
                        var algo = (body[1] << 8) | body[2];
                        if (CertCompression.TryGetValue(algo, out var an)) certCompression = an;
                    }
                    break;
            }

            i += l;
        }

        var ja3Display = $"{version},{Join(ciphersDisplay)},{Join(extsDisplay)},{Join(curvesDisplay)},{Join(points)}";
        var ja3Repro = $"{version},{Join(ciphersRepro)},{Join(extsRepro)},{Join(curvesRepro)},{Join(points)}";
        var md5 = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3Display))).ToLowerInvariant();
        var ja4 = ComputeJa4(version, tls13, sniPresent, ciphersDisplay, extsDisplay, sigAlgs, firstAlpn);

        var custom = new CustomTlsClient
        {
            Ja3String = ja3Repro,
            SupportedVersions = versions.Count > 0 ? versions : null,
            KeyShareCurves = keyShares.Count > 0 ? keyShares : null,
            SupportedSignatureAlgorithms = sigAlgs.Count > 0 ? sigAlgs : null,
            AlpnProtocols = alpn.Count > 0 ? alpn : null,
            CertCompressionAlgos = certCompression is null ? null : [certCompression],
        };

        return new CapturedTlsFingerprint(true, null, ja3Display, md5, ja4, ciphersDisplay.Count, extsDisplay.Count, tls13, custom);
    }

    // JA4_a + "_" + JA4_b + "_" + JA4_c  (TLS-over-TCP variant).
    private static string ComputeJa4(int recordVersion, bool tls13, bool sniPresent, List<int> ciphers, List<int> exts, List<string> sigAlgs, string? firstAlpn)
    {
        var ver = tls13 ? "13" : recordVersion switch { 0x0303 => "12", 0x0302 => "11", 0x0301 => "10", _ => "00" };
        var alpnMark = string.IsNullOrEmpty(firstAlpn)
            ? "00"
            : $"{firstAlpn[0]}{firstAlpn[^1]}";
        var a = $"t{ver}{(sniPresent ? 'd' : 'i')}{Math.Min(ciphers.Count, 99):00}{Math.Min(exts.Count, 99):00}{alpnMark}";

        var b = Sha12(string.Join(',', ciphers.OrderBy(x => x).Select(x => x.ToString("x4"))));

        // JA4_c: sorted extensions excluding SNI(0) and ALPN(16), then signature algorithms in order.
        var extsForC = exts.Where(e => e != 0x0000 && e != 0x0010).OrderBy(x => x).Select(x => x.ToString("x4"));
        var sig = sigAlgs.Count > 0 ? "_" + string.Join(',', SigAlgHex(sigAlgs)) : "";
        var c = Sha12(string.Join(',', extsForC) + sig);

        return $"{a}_{b}_{c}";
    }

    private static IEnumerable<string> SigAlgHex(List<string> names)
    {
        var rev = SigAlgs.ToDictionary(kv => kv.Value, kv => kv.Key);
        foreach (var n in names)
        {
            if (rev.TryGetValue(n, out var v)) yield return v.ToString("x4");
        }
    }

    private static string Sha12(string s)
    {
        if (s.Length == 0) return new string('0', 12);
        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(s)))[..12].ToLowerInvariant();
    }

    private static string Join(List<int> xs) => string.Join('-', xs);
}
