using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JASniffer.Core.Certificates;

/// <summary>
/// The MITM trust root. On first run it generates a self-signed ECDSA P-256 root
/// CA and persists it under <c>%APPDATA%/JASniffer/rootCA.pfx</c> (so the user
/// installs the CA once); thereafter it mints and caches a leaf certificate per
/// host on demand, each signed by the root and carrying the correct SAN, so the
/// proxy can terminate TLS as the requested server.
/// </summary>
public sealed class CertificateAuthority
{
    private const string CaSubject = "CN=JASniffer Root CA, O=JASniffer, OU=Debugging Proxy";

    private readonly X509Certificate2 _caCertificate;

    // Lazy<> so a host requested concurrently for the first time mints exactly one leaf
    // cert (GetOrAdd's factory can run more than once, but only one Lazy.Value executes).
    private readonly ConcurrentDictionary<string, Lazy<X509Certificate2>> _leafCache = new(StringComparer.OrdinalIgnoreCase);

    private CertificateAuthority(X509Certificate2 caCertificate) => _caCertificate = caCertificate;

    /// <summary>Directory where the root CA material lives.</summary>
    public static string DefaultStoreDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create), "JASniffer");

    /// <summary>The root CA's subject common name, for display.</summary>
    public string Subject => _caCertificate.Subject;

    /// <summary>SHA-256 thumbprint of the root CA, for display/verification.</summary>
    public string Thumbprint => _caCertificate.Thumbprint;

    /// <summary>Loads the persisted root CA, generating and saving a new one if none exists yet.</summary>
    public static CertificateAuthority LoadOrCreate(string? storeDirectory = null)
    {
        var dir = storeDirectory ?? DefaultStoreDirectory;
        Directory.CreateDirectory(dir);
        var pfxPath = Path.Combine(dir, "rootCA.pfx");

        if (File.Exists(pfxPath))
        {
            try
            {
                var existing = X509CertificateLoader.LoadPkcs12(
                    File.ReadAllBytes(pfxPath), null, X509KeyStorageFlags.Exportable);
                return new CertificateAuthority(existing);
            }
            catch (CryptographicException)
            {
                // Corrupt/unreadable store — fall through and regenerate.
            }
        }

        var ca = CreateRootCertificate();
        File.WriteAllBytes(pfxPath, ca.Export(X509ContentType.Pfx));
        File.WriteAllBytes(Path.Combine(dir, "rootCA.cer"), ca.Export(X509ContentType.Cert));
        return new CertificateAuthority(ca);
    }

    /// <summary>The root CA certificate in DER form (a <c>.cer</c> the user installs as a trusted root).</summary>
    public byte[] ExportCaCertificateDer() => _caCertificate.Export(X509ContentType.Cert);

    /// <summary>
    /// The root CA in PEM form (<c>-----BEGIN CERTIFICATE-----</c>). This is what
    /// Android, Linux and most non-Windows trust stores expect.
    /// </summary>
    public string ExportCaCertificatePem() => _caCertificate.ExportCertificatePem();

    /// <summary>
    /// The filename Android expects for a CA in its system trust store
    /// (<c>/system/etc/security/cacerts/</c>): OpenSSL's <c>subject_hash_old</c> — the
    /// MD5 of the DER-encoded subject name, first four bytes read little-endian — as
    /// eight lowercase hex digits, followed by <c>.0</c>. Matches
    /// <c>openssl x509 -subject_hash_old</c>.
    /// </summary>
    public string AndroidSystemCertFileName()
    {
        var md5 = MD5.HashData(_caCertificate.SubjectName.RawData);
        var hash = (uint)(md5[0] | (md5[1] << 8) | (md5[2] << 16) | (md5[3] << 24));
        return $"{hash:x8}.0";
    }

    /// <summary>
    /// Installs the root CA (public part only) into the current user's Trusted Root
    /// store so OS-store browsers (Chrome/Edge) trust intercepted HTTPS without a
    /// manual import. On Windows this shows a one-time consent prompt and needs no
    /// admin rights; Firefox keeps its own store and still needs a manual import.
    /// </summary>
    public (bool Ok, string Message) InstallToUserTrustStore()
    {
        try
        {
            // Add only the public certificate — never the CA private key.
            using var publicOnly = X509CertificateLoader.LoadCertificate(_caCertificate.Export(X509ContentType.Cert));
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            if (store.Certificates.Find(X509FindType.FindByThumbprint, publicOnly.Thumbprint, validOnly: false).Count == 0)
            {
                store.Add(publicOnly);
            }

            store.Close();
            return (true, OperatingSystem.IsWindows()
                ? "Root CA установлен в хранилище «Доверенные корневые» текущего пользователя. Если сайт всё ещё ругается — перезапустите браузер."
                : "Root CA добавлен в пользовательское хранилище. Некоторым приложениям/браузерам может потребоваться ручной импорт.");
        }
        catch (Exception ex)
        {
            return (false, $"Не удалось установить CA автоматически: {ex.Message}. Используйте «Download CA» и импортируйте вручную.");
        }
    }

    /// <summary>
    /// Returns (minting and caching on first use) a leaf certificate with private
    /// key for <paramref name="host"/>, ready to hand to
    /// <see cref="System.Net.Security.SslStream"/> as the server certificate.
    /// </summary>
    public X509Certificate2 GetServerCertificate(string host)
    {
        var key = host.ToLowerInvariant();
        return _leafCache.GetOrAdd(key, k => new Lazy<X509Certificate2>(() => CreateLeafCertificate(k))).Value;
    }

    private X509Certificate2 CreateLeafCertificate(string host)
    {
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={host}", leafKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1") /* serverAuth */], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_caCertificate, true, false));

        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip))
        {
            san.AddIpAddress(ip);
        }
        else
        {
            san.AddDnsName(host);
        }

        request.CertificateExtensions.Add(san.Build());

        // Browsers reject server certs valid for too long; stay well under the
        // 398-day public limit and back-date slightly to absorb clock skew.
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(397);
        var serial = RandomNumberGenerator.GetBytes(16);

        using var leaf = request.Create(_caCertificate, notBefore, notAfter, serial);
        using var withKey = leaf.CopyWithPrivateKey(leafKey);

        // Round-trip through PKCS#12 so the private key is materialized in a form
        // every platform's TLS stack (notably Windows SChannel) accepts as a server
        // credential, instead of an ephemeral key handle.
        return X509CertificateLoader.LoadPkcs12(
            withKey.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateRootCertificate()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(CaSubject, caKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
