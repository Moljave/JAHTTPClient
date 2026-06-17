using System.Security.Cryptography.X509Certificates;
using JASniffer.Core.Certificates;

namespace JASniffer.Tests;

public sealed class CertificateAuthorityTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "JASnifferTests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void LoadOrCreate_PersistsRootMaterial()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        Assert.True(File.Exists(Path.Combine(_dir, "rootCA.pfx")));
        Assert.True(File.Exists(Path.Combine(_dir, "rootCA.cer")));
        Assert.Contains("JASniffer", ca.Subject);
        Assert.False(string.IsNullOrEmpty(ca.Thumbprint));
    }

    [Fact]
    public void LoadOrCreate_IsStableAcrossReloads()
    {
        var first = CertificateAuthority.LoadOrCreate(_dir).Thumbprint;
        var second = CertificateAuthority.LoadOrCreate(_dir).Thumbprint;
        Assert.Equal(first, second);
    }

    [Fact]
    public void ExportCaCertificateDer_ParsesAsCertificate()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        var der = ca.ExportCaCertificateDer();
        using var parsed = X509CertificateLoader.LoadCertificate(der);
        Assert.Equal(ca.Subject, parsed.Subject);
    }

    [Fact]
    public void GetServerCertificate_ForHostname_HasCnAndDnsSan()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        using var leaf = ca.GetServerCertificate("api.example.com");

        Assert.Contains("CN=api.example.com", leaf.Subject);
        Assert.Equal(ca.Subject, leaf.Issuer);
        Assert.True(leaf.HasPrivateKey);

        var sans = SubjectAltNames(leaf);
        Assert.Contains("api.example.com", sans);
    }

    [Fact]
    public void GetServerCertificate_ForIpLiteral_HasIpSan()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        using var leaf = ca.GetServerCertificate("127.0.0.1");
        var sans = SubjectAltNames(leaf);
        Assert.Contains("127.0.0.1", sans);
    }

    [Fact]
    public void GetServerCertificate_IsCachedPerHost()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        var a = ca.GetServerCertificate("cache.example.com");
        var b = ca.GetServerCertificate("CACHE.example.com"); // case-insensitive key
        Assert.Same(a, b);
    }

    [Fact]
    public void GetServerCertificate_ValidityWithinPublicLimit()
    {
        var ca = CertificateAuthority.LoadOrCreate(_dir);
        using var leaf = ca.GetServerCertificate("dates.example.com");
        var lifespan = leaf.NotAfter - leaf.NotBefore;
        Assert.True(lifespan.TotalDays <= 398, $"Leaf lifespan {lifespan.TotalDays}d exceeds the 398-day browser limit.");
    }

    private static string SubjectAltNames(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // subjectAltName
            {
                return ext.Format(false);
            }
        }

        return string.Empty;
    }
}
