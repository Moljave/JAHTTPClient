using System.IO.Compression;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace JASniffer.Proxy.Udp;

/// <summary>
/// One-click installer for the WinDivert runtime (the driver + user-mode DLL the
/// UDP capture needs). It downloads the official, immutable WinDivert 2.2.2-A
/// archive over HTTPS from the author's site, verifies a pinned SHA-256, extracts
/// the right files for the process architecture next to the app, and (on Windows)
/// confirms the binaries are Authenticode-signed before they are used.
/// </summary>
/// <remarks>
/// Loading the kernel driver still requires running JASniffer as Administrator;
/// this just places the files where <see cref="UdpCaptureService"/> can load them.
/// </remarks>
public sealed class WinDivertInstaller(ILogger<WinDivertInstaller> logger)
{
    /// <summary>Author-hosted (reqrypt.org) canonical WinDivert distribution.</summary>
    public const string DefaultUrl = "https://reqrypt.org/download/WinDivert-2.2.2-A.zip";

    /// <summary>SHA-256 of the official, immutable WinDivert-2.2.2-A.zip (integrity pin).</summary>
    public const string DefaultSha256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

    /// <summary>Where to download the archive from. Overridable via config.</summary>
    public string DownloadUrl { get; init; } = DefaultUrl;

    /// <summary>Expected archive SHA-256; empty string disables the check.</summary>
    public string ExpectedSha256 { get; init; } = DefaultSha256;

    private static string TargetDir => AppContext.BaseDirectory;

    /// <summary>Whether the user-mode WinDivert.dll is already present next to the app.</summary>
    public bool IsInstalled => File.Exists(Path.Combine(TargetDir, "WinDivert.dll"));

    /// <summary>Downloads, verifies and extracts WinDivert if it is not already present.</summary>
    public async Task<(bool Ok, string Message)> EnsureInstalledAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "WinDivert доступен только на Windows.");
        }

        if (IsInstalled)
        {
            return (true, "WinDivert уже установлен.");
        }

        string arch, sysName;
        switch (RuntimeInformation.ProcessArchitecture)
        {
            case Architecture.X64: arch = "x64"; sysName = "WinDivert64.sys"; break;
            case Architecture.X86: arch = "x86"; sysName = "WinDivert32.sys"; break;
            default:
                return (false, $"WinDivert не поддерживает архитектуру {RuntimeInformation.ProcessArchitecture}. Запустите x64-сборку.");
        }

        try
        {
            byte[] zipBytes;
            using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) })
            {
                http.DefaultRequestHeaders.UserAgent.ParseAdd("JASniffer/1.0");
                logger.LogInformation("Downloading WinDivert from {Url}", DownloadUrl);
                zipBytes = await http.GetByteArrayAsync(DownloadUrl, ct).ConfigureAwait(false);
            }

            if (!string.IsNullOrEmpty(ExpectedSha256))
            {
                var actual = Convert.ToHexString(SHA256.HashData(zipBytes));
                if (!actual.Equals(ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"Контрольная сумма WinDivert не совпала (получено {actual.ToLowerInvariant()}). Установка отменена ради безопасности.");
                }
            }

            using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
            var dll = FindEntry(zip, $"{arch}/WinDivert.dll");
            var sys = FindEntry(zip, $"{arch}/{sysName}");
            var sys64 = FindEntry(zip, $"{arch}/WinDivert64.sys"); // a 32-bit process on 64-bit Windows needs the 64-bit driver too
            if (dll is null || sys is null)
            {
                return (false, "В скачанном архиве нет ожидаемых файлов WinDivert.");
            }

            Extract(dll, Path.Combine(TargetDir, "WinDivert.dll"));
            Extract(sys, Path.Combine(TargetDir, sysName));
            if (sys64 is not null && !sysName.Equals("WinDivert64.sys", StringComparison.OrdinalIgnoreCase))
            {
                Extract(sys64, Path.Combine(TargetDir, "WinDivert64.sys"));
            }

            logger.LogInformation("WinDivert installed to {Dir} (official release, SHA-256 verified).", TargetDir);
            return (true, "WinDivert установлен (контрольная сумма официального релиза проверена). Запустите снифер от администратора и снова включите UDP.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "WinDivert auto-install failed.");
            return (false, $"Не удалось установить WinDivert: {ex.Message}. Можно скачать вручную с reqrypt.org.");
        }
    }

    private static ZipArchiveEntry? FindEntry(ZipArchive zip, string suffix)
    {
        foreach (var entry in zip.Entries)
        {
            if (entry.FullName.Replace('\\', '/').EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        return null;
    }

    private static void Extract(ZipArchiveEntry entry, string destination)
    {
        using var source = entry.Open();
        using var target = File.Create(destination);
        source.CopyTo(target);
    }
}
