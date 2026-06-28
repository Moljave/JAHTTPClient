using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace JASniffer.Web;

/// <summary>
/// Toggles the OS HTTP proxy so traffic is routed through JASniffer without the
/// user editing browser settings. Implemented for Windows (WinINET registry +
/// refresh); a no-op elsewhere, where the user points their browser at
/// <c>127.0.0.1:8866</c> manually. The previous WinINET settings are captured on
/// enable and restored on disable.
/// </summary>
public sealed partial class SystemProxy(ILogger<SystemProxy> logger)
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private string? _savedServer;
    private object? _savedEnable;
    private string? _savedOverride;
    private bool _enabledByUs;

    /// <summary>Whether toggling the OS proxy is supported on the current platform.</summary>
    public bool Supported => OperatingSystem.IsWindows();

    /// <summary>Whether JASniffer currently has the OS proxy pointed at itself.</summary>
    public bool Enabled => _enabledByUs;

    /// <summary>Routes the OS proxy through <c>127.0.0.1:{proxyPort}</c>, bypassing localhost so the UI is direct.</summary>
    public bool Enable(int proxyPort)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            EnableWindows(proxyPort);
            _enabledByUs = true;
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to enable the Windows system proxy.");
            return false;
        }
    }

    /// <summary>Restores the OS proxy settings captured when it was enabled.</summary>
    public bool Disable()
    {
        if (!OperatingSystem.IsWindows() || !_enabledByUs)
        {
            return false;
        }

        try
        {
            DisableWindows();
            _enabledByUs = false;
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to restore the Windows system proxy.");
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private void EnableWindows(int proxyPort)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Internet Settings registry key not found.");

        _savedEnable = key.GetValue("ProxyEnable");
        _savedServer = key.GetValue("ProxyServer") as string;
        _savedOverride = key.GetValue("ProxyOverride") as string;

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"127.0.0.1:{proxyPort}", RegistryValueKind.String);
        // Keep the UI (localhost:8888) and loopback off the proxy path.
        key.SetValue("ProxyOverride", "localhost;127.0.0.1;<-loopback>", RegistryValueKind.String);

        Refresh();
    }

    [SupportedOSPlatform("windows")]
    private void DisableWindows()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
        if (key is null)
        {
            return;
        }

        key.SetValue("ProxyEnable", _savedEnable ?? 0, RegistryValueKind.DWord);
        if (_savedServer is not null)
        {
            key.SetValue("ProxyServer", _savedServer, RegistryValueKind.String);
        }

        if (_savedOverride is not null)
        {
            key.SetValue("ProxyOverride", _savedOverride, RegistryValueKind.String);
        }

        Refresh();
    }

    [SupportedOSPlatform("windows")]
    private static void Refresh()
    {
        // Tell WinINET its settings changed so the new proxy takes effect at once.
        // Best-effort: the registry change already applies to new connections, so a
        // refresh hiccup must never throw up the stack and leave a half-applied state.
        try
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch (EntryPointNotFoundException)
        {
            // Unusual WinINET build without the W entry point — skip the live refresh.
        }
    }

    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    // wininet.dll exports InternetSetOptionW/A; [LibraryImport] needs the exact name
    // (no implicit W/A probing like [DllImport]), so target the wide entry point.
    [LibraryImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
