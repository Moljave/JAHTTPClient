using System.Diagnostics;

namespace JASniffer.Web;

/// <summary>Best-effort "open the UI in the default browser" once the host is up.</summary>
public static class BrowserLauncher
{
    public static void Open(string url)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start \"\" \"{url}\"") { CreateNoWindow = true });
            }
            else if (OperatingSystem.IsMacOS())
            {
                Process.Start("open", url);
            }
            else
            {
                Process.Start("xdg-open", url);
            }
        }
        catch (Exception)
        {
            // Headless box / no browser — the console prints the URL anyway.
        }
    }
}
