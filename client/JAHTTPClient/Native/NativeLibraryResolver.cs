using System.Reflection;
using System.Runtime.InteropServices;

namespace JAHTTPClient.Native;

/// <summary>
/// Resolves the platform-specific native tls-client binary at runtime.
/// </summary>
/// <remarks>
/// <para>
/// The managed code references the import name <c>tls-client</c>. This resolver
/// maps that to the actual file shipped under
/// <c>runtimes/&lt;rid&gt;/native/</c> next to the assembly (the layout produced
/// by the Go build scripts and copied by the .csproj).
/// </para>
/// <para>
/// Registration is idempotent and triggered the first time
/// <see cref="TlsClientNative"/> is used.
/// </para>
/// </remarks>
internal static class NativeLibraryResolver
{
    private const string ImportName = "tls-client";
    private static int _registered;

    /// <summary>Registers the DllImport resolver exactly once for this assembly.</summary>
    internal static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref _registered, 1) == 1)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve);
    }

    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, ImportName, StringComparison.Ordinal))
        {
            return nint.Zero;
        }

        foreach (var candidate in CandidatePaths())
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        // Fall back to default OS probing (handles bin-deployed copies / PATH).
        return NativeLibrary.TryLoad(FileName(), assembly, searchPath, out var fallback)
            ? fallback
            : nint.Zero;
    }

    private static IEnumerable<string> CandidatePaths()
    {
        var baseDir = AppContext.BaseDirectory;
        var rid = Rid();
        var file = FileName();

        // Preferred: runtimes/<rid>/native/<file> (NuGet/RID convention).
        yield return Path.Combine(baseDir, "runtimes", rid, "native", file);
        // Flat next to the assembly.
        yield return Path.Combine(baseDir, file);
    }

    private static string Rid()
    {
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "x64",
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return $"win-{arch}";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return $"osx-{arch}";
        return $"linux-{arch}";
    }

    private static string FileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "tls-client-windows-64.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? "tls-client-darwin-arm64.dylib"
                : "tls-client-darwin-amd64.dylib";
        }

        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? "tls-client-linux-arm64.so"
            : "tls-client-linux-amd64.so";
    }
}
