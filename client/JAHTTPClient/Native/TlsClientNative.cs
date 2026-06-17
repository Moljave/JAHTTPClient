using System.Runtime.InteropServices;
using System.Text.Json;
using JAHTTPClient.Interop;

namespace JAHTTPClient.Native;

/// <summary>
/// Low-level, source-generated P/Invoke bindings for the native tls-client
/// shared library, plus thin managed helpers that own memory correctly.
/// </summary>
/// <remarks>
/// <para>
/// Every native call that returns a C string transfers ownership to the caller.
/// We immediately marshal it to a managed string and then release it via
/// <c>freeMemory(response.id)</c>. The <c>*Json</c> helpers encapsulate this so
/// no caller can forget and leak.
/// </para>
/// <para>
/// The underlying library is thread-safe (Go runtime), so these static methods
/// may be called concurrently from any number of threads.
/// </para>
/// </remarks>
internal static partial class TlsClientNative
{
    static TlsClientNative() => NativeLibraryResolver.EnsureRegistered();

    // ---- raw imports -------------------------------------------------------

    [LibraryImport("tls-client", EntryPoint = "request")]
    private static partial nint NativeRequest(nint payloadUtf8);

    [LibraryImport("tls-client", EntryPoint = "getCookiesFromSession")]
    private static partial nint NativeGetCookies(nint payloadUtf8);

    [LibraryImport("tls-client", EntryPoint = "addCookiesToSession")]
    private static partial nint NativeAddCookies(nint payloadUtf8);

    [LibraryImport("tls-client", EntryPoint = "destroySession")]
    private static partial nint NativeDestroySession(nint payloadUtf8);

    [LibraryImport("tls-client", EntryPoint = "destroyAll")]
    private static partial nint NativeDestroyAll();

    [LibraryImport("tls-client", EntryPoint = "freeMemory")]
    private static partial void NativeFreeMemory(nint responseIdUtf8);

    // ---- managed helpers ---------------------------------------------------

    /// <summary>Performs a request and returns the parsed response. Frees native memory automatically.</summary>
    internal static TlsResponsePayload Request(TlsRequestPayload payload)
    {
        var json = JsonSerializer.Serialize(payload, TlsJsonContext.Default.TlsRequestPayload);
        var raw = InvokeWithUtf8(json, NativeRequest);
        var response = JsonSerializer.Deserialize(raw, TlsJsonContext.Default.TlsResponsePayload)
                       ?? throw new InvalidOperationException("Native tls-client returned an empty response.");
        FreeById(response.Id);
        return response;
    }

    /// <summary>Reads the cookie jar for a session/url.</summary>
    internal static TlsResponsePayload GetCookies(SessionCookiesPayload payload)
        => CallCookieEndpoint(payload, NativeGetCookies);

    /// <summary>Adds/overwrites cookies in a session jar.</summary>
    internal static TlsResponsePayload AddCookies(SessionCookiesPayload payload)
        => CallCookieEndpoint(payload, NativeAddCookies);

    /// <summary>Releases a session and its cookie jar.</summary>
    internal static void DestroySession(string sessionId)
    {
        var json = JsonSerializer.Serialize(
            new DestroySessionPayload { SessionId = sessionId },
            TlsJsonContext.Default.DestroySessionPayload);
        var raw = InvokeWithUtf8(json, NativeDestroySession);
        TryFreeFromRawJson(raw);
    }

    /// <summary>Releases every session held by the native library (process shutdown).</summary>
    internal static void DestroyAll()
    {
        var raw = MarshalAndFree(NativeDestroyAll());
        TryFreeFromRawJson(raw);
    }

    private static TlsResponsePayload CallCookieEndpoint(
        SessionCookiesPayload payload, Func<nint, nint> native)
    {
        var json = JsonSerializer.Serialize(payload, TlsJsonContext.Default.SessionCookiesPayload);
        var raw = InvokeWithUtf8(json, native);
        var response = JsonSerializer.Deserialize(raw, TlsJsonContext.Default.TlsResponsePayload)
                       ?? new TlsResponsePayload();
        FreeById(response.Id);
        return response;
    }

    /// <summary>Marshals <paramref name="json"/> to UTF-8, invokes the native fn, and returns the managed result string.</summary>
    private static string InvokeWithUtf8(string json, Func<nint, nint> native)
    {
        var utf8 = Marshal.StringToCoTaskMemUTF8(json);
        try
        {
            return MarshalAndFree(native(utf8));
        }
        finally
        {
            Marshal.FreeCoTaskMem(utf8);
        }
    }

    private static string MarshalAndFree(nint resultPtr)
        => Marshal.PtrToStringUTF8(resultPtr) ?? string.Empty;

    private static void FreeById(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return;
        }

        var idPtr = Marshal.StringToCoTaskMemUTF8(id);
        try
        {
            NativeFreeMemory(idPtr);
        }
        finally
        {
            Marshal.FreeCoTaskMem(idPtr);
        }
    }

    private static void TryFreeFromRawJson(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("id", out var id) &&
                id.ValueKind == JsonValueKind.String)
            {
                FreeById(id.GetString());
            }
        }
        catch (JsonException)
        {
            // Endpoint returned a bare status string with no id to free — nothing to do.
        }
    }
}
