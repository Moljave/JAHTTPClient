using JASniffer.Core.Models;

namespace JASniffer.Proxy;

/// <summary>
/// The response to write back on the browser leg. The body is the full,
/// already-decoded payload (what the browser must receive); the owning session may
/// store a truncated copy for the inspector, but this never is.
/// </summary>
internal sealed class RelayResult
{
    public int Status { get; init; }
    public string Reason { get; init; } = string.Empty;
    public List<HeaderEntry> Headers { get; init; } = [];
    public byte[] Body { get; init; } = [];

    /// <summary>Builds a synthetic 502 to show the browser when the upstream call failed outright.</summary>
    public static RelayResult Gateway502(string message)
    {
        var body = System.Text.Encoding.UTF8.GetBytes(
            $"JASniffer could not complete the upstream request.\n\n{message}");
        return new RelayResult
        {
            Status = 502,
            Reason = "Bad Gateway",
            Headers = [new HeaderEntry("Content-Type", "text/plain; charset=utf-8")],
            Body = body,
        };
    }
}
