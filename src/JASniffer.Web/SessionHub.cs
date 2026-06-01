using Microsoft.AspNetCore.SignalR;

namespace JASniffer.Web;

/// <summary>
/// SignalR hub the SPA connects to for live capture updates. The server pushes
/// <c>sessions</c> (batched summary upserts) and <c>cleared</c> messages; clients
/// don't invoke anything back, so the hub body is intentionally empty.
/// </summary>
public sealed class SessionHub : Hub
{
}
