using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace JASniffer.Tests.Integration;

/// <summary>
/// A tiny in-process HTTP/1.1 origin server bound to a free loopback port, used as
/// the "real site" the proxy re-issues requests to. Cross-platform (managed
/// <see cref="HttpListener"/>); no external network is touched.
/// </summary>
internal sealed class LoopbackOrigin : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();

    public int Port { get; }
    public string BaseUrl => $"http://127.0.0.1:{Port}";

    /// <summary>Requests the origin actually received (what the upstream leg sent).</summary>
    public ConcurrentQueue<ReceivedRequest> Received { get; } = new();

    /// <summary>Produces the response for a received request. Override per test.</summary>
    public Func<ReceivedRequest, OriginResponse> Handler { get; set; } =
        _ => OriginResponse.Text("ok");

    public LoopbackOrigin()
    {
        Port = FreeTcpPort();
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
        _listener.Start();
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                return; // listener stopped
            }

            _ = Task.Run(() => ServeAsync(ctx));
        }
    }

    private async Task ServeAsync(HttpListenerContext ctx)
    {
        try
        {
            var req = ctx.Request;
            byte[] body;
            using (var ms = new MemoryStream())
            {
                await req.InputStream.CopyToAsync(ms).ConfigureAwait(false);
                body = ms.ToArray();
            }

            var headers = req.Headers.AllKeys
                .ToDictionary(k => k!, k => req.Headers[k]!, StringComparer.OrdinalIgnoreCase);
            var received = new ReceivedRequest(req.HttpMethod, req.Url!.PathAndQuery, headers, body);
            Received.Enqueue(received);

            var response = Handler(received);
            ctx.Response.StatusCode = response.Status;
            ctx.Response.StatusDescription = response.Reason;
            if (response.ContentType is not null)
            {
                ctx.Response.ContentType = response.ContentType;
            }

            foreach (var (name, value) in response.Headers)
            {
                // Content-Type has a dedicated slot on HttpListenerResponse; routing it
                // there (rather than the header bag) avoids setting it twice.
                if (string.Equals(name, "Content-Type", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Response.ContentType = value;
                }
                else
                {
                    ctx.Response.Headers[name] = value;
                }
            }

            ctx.Response.ContentLength64 = response.Body.Length;
            await ctx.Response.OutputStream.WriteAsync(response.Body).ConfigureAwait(false);
            ctx.Response.OutputStream.Close();
        }
        catch
        {
            // best effort; a torn client connection is not the origin's concern
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* ignore */ }
        try { _listener.Close(); } catch { /* ignore */ }
    }

    internal static int FreeTcpPort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}

internal sealed record ReceivedRequest(
    string Method, string PathAndQuery, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string BodyText => Encoding.UTF8.GetString(Body);
}

internal sealed record OriginResponse(int Status, string Reason, string? ContentType, byte[] Body)
{
    public List<(string Name, string Value)> Headers { get; } = [];

    public static OriginResponse Text(string text, int status = 200)
        => new(status, ReasonFor(status), "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(text));

    public static OriginResponse Json(string json, int status = 200)
        => new(status, ReasonFor(status), "application/json", Encoding.UTF8.GetBytes(json));

    private static string ReasonFor(int status) => status switch
    {
        200 => "OK", 201 => "Created", 204 => "No Content", 301 => "Moved Permanently",
        302 => "Found", 304 => "Not Modified", 400 => "Bad Request", 401 => "Unauthorized",
        403 => "Forbidden", 404 => "Not Found", 429 => "Too Many Requests",
        500 => "Internal Server Error", 502 => "Bad Gateway", 503 => "Service Unavailable", _ => "OK",
    };

    public OriginResponse WithHeader(string name, string value)
    {
        Headers.Add((name, value));
        return this;
    }
}
