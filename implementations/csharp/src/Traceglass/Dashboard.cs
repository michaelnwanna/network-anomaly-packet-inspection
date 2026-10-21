using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Traceglass;

public sealed class Dashboard : IAsyncDisposable
{
    private readonly WebApplication app;
    public string Address { get; private set; } = "";
    public string Token { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    public Dashboard(string endpoint, MetadataStore store, ProxyServer proxy, Options options)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://" + endpoint);
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestHeadersTotalSize = 16384;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            server.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            server.Limits.MaxConcurrentConnections = 64;
            server.Limits.MaxRequestBodySize = 0;
        });
        app = builder.Build();
        app.Run(async context =>
        {
            var response = context.Response;
            response.Headers.CacheControl = "no-store";
            response.Headers.ContentSecurityPolicy = "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
            response.Headers.XContentTypeOptions = "nosniff";
            response.Headers.XFrameOptions = "DENY";
            response.Headers["Referrer-Policy"] = "no-referrer";
            async Task Error(int code, string text)
            {
                response.StatusCode = code;
                response.ContentType = "text/plain";
                await response.WriteAsync(text);
            }
            if (context.Request.Host.Value != Address) { await Error(403, "unexpected dashboard host"); return; }
            var origin = context.Request.Headers.Origin.ToString();
            if (origin.Length != 0 && origin != "http://" + Address) { await Error(403, "cross-origin access denied"); return; }
            var path = context.Request.Path.Value ?? "/";
            if (path.StartsWith("/api/", StringComparison.Ordinal))
            {
                if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(context.Request.Headers.Authorization.ToString()),
                    Encoding.UTF8.GetBytes("Bearer " + Token)))
                { await Error(401, "dashboard bearer token required"); return; }
                if (context.Request.Method != "GET") { await Error(405, "read-only API"); return; }
                object value;
                try
                {
                    if (path == "/api/status")
                        value = new
                        {
                            stats = store.Stats(), active = proxy.Active, proxy = proxy.Address,
                            inspect = options.Scope.Patterns, max_records = options.MaxRecords,
                            max_age = options.MaxAgeText, allow_private = options.AllowPrivate
                        };
                    else if (path == "/api/records")
                    {
                        var query = context.Request.Query;
                        var limit = 100;
                        long before = 0;
                        if (query.ContainsKey("limit") && (!int.TryParse(query["limit"], out limit) || limit is < 1 or > 200))
                        { await Error(400, "limit must be between 1 and 200"); return; }
                        if (query.ContainsKey("before") && (!long.TryParse(query["before"], out before) || before < 1))
                        { await Error(400, "before must be a positive record ID"); return; }
                        var flagged = query["flagged"].ToString();
                        var host = query["host"].ToString().ToLowerInvariant();
                        if (Encoding.UTF8.GetByteCount(host) > 253 || flagged is not ("" or "true" or "false"))
                        { await Error(400, "invalid host or flagged filter"); return; }
                        var rows = store.List(limit, before, host, flagged == "true");
                        value = new { records = rows, next_before = rows.Count == limit ? rows[^1].Id : 0 };
                    }
                    else { await Error(404, "not found"); return; }
                }
                catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException)
                {
                    Console.Error.WriteLine("metadata query failed");
                    await Error(500, "metadata query failed"); return;
                }
                response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(response.Body, value, Json.Options, context.RequestAborted);
                return;
            }
            if (context.Request.Method is not ("GET" or "HEAD")) { await Error(405, "read-only dashboard"); return; }
            var asset = path switch { "/" or "/index.html" => "index.html", "/app.js" => "app.js", "/style.css" => "style.css", _ => null };
            if (asset is null) { await Error(404, "not found"); return; }
            response.ContentType = asset.EndsWith(".js", StringComparison.Ordinal) ? "text/javascript" :
                asset.EndsWith(".css", StringComparison.Ordinal) ? "text/css" : "text/html";
            await using var stream = typeof(Dashboard).Assembly.GetManifestResourceStream("Traceglass.web." + asset)!;
            response.ContentLength = stream.Length;
            if (context.Request.Method != "HEAD") await stream.CopyToAsync(response.Body, context.RequestAborted);
        });
    }
    public async Task Start(CancellationToken token)
    {
        await app.StartAsync(token);
        var urls = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses;
        Address = new Uri(urls.Single()).Authority;
    }
    public async ValueTask DisposeAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await app.StopAsync(timeout.Token);
        await app.DisposeAsync();
    }
}
