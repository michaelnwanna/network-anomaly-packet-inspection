using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Traceglass;

public sealed record Destination(string Host, int Port)
{
    public static Destination Parse(string authority, int defaultPort)
    {
        if (!Uri.TryCreate("http://" + authority, UriKind.Absolute, out var uri) ||
            uri.UserInfo.Length != 0 || uri.AbsolutePath != "/" || uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 || authority.EndsWith(':') || authority.Contains('\\') ||
            authority.Any(char.IsWhiteSpace))
            throw new InvalidDataException("Invalid authority");
        var host = Classifier.Normalize(uri.IdnHost.Trim('[', ']'));
        if (!Classifier.ValidDomain(host) && !IPAddress.TryParse(host, out _))
            throw new InvalidDataException("Invalid host");
        // Uri supplies port 80 even when no port was present.
        var explicitPort = authority.StartsWith('[') ? authority.Contains("]:", StringComparison.Ordinal) : authority.Contains(':');
        var port = explicitPort ? uri.Port : defaultPort;
        if (port is < 1 or > 65535) throw new InvalidDataException("Invalid port");
        return new Destination(host, port);
    }
    public string Authority => Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

public sealed class ProxyServer : IAsyncDisposable
{
    private readonly TcpListener listener;
    private readonly MetadataStore store;
    private readonly Classifier classifier;
    private readonly InspectionScope scope;
    private readonly Authority? ca;
    private readonly bool allowPrivate;
    private readonly int maxActive;
    private readonly RemoteCertificateValidationCallback? validateUpstream;
    private readonly X509Certificate2Collection extraRoots = [];
    private readonly CancellationTokenSource stopping = new();
    private readonly ConcurrentDictionary<long, (TcpClient Client, Task Task)> handlers = [];
    private Task? acceptTask;
    private long next;
    private int active;
    public int Active => Volatile.Read(ref active);
    public string Address => ((IPEndPoint)listener.LocalEndpoint).ToString();
    public Task Completion => acceptTask ?? Task.CompletedTask;

    public ProxyServer(IPEndPoint endpoint, MetadataStore store, Classifier classifier, InspectionScope scope,
        Authority? ca, bool allowPrivate, int maxActive, string? upstreamCa = null)
    {
        if (maxActive < 1 || scope.Patterns.Length > 0 && ca is null) throw new ArgumentException("Invalid proxy options");
        listener = new TcpListener(endpoint);
        this.store = store; this.classifier = classifier; this.scope = scope; this.ca = ca;
        this.allowPrivate = allowPrivate; this.maxActive = maxActive;
        if (upstreamCa is not null)
        {
            extraRoots.ImportFromPemFile(upstreamCa);
            if (extraRoots.Count == 0) throw new ArgumentException("Upstream CA file contains no certificates");
            // Build against OS roots first, then explicitly supplied roots. Hostname errors never bypass validation.
            validateUpstream = (_, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None) return true;
                if (cert is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) ||
                    errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) return false;
                using var customChain = new X509Chain();
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.CustomTrustStore.AddRange(extraRoots);
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                customChain.ChainPolicy.DisableCertificateDownloads = true;
                customChain.ChainPolicy.ApplicationPolicy.Add(new("1.3.6.1.5.5.7.3.1"));
                if (chain is not null)
                    foreach (var element in chain.ChainElements) customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
                using var remote = new X509Certificate2(cert);
                return customChain.Build(remote);
            };
        }
    }

    public void Start()
    {
        listener.Start(128);
        acceptTask = Accept();
    }
    private async Task Accept()
    {
        try
        {
            while (!stopping.IsCancellationRequested)
            {
                var connection = await listener.AcceptTcpClientAsync(stopping.Token);
                connection.NoDelay = true;
                if (Active >= maxActive)
                {
                    // Do not let idle rejected clients consume tasks or bounded handler slots.
                    connection.Dispose();
                    continue;
                }
                Interlocked.Increment(ref active);
                var id = Interlocked.Increment(ref next);
                var task = Handle(connection);
                handlers[id] = (connection, task);
                _ = task.ContinueWith(_ =>
                {
                    handlers.TryRemove(id, out var ignored);
                    Interlocked.Decrement(ref active);
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch (SocketException) when (stopping.IsCancellationRequested) { }
    }

    private async Task Handle(TcpClient connection)
    {
        using (connection)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token))
        {
            timeout.CancelAfter(TimeSpan.FromMinutes(2));
            var token = timeout.Token;
            var stream = connection.GetStream();
            try
            {
                var request = await WireRequest.Read(stream, token);
                if (request.Method == "CONNECT")
                {
                    var target = Destination.Parse(request.Target, 443);
                    if (request.Headers.ContainsKey("Transfer-Encoding") ||
                        request.Headers.TryGetValue("Content-Length", out var bodyLength) && bodyLength != "0")
                        throw new InvalidDataException("CONNECT cannot contain body");
                    if (scope.Matches(target.Host)) await Inspect(stream, request, target, token);
                    else await Tunnel(stream, connection.Client, target, token);
                }
                else
                {
                    if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) || uri.Scheme != "http" ||
                        uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
                        throw new InvalidDataException("Expected explicit HTTP proxy request");
                    var target = Destination.Parse(uri.Authority, 80);
                    await Exchange(stream, request, uri, target, "http", token);
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or AuthenticationException or ArgumentException)
            {
                try { await HttpWire.Error(stream, 400, token); } catch (Exception io) when (io is IOException or OperationCanceledException or SocketException) { }
            }
        }
    }

    private async Task Inspect(Stream stream, WireRequest connect, Destination target, CancellationToken token)
    {
        await HttpWire.Write(stream, "HTTP/1.1 200 Connection Established\r\n\r\n", token);
        using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
        using var cert = ca!.Certificate(target.Host);
        try
        {
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11]
            }, token);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or OperationCanceledException)
        {
            Save(new Flow { Method = connect.Method, Scheme = "https", Host = target.Host, Port = target.Port,
                Mode = "inspected", ErrorCode = "client-tls-failed" }, Stopwatch.StartNew());
            return;
        }
        var request = await WireRequest.Read(tls, token);
        if (request.Method == "CONNECT" || !request.Target.StartsWith('/') || request.Target.StartsWith("//", StringComparison.Ordinal) ||
            Destination.Parse(request.Headers["Host"], 443) != target)
        {
            await HttpWire.Error(tls, 421, token);
            return;
        }
        var uri = new Uri("https://" + target.Authority + request.Target);
        await Exchange(tls, request, uri, target, "inspected", token);
    }

    private async Task Exchange(Stream downstream, WireRequest request, Uri uri, Destination target, string mode, CancellationToken token)
    {
        var clock = Stopwatch.StartNew();
        var flow = new Flow { Method = request.Method, Scheme = uri.Scheme, Host = target.Host, Port = target.Port, Mode = mode };
        var length = request.Headers.TryGetValue("Content-Length", out var value) ? long.Parse(value, CultureInfo.InvariantCulture) : 0;
        var chunked = request.Headers.ContainsKey("Transfer-Encoding");
        using var body = new RequestBody(downstream, length, chunked);
        var headersSent = false;
        try
        {
            if (request.Headers.ContainsKey("Upgrade"))
            {
                flow.Status = 501; flow.ErrorCode = "upgrade-unsupported";
                await HttpWire.Error(downstream, 501, token); return;
            }
            if (request.Headers.TryGetValue("Expect", out var expect))
            {
                if (!expect.Equals("100-continue", StringComparison.OrdinalIgnoreCase))
                { await HttpWire.Error(downstream, 417, token); flow.Status = 417; return; }
                await HttpWire.Write(downstream, "HTTP/1.1 100 Continue\r\n\r\n", token);
            }
            await using var upstream = await ConnectUpstream(target, uri.Scheme == "https", token);
            var outgoing = new StringBuilder($"{request.Method} {uri.PathAndQuery} HTTP/1.1\r\nHost: {target.Authority}\r\n");
            var hops = HttpWire.HopHeaders(request.Headers);
            foreach (var (name, headerValue) in request.Headers)
            {
                if (hops.Contains(name) || name.Equals("Host", StringComparison.OrdinalIgnoreCase) || name.Equals("Expect", StringComparison.OrdinalIgnoreCase)) continue;
                outgoing.Append(name).Append(": ").Append(headerValue).Append("\r\n");
            }
            if (chunked) outgoing.Append("Transfer-Encoding: chunked\r\n");
            else if (request.Headers.ContainsKey("Content-Length")) outgoing.Append("Content-Length: ").Append(length).Append("\r\n");
            outgoing.Append("\r\n");
            await HttpWire.Write(upstream, outgoing.ToString(), token);
            using var uploadStop = CancellationTokenSource.CreateLinkedTokenSource(token);
            using var headerStop = CancellationTokenSource.CreateLinkedTokenSource(token);
            headerStop.CancelAfter(TimeSpan.FromSeconds(20));
            async Task Upload()
            {
                try
                {
                    var buffer = new byte[32768];
                    int n;
                    while ((n = await body.ReadAsync(buffer, uploadStop.Token)) != 0)
                    {
                        if (chunked) await HttpWire.Write(upstream, n.ToString("x", CultureInfo.InvariantCulture) + "\r\n", uploadStop.Token);
                        await upstream.WriteAsync(buffer.AsMemory(0, n), uploadStop.Token);
                        if (chunked) await HttpWire.Write(upstream, "\r\n", uploadStop.Token);
                    }
                    if (chunked) await HttpWire.Write(upstream, "0\r\n\r\n", uploadStop.Token);
                }
                catch
                {
                    if (!uploadStop.IsCancellationRequested) await headerStop.CancelAsync();
                    throw;
                }
            }
            var upload = Upload();
            WireResponse response;
            try
            {
                do { response = await WireResponse.Read(upstream, headerStop.Token); }
                while (response.Status < 200 && response.Status != 101);
            }
            finally
            {
                await uploadStop.CancelAsync();
                try { await upload; }
                catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
                {
                    flow.ErrorCode = "request-body-failed";
                }
            }
            flow.Status = response.Status;
            if (flow.Status == 101)
            {
                flow.Status = 501; flow.ErrorCode = "upgrade-unsupported";
                await HttpWire.Error(downstream, 501, token); return;
            }
            var responseHeaders = response.Headers;
            var removed = HttpWire.HopHeaders(responseHeaders);
            var noBody = request.Method == "HEAD" || flow.Status is 204 or 304 || flow.Status < 200;
            var lengthHeader = responseHeaders.FirstOrDefault(h => h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).Value;
            long? contentLength = lengthHeader is null ? null : long.Parse(lengthHeader, CultureInfo.InvariantCulture);
            var incomingChunked = responseHeaders.Any(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));
            var useChunks = !noBody && !contentLength.HasValue;
            var head = new StringBuilder($"HTTP/1.1 {flow.Status} Response\r\nConnection: close\r\n");
            foreach (var (name, headerValue) in responseHeaders)
                if (!removed.Contains(name)) head.Append(name).Append(": ").Append(headerValue).Append("\r\n");
            if (contentLength.HasValue && (!noBody || request.Method == "HEAD" || flow.Status == 304))
                head.Append("Content-Length: ").Append(contentLength.Value).Append("\r\n");
            else if (useChunks) head.Append("Transfer-Encoding: chunked\r\n");
            head.Append("\r\n");
            headersSent = true;
            await HttpWire.Write(downstream, head.ToString(), token);
            if (!noBody)
            {
                using var framed = new RequestBody(upstream, contentLength ?? 0, incomingChunked);
                var incoming = contentLength.HasValue || incomingChunked ? framed : upstream;
                var buffer = new byte[32768];
                int n;
                while ((n = await incoming.ReadAsync(buffer, token)) != 0)
                {
                    flow.ResponseBytes += n;
                    if (useChunks) await HttpWire.Write(downstream, n.ToString("x", CultureInfo.InvariantCulture) + "\r\n", token);
                    await downstream.WriteAsync(buffer.AsMemory(0, n), token);
                    if (useChunks) await HttpWire.Write(downstream, "\r\n", token);
                }
                if (contentLength.HasValue && flow.ResponseBytes != contentLength.Value) throw new IOException("Incomplete response");
                if (useChunks) await HttpWire.Write(downstream, "0\r\n\r\n", token);
            }
            if (!body.Complete) flow.ErrorCode = "request-body-failed";
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException or SocketException or AuthenticationException)
        {
            flow.ErrorCode = headersSent ? "stream-failed" : "upstream-failed";
            if (!headersSent)
            {
                flow.Status = 502;
                try { await HttpWire.Error(downstream, 502, token); } catch (Exception io) when (io is IOException or OperationCanceledException) { }
            }
            // On partial responses simply close: never send a successful final chunk.
        }
        finally { flow.RequestBytes = body.Count; Save(flow, clock); }
    }

    private async Task<Stream> ConnectUpstream(Destination target, bool secure, CancellationToken token)
    {
        var socket = await Dial(target.Host, target.Port, token);
        Stream stream = new NetworkStream(socket, ownsSocket: true);
        if (!secure) return stream;
        var tls = new SslStream(stream, leaveInnerStreamOpen: false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.Host, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                RemoteCertificateValidationCallback = validateUpstream
            }, timeout.Token);
            return tls;
        }
        catch
        {
            await tls.DisposeAsync();
            throw;
        }
    }

    private async Task Tunnel(Stream downstream, Socket clientSocket, Destination target, CancellationToken token)
    {
        var clock = Stopwatch.StartNew();
        var flow = new Flow { Method = "CONNECT", Scheme = "https", Host = target.Host, Port = target.Port, Mode = "tunnel" };
        try
        {
            using var socket = await Dial(target.Host, target.Port, token);
            await using var upstream = new NetworkStream(socket, ownsSocket: false);
            await HttpWire.Write(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n", token);
            flow.Status = 200;
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token);
            async Task Pump(Stream source, Stream destination, Socket destinationSocket, bool upload)
            {
                var buffer = new byte[32768];
                try
                {
                    int n;
                    while ((n = await source.ReadAsync(buffer, linked.Token)) > 0)
                    {
                        if (upload) flow.RequestBytes += n; else flow.ResponseBytes += n;
                        await destination.WriteAsync(buffer.AsMemory(0, n), linked.Token);
                    }
                    destinationSocket.Shutdown(SocketShutdown.Send);
                }
                catch { await linked.CancelAsync(); throw; }
            }
            await Task.WhenAll(Pump(downstream, upstream, socket, true), Pump(upstream, downstream, clientSocket, false));
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            flow.ErrorCode = flow.Status == 200 ? "tunnel-io" : "connect-failed";
            if (flow.Status == 0) { flow.Status = 502; try { await HttpWire.Error(downstream, 502, token); } catch (IOException) { } }
        }
        finally { Save(flow, clock); }
    }

    private void Save(Flow flow, Stopwatch clock)
    {
        flow.DurationMs = clock.ElapsedMilliseconds;
        flow.Flags = classifier.Flags(flow.Host, flow.Port, flow.RequestBytes, flow.ResponseBytes);
        store.Enqueue(flow);
    }

    internal static bool Allowed(IPAddress ip, bool allowPrivate)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast ||
            ip.ScopeIdSafe() != 0) return false;
        var b = ip.GetAddressBytes();
        if (b.Length == 4 && (b[0] >= 224 || b[0] == 0)) return false;
        if (allowPrivate) return true;
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return false;
        return b.Length == 4
            ? !(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168 ||
                b[0] == 169 && b[1] == 254 || b[0] == 100 && b[1] is >= 64 and <= 127)
            : (b[0] & 0xfe) != 0xfc;
    }

    private async Task<Socket> Dial(string host, int port, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var ips = await Dns.GetHostAddressesAsync(host, timeout.Token);
        if (ips.Length == 0 || ips.Any(ip => !Allowed(ip, allowPrivate))) throw new IOException("Destination denied");
        foreach (var ip in ips)
        {
            var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try { await socket.ConnectAsync(new IPEndPoint(ip, port), timeout.Token); return socket; }
            catch (SocketException) { socket.Dispose(); }
            catch { socket.Dispose(); throw; }
        }
        throw new IOException("Connect failed");
    }
    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        listener.Stop();
        if (acceptTask is not null) await acceptTask;
        var pending = handlers.Values.ToArray();
        foreach (var item in pending) item.Client.Dispose();
        await Task.WhenAll(pending.Select(item => item.Task));
        foreach (var root in extraRoots) root.Dispose();
        stopping.Dispose();
    }
}

internal static class IpExtensions
{
    public static long ScopeIdSafe(this IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetworkV6 ? ip.ScopeId : 0;
}
