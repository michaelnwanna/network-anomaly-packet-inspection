using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Traceglass;

public sealed class Options
{
    public string Listen { get; init; } = "127.0.0.1:8080";
    public string Dashboard { get; init; } = "127.0.0.1:9090";
    public string DataDir { get; init; } = "./data-csharp";
    public InspectionScope Scope { get; init; } = new("");
    public string? Rules { get; init; }
    public string? UpstreamCa { get; init; }
    public long MaxRecords { get; init; } = 1_000_000;
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(7);
    public string MaxAgeText { get; init; } = "168h0m0s";
    public int QueueSize { get; init; } = 8192;
    public int MaxActive { get; init; } = 256;
    public bool AllowPrivate { get; init; }

    public static Dictionary<string, string> Flags(string[] args, params string[] allowed)
    {
        Dictionary<string, string> result = [];
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith('-')) throw new ArgumentException("Unexpected positional argument");
            var parts = arg.TrimStart('-').Split('=', 2);
            var name = parts[0];
            if (!allowed.Contains(name)) throw new ArgumentException($"Unknown flag: {name}");
            string value;
            if (parts.Length == 2) value = parts[1];
            else if (name == "allow-private") value = "true";
            else if (++i < args.Length) value = args[i];
            else throw new ArgumentException($"Missing flag value: {name}");
            if (!result.TryAdd(name, value)) throw new ArgumentException($"Duplicate flag: {name}");
        }
        return result;
    }

    public static Options Parse(string[] args)
    {
        var flags = Flags(args, "listen", "dashboard", "data-dir", "inspect", "rules", "upstream-ca",
            "max-records", "max-age", "queue-size", "max-active", "allow-private");
        string Get(string key, string fallback) => flags.GetValueOrDefault(key, fallback);
        var age = Get("max-age", "168h");
        var options = new Options
        {
            Listen = Get("listen", "127.0.0.1:8080"), Dashboard = Get("dashboard", "127.0.0.1:9090"),
            DataDir = Get("data-dir", "./data-csharp"), Scope = new(Get("inspect", "")),
            Rules = flags.GetValueOrDefault("rules"), UpstreamCa = flags.GetValueOrDefault("upstream-ca"),
            MaxRecords = long.Parse(Get("max-records", "1000000"), CultureInfo.InvariantCulture),
            MaxAge = Duration(age), MaxAgeText = age,
            QueueSize = int.Parse(Get("queue-size", "8192"), CultureInfo.InvariantCulture),
            MaxActive = int.Parse(Get("max-active", "256"), CultureInfo.InvariantCulture),
            AllowPrivate = bool.Parse(Get("allow-private", "false"))
        };
        Endpoint(options.Listen); Endpoint(options.Dashboard);
        if (options.MaxRecords < 1 || options.MaxAge <= TimeSpan.Zero ||
            options.QueueSize is < 1 or > 1_000_000 || options.MaxActive is < 1 or > 4096)
            throw new ArgumentException("Invalid resource limits");
        return options;
    }
    public static IPEndPoint Endpoint(string text)
    {
        if (!IPEndPoint.TryParse(text, out var endpoint) || !IPAddress.IsLoopback(endpoint.Address))
            throw new ArgumentException("Listeners require loopback IP:port (0 permitted)");
        return endpoint;
    }
    public static TimeSpan Duration(string text)
    {
        var matches = Regex.Matches(text, @"(\d+(?:\.\d+)?)(ms|s|m|h)");
        if (matches.Count == 0 || string.Concat(matches.Select(m => m.Value)) != text)
            throw new ArgumentException("Duration requires Go-style h, m, s, or ms units");
        double milliseconds = 0;
        foreach (Match match in matches)
            milliseconds += double.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture) *
                (match.Groups[2].Value switch { "h" => 3_600_000, "m" => 60_000, "s" => 1000, _ => 1 });
        return TimeSpan.FromMilliseconds(milliseconds);
    }
}

public static class Program
{
    private const string Help = """
        Traceglass C# 0.1.0 — native metadata-only inspection proxy (.NET 10)
        Usage:
          traceglass-csharp serve [flags]
          traceglass-csharp ca init [-data-dir DIR]
          traceglass-csharp help | version
        Serve flags (single or double dash):
          -listen 127.0.0.1:8080 -dashboard 127.0.0.1:9090 -data-dir ./data-csharp
          -inspect ''       comma-separated exact hosts or *.domain (empty means tunnel)
          -rules FILE       replaces embedded canonical classifier defaults
          -upstream-ca FILE additional trusted PEM roots; hostname verification remains enabled
          -max-records 1000000 -max-age 168h -queue-size 8192 -max-active 256
          -allow-private    explicitly permit private/local destinations for trusted test/dev clients
        CA initialization never installs system trust. Only inspect authorized traffic.
        """;
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "help" or "-h" or "--help" ||
                args.Skip(1).Any(a => a is "-h" or "--help"))
            { Console.WriteLine(Help); return 0; }
            if (args[0] == "version") { Console.WriteLine("traceglass-csharp 0.1.0"); return 0; }
            if (args[0] == "ca" && args.Length >= 2 && args[1] == "init")
            {
                var flags = Options.Flags(args[2..], "data-dir");
                var directory = flags.GetValueOrDefault("data-dir", "./data-csharp");
                Authority.Init(directory);
                Console.WriteLine($"Local CA created: {Path.Combine(directory, Authority.CertFile)}\nNo trust was installed.");
                return 0;
            }
            if (args[0] != "serve") throw new ArgumentException("Unknown command; run help");
            var options = Options.Parse(args[1..]);
            using var stopping = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; stopping.Cancel(); };
            using var sigterm = OperatingSystem.IsWindows() ? null :
                PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stopping.Cancel(); });
            using var ca = options.Scope.Patterns.Length == 0 ? null : new Authority(options.DataDir);
            var classifier = new Classifier(options.Rules);
            await using var store = new MetadataStore(Path.Combine(options.DataDir, "metadata-csharp.db"),
                options.MaxRecords, options.MaxAge, options.QueueSize);
            await using var proxy = new ProxyServer(Options.Endpoint(options.Listen), store, classifier,
                options.Scope, ca, options.AllowPrivate, options.MaxActive, options.UpstreamCa);
            proxy.Start();
            await using var dashboard = new Dashboard(options.Dashboard, store, proxy, options);
            await dashboard.Start(stopping.Token);
            Console.WriteLine($"Traceglass C# 0.1.0\nProxy: http://{proxy.Address}\nDashboard: http://{dashboard.Address}/#token={dashboard.Token}\nHTTPS inspection scope: [{string.Join(", ", options.Scope.Patterns)}]\nData: {options.DataDir}");
            if (options.AllowPrivate) Console.Error.WriteLine("WARNING: private-network destinations enabled; do not proxy untrusted clients");
            var signal = Task.Delay(Timeout.InfiniteTimeSpan, stopping.Token);
            var completed = await Task.WhenAny(signal, store.Failure, proxy.Completion);
            if (completed == store.Failure) throw new IOException("Fatal metadata writer failure", await store.Failure);
            if (completed == proxy.Completion) { await proxy.Completion; throw new IOException("Proxy listener stopped unexpectedly"); }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Traceglass stopped: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }
}
