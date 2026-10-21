using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Traceglass;

public sealed record Rules(
    [property: JsonPropertyName("tracking_domains")] string[] TrackingDomains,
    [property: JsonPropertyName("allowed_ports")] int[] AllowedPorts,
    [property: JsonPropertyName("large_payload_bytes")] long LargePayloadBytes);

public sealed class Classifier
{
    private readonly Rules rules;
    public Classifier(string? filename = null)
    {
        using var stream = filename is null
            ? typeof(Classifier).Assembly.GetManifestResourceStream("Traceglass.defaults.json")!
            : File.OpenRead(filename);
        if (stream.Length > 1 << 20) throw new ArgumentException("Rules exceed 1 MiB");
        rules = JsonSerializer.Deserialize<Rules>(stream, new JsonSerializerOptions
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        }) ?? throw new ArgumentException("Missing rules");
        if (rules.TrackingDomains is null || rules.AllowedPorts is null ||
            rules.LargePayloadBytes <= 0 || rules.AllowedPorts.Length == 0 ||
            rules.AllowedPorts.Any(p => p is < 1 or > 65535))
            throw new ArgumentException("Invalid classifier rules");
        rules = rules with { TrackingDomains = rules.TrackingDomains.Select(Normalize).ToArray() };
        if (rules.TrackingDomains.Any(d => !ValidDomain(d)))
            throw new ArgumentException("Invalid tracking domain");
    }

    public static string Normalize(string host) => host.ToLowerInvariant().TrimEndSingleDot();
    public static bool ValidDomain(string host) => host.Length is > 0 and <= 253 &&
        !IPAddress.TryParse(host, out _) && host.Split('.').All(label => label.Length is > 0 and <= 63 &&
        label[0] != '-' && label[^1] != '-' && label.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'));
    public string[] Flags(string host, int port, long sent, long received)
    {
        host = Normalize(host);
        List<string> flags = [];
        if (rules.TrackingDomains.Any(d => host == d || host.EndsWith("." + d, StringComparison.Ordinal)))
            flags.Add("known-tracker");
        if (sent > rules.LargePayloadBytes || received > rules.LargePayloadBytes - sent)
            flags.Add("large-payload");
        if (!rules.AllowedPorts.Contains(port)) flags.Add("unsanctioned-port");
        return [.. flags];
    }
}

internal static class HostExtensions
{
    public static string TrimEndSingleDot(this string value) => value.EndsWith('.') ? value[..^1] : value;
}

public sealed class InspectionScope
{
    public string[] Patterns { get; }
    public InspectionScope(string value)
    {
        Patterns = value.Length == 0 ? [] : value.Split(',').Select(s => Classifier.Normalize(s.Trim())).ToArray();
        foreach (var pattern in Patterns)
        {
            var domain = pattern.StartsWith("*.", StringComparison.Ordinal) ? pattern[2..] : pattern;
            if (!Classifier.ValidDomain(domain) && !(domain == pattern && IPAddress.TryParse(domain, out _)))
                throw new ArgumentException("Invalid inspection scope");
        }
    }
    public bool Matches(string host)
    {
        host = Classifier.Normalize(host);
        return Patterns.Any(p => host == p || p.StartsWith("*.", StringComparison.Ordinal) &&
            host.EndsWith(p[1..], StringComparison.Ordinal));
    }
}
