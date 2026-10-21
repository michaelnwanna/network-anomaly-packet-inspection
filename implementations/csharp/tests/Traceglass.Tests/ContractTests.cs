using System.Text.Json;
using Traceglass;
using Xunit;

namespace Traceglass.Tests;

public sealed class ContractTests
{
    [Fact]
    public void SharedClassificationContract()
    {
        using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "classification.json")));
        var root = fixture.RootElement;
        var path = Path.Combine(Path.GetTempPath(), "traceglass-rules-" + Guid.NewGuid() + ".json");
        try
        {
            File.WriteAllText(path, root.GetProperty("rules").GetRawText());
            var classifier = new Classifier(path);
            foreach (var item in root.GetProperty("classifications").EnumerateArray())
                Assert.Equal(item.GetProperty("flags").Deserialize<string[]>(), classifier.Flags(
                    item.GetProperty("host").GetString()!, item.GetProperty("port").GetInt32(),
                    item.GetProperty("sent").GetInt64(), item.GetProperty("received").GetInt64()));
            var scope = new InspectionScope(root.GetProperty("inspection_scope").GetString()!);
            foreach (var item in root.GetProperty("inspection_matches").EnumerateArray())
                Assert.Equal(item.GetProperty("matches").GetBoolean(), scope.Matches(item.GetProperty("host").GetString()!));
            foreach (var item in root.GetProperty("invalid_scopes").EnumerateArray())
                Assert.Throws<ArgumentException>(() => new InspectionScope(item.GetString()!));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task StoreRetainsNewestAndLocksWriterAndReopens()
    {
        var directory = Path.Combine(Path.GetTempPath(), "traceglass-store-" + Guid.NewGuid());
        var path = Path.Combine(directory, "metadata.db");
        try
        {
            await using (var store = new MetadataStore(path, 2, TimeSpan.FromHours(1), 32))
            {
                Assert.Throws<IOException>(() => new MetadataStore(path, 2, TimeSpan.FromHours(1), 32));
                for (var i = 0; i < 7; i++)
                    Assert.True(store.Enqueue(new Flow { Host = $"h{i}.example", RequestBytes = i,
                        ResponseBytes = i * 2, Flags = i % 2 == 0 ? ["known-tracker"] : [] }));
                await store.DisposeAsync();
                await store.DisposeAsync();
                Assert.Equal(2, store.Stats().Records);
                Assert.Equal(1, store.Stats().Flagged);
                Assert.Equal(11, store.Stats().RequestBytes);
                Assert.Equal(22, store.Stats().ResponseBytes);
                Assert.Equal(["h6.example", "h5.example"], store.List().Select(r => r.Host));
                Assert.Throws<ArgumentException>(() => store.List(limit: 201));
            }
            await using var reopened = new MetadataStore(path, 2, TimeSpan.FromHours(1), 32);
            Assert.Equal(2, reopened.Stats().Records);
            Assert.Single(reopened.List(flagged: true));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task StorePrunesAgeAndSurvivesSaturation()
    {
        var directory = Path.Combine(Path.GetTempPath(), "traceglass-age-" + Guid.NewGuid());
        try
        {
            await using var store = new MetadataStore(Path.Combine(directory, "metadata.db"), 10, TimeSpan.FromMinutes(1), 1);
            store.Enqueue(new Flow { Timestamp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds() });
            for (var i = 0; i < 10_000; i++) store.Enqueue(new Flow { Host = "current.test" });
            await store.DisposeAsync();
            Assert.InRange(store.Stats().Records, 1, 10);
            Assert.True(store.Dropped > 0);
            Assert.All(store.List(), row => Assert.Equal("current.test", row.Host));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void CertificateHandlesHaveIndependentLifetimes()
    {
        var directory = Path.Combine(Path.GetTempPath(), "traceglass-ca-" + Guid.NewGuid());
        try
        {
            Authority.Init(directory);
            Assert.Throws<IOException>(() => Authority.Init(directory));
            using var ca = new Authority(directory);
            using (var first = ca.Certificate("example.test")) Assert.True(first.HasPrivateKey);
            using var second = ca.Certificate("example.test");
            Assert.True(second.HasPrivateKey);
            Assert.True(second.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(2));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
