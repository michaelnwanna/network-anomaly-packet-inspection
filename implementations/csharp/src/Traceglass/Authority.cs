using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Traceglass;

public sealed class Authority : IDisposable
{
    public const string CertFile = "traceglass-ca.crt";
    public const string KeyFile = "traceglass-ca.key";
    private readonly X509Certificate2 root;
    private readonly Dictionary<string, X509Certificate2> certificates = [];
    private readonly object gate = new();

    public static void Init(string directory)
    {
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var certPath = Path.Combine(directory, CertFile);
        var keyPath = Path.Combine(directory, KeyFile);
        if (File.Exists(certPath) || File.Exists(keyPath)) throw new IOException("CA already exists; refusing overwrite");
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Traceglass CSharp Local CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(2));
        WriteNew(keyPath, key.ExportPkcs8PrivateKeyPem(), true);
        WriteNew(certPath, cert.ExportCertificatePem(), false);
    }

    private static void WriteNew(string path, string text, bool secret)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = secret
            ? UnixFileMode.UserRead | UnixFileMode.UserWrite
            : UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        using var stream = new FileStream(path, options);
        using var writer = new StreamWriter(stream);
        writer.Write(text);
    }

    public Authority(string directory)
    {
        var keyPath = Path.Combine(directory, KeyFile);
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(keyPath) &
            (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite)) != 0)
            throw new IOException("CA private key permissions must be owner-only");
        root = X509Certificate2.CreateFromPemFile(Path.Combine(directory, CertFile), keyPath);
        if (!root.HasPrivateKey || root.NotBefore.ToUniversalTime() > DateTime.UtcNow || root.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddMinutes(1) ||
            !root.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority))
            throw new IOException("Invalid or expired inspection CA");
    }

    public X509Certificate2 Certificate(string host)
    {
        lock (gate)
        {
            if (certificates.TryGetValue(host, out var existing))
            {
                if (existing.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddMinutes(1)) return new X509Certificate2(existing);
                certificates.Remove(host);
                existing.Dispose();
            }
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Traceglass inspected host", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            if (IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip); else san.AddDnsName(host);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
            var end = DateTimeOffset.UtcNow.AddDays(1);
            if (end > root.NotAfter) end = root.NotAfter;
            using var leaf = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-5), end, RandomNumberGenerator.GetBytes(16));
            var result = leaf.CopyWithPrivateKey(key);
            // Stop caching at a fixed bound; callers own uncached certificates.
            if (certificates.Count < 256) certificates.Add(host, new X509Certificate2(result));
            return result;
        }
    }
    public void Dispose()
    {
        lock (gate) { foreach (var cert in certificates.Values) cert.Dispose(); certificates.Clear(); root.Dispose(); }
    }
}
