using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

internal sealed class HostCredentialMaterialFixture : IDisposable
{
    internal HostCredentialMaterialFixture(bool jwt = true, NatsAuthenticationFiles? authentication = null,
        NatsTlsFiles? tls = null, string? account = null, string? node = null, string certificateKind = "client",
        long? jwtExpires = null, long? jwtNotBefore = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Host credentials require Linux permissions.");
        Directory = System.IO.Directory.CreateTempSubdirectory("ts-host-material-");
        File.SetUnixFileMode(Directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var natsPath = Path.Combine(Directory.FullName, jwt ? "host.creds" : "host.nk");
        if (authentication is null)
        {
            var seed = NATS.Client.Core.NKeys.CreateUserSeed();
            Write(natsPath, jwt ? NatsAuthenticationFilesTests.Credentials(seed, jwtExpires, jwtNotBefore) : seed);
        }
        else Write(natsPath, File.ReadAllText(authentication.CredentialsFile ?? authentication.NKeyFile!));
        Authentication = NatsAuthenticationFiles.Resolve(jwt ? null : natsPath, jwt ? natsPath : null, "fixture")!;
        Tls = new(Path.Combine(Directory.FullName, "ca.pem"), Path.Combine(Directory.FullName, "client.pem"), Path.Combine(Directory.FullName, "client.key"));
        var now = DateTimeOffset.UtcNow;
        if (tls is not null)
        {
            Write(Tls.CaFile, File.ReadAllText(tls.CaFile));
            Write(Tls.CertificateFile, File.ReadAllText(tls.CertificateFile));
            Write(Tls.KeyFile, File.ReadAllText(tls.KeyFile));
        }
        else
        {
            using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootRequest = new CertificateRequest("CN=host-fixture-root", caKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using var root = rootRequest.CreateSelfSigned(now.AddDays(-1), certificateKind == "short-ca" ? now.AddMinutes(30) : now.AddHours(2));
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=host-fixture-client", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateKind == "ca", false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(certificateKind == "wrong-usage"
                ? X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature, true));
            if (certificateKind != "no-eku") request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new(certificateKind == "server" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
            using var cert = request.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey),
                certificateKind == "future" ? now.AddMinutes(1) : now.AddHours(-1),
                certificateKind == "expired" ? now.AddMinutes(-1) : now.AddHours(1), RandomNumberGenerator.GetBytes(16));
            Write(Tls.CaFile, root.ExportCertificatePem());
            Write(Tls.CertificateFile, cert.ExportCertificatePem());
            Write(Tls.KeyFile, key.ExportPkcs8PrivateKeyPem());
        }
        Session = new(Authentication, account, node, realTime: true);
        Configuration = Bind();
    }

    internal DirectoryInfo Directory { get; }
    internal SessionMaterial Session { get; }
    internal NatsAuthenticationFiles Authentication { get; }
    internal NatsTlsFiles Tls { get; }
    internal RegionalHostAdmissionConfiguration Configuration { get; private set; }
    internal string[] CredentialPaths => [Authentication.CredentialsFile ?? Authentication.NKeyFile!, Tls.CaFile, Tls.CertificateFile, Tls.KeyFile];

    internal RegionalHostCredentialMaterial Load(TimeProvider? clock = null) =>
        RegionalHostCredentialMaterial.Load(Configuration, Authentication, Tls, clock);

    internal RegionalHostAdmissionConfiguration Bind(string? manifest = null, BootstrapCertificateFingerprint? fingerprint = null)
    {
        var bundlePath = Path.Combine(Directory.FullName, "bundle.json");
        manifest ??= JsonSerializer.Serialize(new { schemaVersion = 1, files = CredentialPaths.Select(path =>
            new { path, sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))) }).ToArray() });
        Write(bundlePath, manifest);
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(Tls.CertificateFile);
        var enrollment = Session.Enroll(1, credentialBundleSha256: Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(bundlePath))),
            certificateFingerprint: fingerprint ?? BootstrapWorkloadIdentity.CertificateFingerprint(certificate.PublicKey.ExportSubjectPublicKeyInfo()));
        return Configuration = Session.WriteHostConfiguration(Directory.FullName, enrollment, bundlePath);
    }

    internal static void Write(string path, string text)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Host credentials require Linux permissions.");
        File.WriteAllText(path, text);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public void Dispose() { Session.Dispose(); Directory.Delete(recursive: true); }
}
