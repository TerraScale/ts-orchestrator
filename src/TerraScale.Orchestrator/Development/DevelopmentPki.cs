using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentPki
{
    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PublicMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public static IReadOnlyDictionary<string, DevelopmentNatsTlsSecurity> Create(
        DevelopmentTopology topology,
        string dataDirectory)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }

        var root = Path.Combine(dataDirectory, "credentials", "pki");
        RecreatePrivateDirectory(root);
        using var controlRoot = CreateRoot("TerraScale DevHost control root");
        using var productRoot = CreateRoot("TerraScale DevHost product root");
        var result = new Dictionary<string, DevelopmentNatsTlsSecurity>(StringComparer.Ordinal);

        foreach (var cell in topology.Cells)
        {
            var cellRoot = Path.Combine(root, cell.Cell);
            RecreatePrivateDirectory(cellRoot);
            using var controlIntermediate = CreateIntermediate(controlRoot, $"TerraScale {cell.Cell} control issuer");
            using var productIntermediate = CreateIntermediate(productRoot, $"TerraScale {cell.Cell} product issuer");
            var control = CreatePlane(
                cell,
                DevelopmentResourceKind.ControlNats,
                "control",
                controlRoot,
                controlIntermediate,
                cell.OfKind(DevelopmentResourceKind.ControllerAgent)
                    .ToDictionary(
                        resource => resource.Name,
                        resource => (Role: "controller", Identity: resource.Name),
                        StringComparer.Ordinal)
                    .Append(new KeyValuePair<string, (string Role, string Identity)>(
                        "operator-read",
                        ("operator", "operator-read")))
                    .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
                cellRoot);
            var product = CreatePlane(
                cell,
                DevelopmentResourceKind.ProductNats,
                "product",
                productRoot,
                productIntermediate,
                cell.OfKind(DevelopmentResourceKind.Api)
                    .ToDictionary(
                        resource => resource.Name,
                        resource => (Role: "workload", Identity: resource.Name),
                        StringComparer.Ordinal),
                cellRoot);
            result.Add(cell.Cell, new DevelopmentNatsTlsSecurity(control, product));
        }

        return result;
    }

    private static DevelopmentNatsTlsPlane CreatePlane(
        DevelopmentCellPlan cell,
        DevelopmentResourceKind kind,
        string plane,
        X509Certificate2 root,
        X509Certificate2 intermediate,
        IReadOnlyDictionary<string, (string Role, string Identity)> clientIdentities,
        string cellRoot)
    {
        var planeRoot = Path.Combine(cellRoot, plane);
        RecreatePrivateDirectory(planeRoot);
        var caFile = Path.Combine(planeRoot, "ca.pem");
        WritePublic(caFile, root.ExportCertificatePem());
        WritePublic(Path.Combine(planeRoot, "intermediate.pem"), intermediate.ExportCertificatePem());

        var servers = new Dictionary<string, DevelopmentNatsServerTlsIdentity>(StringComparer.Ordinal);
        foreach (var server in cell.OfKind(kind))
        {
            var serverRoot = Path.Combine(planeRoot, "servers", server.Name);
            RecreatePrivateDirectory(serverRoot);
            servers.Add(server.Name, new DevelopmentNatsServerTlsIdentity(
                CreateLeaf(
                    intermediate,
                    caFile,
                    serverRoot,
                    "client",
                    $"spiffe://terrascale.tech/cell/{cell.Cell}/nats/{plane}/server/{server.Name}",
                    server.Name,
                    serverAuth: true,
                    clientAuth: false),
                CreateLeaf(
                    intermediate,
                    caFile,
                    serverRoot,
                    "route",
                    $"spiffe://terrascale.tech/cell/{cell.Cell}/nats/{plane}/route/{server.Name}",
                    server.Name,
                    serverAuth: true,
                    clientAuth: true)));
        }

        var clients = new Dictionary<string, DevelopmentTlsIdentity>(StringComparer.Ordinal);
        foreach (var (name, identity) in clientIdentities)
        {
            var clientRoot = Path.Combine(planeRoot, "clients", name);
            RecreatePrivateDirectory(clientRoot);
            clients.Add(name, CreateLeaf(
                intermediate,
                caFile,
                clientRoot,
                "identity",
                $"spiffe://terrascale.tech/cell/{cell.Cell}/{identity.Role}/{identity.Identity}",
                name,
                serverAuth: false,
                clientAuth: true));
        }
        return new DevelopmentNatsTlsPlane(servers, clients);
    }

    private static X509Certificate2 CreateRoot(string commonName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(commonName, key, certificateAuthority: true, serverAuth: false, clientAuth: false, null, null);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateIntermediate(X509Certificate2 root, string commonName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(commonName, key, certificateAuthority: true, serverAuth: false, clientAuth: false, null, null);
        using var certificate = request.Create(
            root,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            Serial());
        return certificate.CopyWithPrivateKey(key);
    }

    private static DevelopmentTlsIdentity CreateLeaf(
        X509Certificate2 issuer,
        string caFile,
        string directory,
        string filePrefix,
        string spiffeId,
        string dnsName,
        bool serverAuth,
        bool clientAuth)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(
            dnsName,
            key,
            certificateAuthority: false,
            serverAuth,
            clientAuth,
            spiffeId,
            dnsName);
        using var certificate = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(24),
            Serial());
        var certificateFile = Path.Combine(directory, $"{filePrefix}.pem");
        var keyFile = Path.Combine(directory, $"{filePrefix}.key.pem");
        WritePublic(
            certificateFile,
            certificate.ExportCertificatePem() + Environment.NewLine +
            issuer.ExportCertificatePem() + Environment.NewLine);
        WritePrivate(keyFile, key.ExportPkcs8PrivateKeyPem());
        return new DevelopmentTlsIdentity(certificateFile, keyFile, caFile, spiffeId);
    }

    private static CertificateRequest Request(
        string commonName,
        ECDsa key,
        bool certificateAuthority,
        bool serverAuth,
        bool clientAuth,
        string? spiffeId,
        string? dnsName)
    {
        var request = new CertificateRequest(
            $"CN={commonName}",
            key,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority,
            certificateAuthority,
            certificateAuthority ? 1 : 0,
            critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            certificateAuthority
                ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                : X509KeyUsageFlags.DigitalSignature,
            critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (!certificateAuthority)
        {
            var usages = new OidCollection();
            if (serverAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            if (clientAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
            var names = new SubjectAlternativeNameBuilder();
            names.AddUri(new Uri(spiffeId!, UriKind.Absolute));
            names.AddDnsName(dnsName!);
            names.AddDnsName("localhost");
            if (serverAuth) names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build(critical: false));
        }
        return request;
    }

    private static byte[] Serial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        if (serial.All(value => value == 0)) serial[^1] = 1;
        return serial;
    }

    private static void RecreatePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(path, DirectoryMode);
    }

    private static void WritePrivate(string path, string content)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }
        File.WriteAllText(path, content);
        File.SetUnixFileMode(path, PrivateMode);
    }

    private static void WritePublic(string path, string content)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }
        File.WriteAllText(path, content);
        File.SetUnixFileMode(path, PublicMode);
    }
}
