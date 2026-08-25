using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentPki
{
    // DevHost mints regional mTLS material at generation start. Continuous labs may
    // outlive a single leaf NotAfter; without remint, health-driven restarts keep
    // loading expired PEMs and every NATS handshake fails. Leaves therefore use a
    // multi-week lifetime, and the lab remints when remaining validity drops below
    // one-third of LeafLifetime (production-style renewal lead time). Intermediate
    // lifetime strictly outlives leaf lifetime so chain creation cannot fail when
    // wall-clock advances between issuer and leaf issuance. Full dual-bundle issuer
    // rotation remains a production qualification gate; remint rewrites the whole
    // regional tree onto stable PEM paths and restarts TLS consumers.
    internal static readonly TimeSpan RootLifetime = TimeSpan.FromDays(365);
    internal static readonly TimeSpan IntermediateLifetime = TimeSpan.FromDays(90);
    internal static readonly TimeSpan LeafLifetime = TimeSpan.FromDays(30);
    // Renew when less than one-third of the leaf lifetime remains.
    internal static readonly TimeSpan LeafRenewalLeadTime = TimeSpan.FromTicks(LeafLifetime.Ticks / 3);
    private static readonly TimeSpan NotBeforeSkew = TimeSpan.FromMinutes(5);

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

        // Mint into a staging tree, then swap onto the stable PEM paths. A non-atomic
        // wipe of credentials/pki mid-remint leaves operator-read (and every other
        // leaf) missing for concurrent NATS handshakes, which surfaces as the same
        // continuous-lab TLS failure mode as expiry.
        var root = Path.Combine(dataDirectory, "credentials", "pki");
        var credentialsRoot = Path.Combine(dataDirectory, "credentials");
        Directory.CreateDirectory(credentialsRoot);
        var staging = Path.Combine(
            credentialsRoot,
            $".pki-staging-{Environment.ProcessId}-{Guid.NewGuid():N}");
        var retired = Path.Combine(
            credentialsRoot,
            $".pki-retired-{Environment.ProcessId}-{Guid.NewGuid():N}");
        try
        {
            RecreatePrivateDirectory(staging);
            // One issuance clock for the whole mint so every cert shares the same
            // notBefore baseline; IntermediateLifetime strictly exceeds LeafLifetime.
            var issuedAt = DateTimeOffset.UtcNow;
            using var controlRoot = CreateRoot("TerraScale DevHost control root", issuedAt);
            using var productRoot = CreateRoot("TerraScale DevHost product root", issuedAt);
            var result = new Dictionary<string, DevelopmentNatsTlsSecurity>(StringComparer.Ordinal);

            foreach (var cell in topology.Cells)
            {
                var cellRoot = Path.Combine(staging, cell.Cell);
                RecreatePrivateDirectory(cellRoot);
                using var controlIntermediate = CreateIntermediate(
                    controlRoot,
                    $"TerraScale {cell.Cell} control issuer",
                    issuedAt);
                using var productIntermediate = CreateIntermediate(
                    productRoot,
                    $"TerraScale {cell.Cell} product issuer",
                    issuedAt);
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
                    cellRoot,
                    issuedAt);
                var product = CreatePlane(
                    cell,
                    DevelopmentResourceKind.ProductNats,
                    "product",
                    productRoot,
                    productIntermediate,
                    cell.OfKind(DevelopmentResourceKind.Platform)
                        .ToDictionary(
                            resource => resource.Name,
                            resource => (Role: "workload", Identity: resource.Name),
                            StringComparer.Ordinal),
                    cellRoot,
                    issuedAt);
                // Rewrite identity paths from staging to the stable published root so
                // callers keep using credentials/pki/... after the atomic swap.
                result.Add(
                    cell.Cell,
                    RelocateTlsSecurity(new DevelopmentNatsTlsSecurity(control, product), staging, root));
            }

            PublishPkiTree(staging, root, retired);
            return result;
        }
        finally
        {
            // PublishPkiTree removes staging on success and restores root on failure.
            // Only clean leftovers that are no longer the live credentials/pki tree.
            if (Directory.Exists(staging) &&
                !string.Equals(
                    Path.GetFullPath(staging),
                    Path.GetFullPath(root),
                    StringComparison.Ordinal))
            {
                Directory.Delete(staging, recursive: true);
            }
            if (Directory.Exists(retired))
            {
                Directory.Delete(retired, recursive: true);
            }
        }
    }

    /// <summary>
    /// Returns true when any on-disk leaf is missing, unreadable, already expired, or
    /// within <see cref="LeafRenewalLeadTime"/> of NotAfter. Callers that remint must
    /// also restart processes that loaded the previous PEMs into memory.
    /// </summary>
    internal static bool LeavesNeedRemint(string dataDirectory, DateTimeOffset utcNow)
    {
        var survey = SurveyLeaves(dataDirectory);
        if (survey.UnreadableLeaves)
        {
            return true;
        }
        if (survey.EarliestNotAfter is not { } earliestNotAfter)
        {
            return true;
        }

        return earliestNotAfter <= utcNow + LeafRenewalLeadTime;
    }

    /// <summary>
    /// Remints the full regional PKI when <see cref="LeavesNeedRemint"/> is true.
    /// PEM paths are stable; NKey and product password material is left untouched.
    /// Intermediate private keys are not persisted, so remint rewrites the whole
    /// trust tree (roots, intermediates, and leaves) onto the same paths.
    /// </summary>
    internal static bool RemintLeavesIfNeeded(
        DevelopmentTopology topology,
        string dataDirectory,
        DateTimeOffset utcNow)
    {
        if (!LeavesNeedRemint(dataDirectory, utcNow))
        {
            return false;
        }

        Create(topology, dataDirectory);
        return true;
    }

    internal static DateTimeOffset? TryGetEarliestLeafNotAfter(string dataDirectory) =>
        SurveyLeaves(dataDirectory).EarliestNotAfter;

    private static LeafSurvey SurveyLeaves(string dataDirectory)
    {
        var root = Path.Combine(dataDirectory, "credentials", "pki");
        if (!Directory.Exists(root))
        {
            return new LeafSurvey(EarliestNotAfter: null, UnreadableLeaves: false);
        }

        DateTimeOffset? earliest = null;
        var sawLeaf = false;
        var unreadable = false;
        foreach (var path in Directory.EnumerateFiles(root, "*.pem", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(path);
            if (name.EndsWith(".key.pem", StringComparison.Ordinal) || name is "ca.pem")
            {
                continue;
            }

            // Survey leaves and intermediate.pem. Intermediate private keys are not
            // persisted, so an intermediate that ages out with (or before) its leaves
            // still requires a full tree remint; skipping it would miss that window.
            sawLeaf = true;
            try
            {
                // Leaf PEMs are written as leaf + intermediate; CreateFromPem takes the first cert.
                using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(path));
                // NotAfter is local DateTime on some runtimes; normalize to UTC offset.
                var notAfter = new DateTimeOffset(
                    DateTime.SpecifyKind(certificate.NotAfter.ToUniversalTime(), DateTimeKind.Utc));
                if (earliest is not { } currentEarliest || notAfter < currentEarliest)
                {
                    earliest = notAfter;
                }
            }
            catch (Exception exception) when (
                exception is CryptographicException or ArgumentException or IOException)
            {
                // A single corrupt leaf still breaks its NATS identity; force remint.
                unreadable = true;
            }
        }

        if (!sawLeaf)
        {
            return new LeafSurvey(EarliestNotAfter: null, UnreadableLeaves: false);
        }

        return new LeafSurvey(earliest, unreadable);
    }

    private readonly record struct LeafSurvey(DateTimeOffset? EarliestNotAfter, bool UnreadableLeaves);

    private static void PublishPkiTree(string staging, string root, string retired)
    {
        if (Directory.Exists(retired))
        {
            Directory.Delete(retired, recursive: true);
        }

        var hadPrevious = Directory.Exists(root);
        if (hadPrevious)
        {
            Directory.Move(root, retired);
        }

        try
        {
            Directory.Move(staging, root);
        }
        catch
        {
            // Restore the previous tree if the publish rename fails so callers keep
            // whatever mTLS material was last known good.
            if (hadPrevious && !Directory.Exists(root) && Directory.Exists(retired))
            {
                Directory.Move(retired, root);
            }
            throw;
        }
    }

    private static DevelopmentNatsTlsSecurity RelocateTlsSecurity(
        DevelopmentNatsTlsSecurity security,
        string fromRoot,
        string toRoot)
    {
        return new DevelopmentNatsTlsSecurity(
            RelocatePlane(security.Control, fromRoot, toRoot),
            RelocatePlane(security.Product, fromRoot, toRoot));
    }

    private static DevelopmentNatsTlsPlane RelocatePlane(
        DevelopmentNatsTlsPlane plane,
        string fromRoot,
        string toRoot)
    {
        var servers = plane.Servers.ToDictionary(
            pair => pair.Key,
            pair => new DevelopmentNatsServerTlsIdentity(
                RelocateIdentity(pair.Value.Client, fromRoot, toRoot),
                RelocateIdentity(pair.Value.Route, fromRoot, toRoot)),
            StringComparer.Ordinal);
        var clients = plane.Clients.ToDictionary(
            pair => pair.Key,
            pair => RelocateIdentity(pair.Value, fromRoot, toRoot),
            StringComparer.Ordinal);
        return new DevelopmentNatsTlsPlane(servers, clients);
    }

    private static DevelopmentTlsIdentity RelocateIdentity(
        DevelopmentTlsIdentity identity,
        string fromRoot,
        string toRoot)
    {
        return new DevelopmentTlsIdentity(
            RelocatePath(identity.CertificateFile, fromRoot, toRoot),
            RelocatePath(identity.KeyFile, fromRoot, toRoot),
            RelocatePath(identity.CaFile, fromRoot, toRoot),
            identity.SpiffeId);
    }

    private static string RelocatePath(string path, string fromRoot, string toRoot)
    {
        var full = Path.GetFullPath(path);
        var from = Path.GetFullPath(fromRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!full.StartsWith(from + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
            !string.Equals(full, from, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Development PKI path '{path}' is outside staging root '{fromRoot}'.");
        }

        var relative = full[from.Length..].TrimStart(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);
        return Path.Combine(toRoot, relative);
    }

    private static DevelopmentNatsTlsPlane CreatePlane(
        DevelopmentCellPlan cell,
        DevelopmentResourceKind kind,
        string plane,
        X509Certificate2 root,
        X509Certificate2 intermediate,
        IReadOnlyDictionary<string, (string Role, string Identity)> clientIdentities,
        string cellRoot,
        DateTimeOffset issuedAt)
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
                    clientAuth: false,
                    issuedAt),
                CreateLeaf(
                    intermediate,
                    caFile,
                    serverRoot,
                    "route",
                    $"spiffe://terrascale.tech/cell/{cell.Cell}/nats/{plane}/route/{server.Name}",
                    server.Name,
                    serverAuth: true,
                    clientAuth: true,
                    issuedAt)));
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
                clientAuth: true,
                issuedAt));
        }
        return new DevelopmentNatsTlsPlane(servers, clients);
    }

    private static X509Certificate2 CreateRoot(string commonName, DateTimeOffset issuedAt)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(commonName, key, certificateAuthority: true, serverAuth: false, clientAuth: false, null, null);
        var notBefore = issuedAt - NotBeforeSkew;
        return request.CreateSelfSigned(notBefore, notBefore + RootLifetime);
    }

    private static X509Certificate2 CreateIntermediate(
        X509Certificate2 root,
        string commonName,
        DateTimeOffset issuedAt)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(commonName, key, certificateAuthority: true, serverAuth: false, clientAuth: false, null, null);
        var notBefore = issuedAt - NotBeforeSkew;
        using var certificate = request.Create(
            root,
            notBefore,
            notBefore + IntermediateLifetime,
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
        bool clientAuth,
        DateTimeOffset issuedAt)
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
        var notBefore = issuedAt - NotBeforeSkew;
        using var certificate = request.Create(
            issuer,
            notBefore,
            notBefore + LeafLifetime,
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
            if (string.IsNullOrWhiteSpace(spiffeId) || string.IsNullOrWhiteSpace(dnsName))
            {
                throw new InvalidOperationException(
                    "A development leaf certificate requires both a SPIFFE ID and a DNS name.");
            }
            var usages = new OidCollection();
            if (serverAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            if (clientAuth) usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
            var names = new SubjectAlternativeNameBuilder();
            names.AddUri(new Uri(spiffeId, UriKind.Absolute));
            names.AddDnsName(dnsName);
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
        WriteAtomically(path, content, PrivateMode);
    }

    private static void WritePublic(string path, string content)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }
        WriteAtomically(path, content, PublicMode);
    }

    private static void WriteAtomically(string path, string content, UnixFileMode mode)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The Orchestrator development PKI requires Linux.");
        }

        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException($"Certificate path '{path}' has no directory.");
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temporary, content);
            File.SetUnixFileMode(temporary, mode);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
