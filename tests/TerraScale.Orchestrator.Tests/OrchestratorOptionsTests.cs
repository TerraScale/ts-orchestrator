namespace TerraScale.Orchestrator.Tests;

public sealed class OrchestratorOptionsTests
{
    [Test]
    public async Task CatalogCommandIsReadOnlyAndRejectsArguments()
    {
        var options = OrchestratorOptions.Parse(["catalog"], _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Catalog);
        await Assert.That(() => OrchestratorOptions.Parse(["catalog", "extra"], _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ParsesLabPlanWithoutDeploymentEvidence()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--workspace", "/tmp/workspace", "--data-directory", "/tmp/data", "--profile", "regional"],
            _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Lab);
        await Assert.That(options.LabCommand).IsEqualTo(OrchestratorLabCommand.Plan);
        await Assert.That(options.WorkspaceRoot).IsEqualTo("/tmp/workspace");
        await Assert.That(options.DataDirectory).IsEqualTo("/tmp/data/profiles/regional");
        await Assert.That(options.LabProfile).IsEqualTo(OrchestratorLabProfile.Regional);
    }

    [Test]
    public async Task ParsesControlPlaneContainerProfile()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--profile", "control"],
            _ => null);

        await Assert.That(options.LabProfile)
            .IsEqualTo(OrchestratorLabProfile.Control);
    }

    [Test]
    public async Task ProfilesUseSeparatePersistentDataDirectories()
    {
        var quick = OrchestratorOptions.Parse(
            ["lab", "plan", "--data-directory", "/tmp/data", "--profile", "quick"],
            _ => null);
        var regional = OrchestratorOptions.Parse(
            ["lab", "plan", "--data-directory", "/tmp/data", "--profile", "regional"],
            _ => null);

        await Assert.That(quick.DataDirectory).IsEqualTo("/tmp/data/profiles/quick");
        await Assert.That(regional.DataDirectory).IsEqualTo("/tmp/data/profiles/regional");
        await Assert.That(quick.StateFile).IsEqualTo(regional.StateFile);
    }

    [Test]
    public async Task RejectsUnknownAndDuplicateLabOptions()
    {
        await Assert.That(() => OrchestratorOptions.Parse(["lab", "plan", "--wat"], _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["lab", "plan", "--workspace", "/one", "--workspace", "/two"],
                _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task LabUpFailsClosedWithoutEvidence()
    {
        var options = OrchestratorOptions.Parse(["lab", "up"], _ => null);

        var exception = await Assert.That(async () =>
                await Development.DevelopmentLab.ExecuteAsync(options, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(exception!.Message).Contains("--evidence");
    }

    [Test]
    public async Task ParsesAndValidatesStableControllerInstance()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["TS_ORCH_INSTANCE"] = "controller-2"
        };

        var options = OrchestratorOptions.Parse(["check"], name => values.GetValueOrDefault(name));

        await Assert.That(options.Instance).IsEqualTo("controller-2");
        await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_INSTANCE" ? "Controller/2" : null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task RunRequiresAuthenticatedTlsRegionalControlNats()
    {
        await Assert.That(() => OrchestratorOptions.Parse(["run"], _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ProvisionJournalRequiresTheSeparateInfrastructureIdentity()
    {
        await Assert.That(() => OrchestratorOptions.Parse(["provision-journal"], _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task JournalWriterHostingFailsClosedForPartialAuthorityConfiguration()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-authority-{Guid.NewGuid():N}.pem");
        try
        {
            using var authority = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(path, authority.ExportSubjectPublicKeyInfoPem());
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["journal-writer"],
                    name => name == "TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE" ? path : null))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task ControllerAndJournalWriterRolesRejectEachOthersCredentialMounts()
    {
        var controller = await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_JOURNAL_NATS_NKEY_FILE" ? "/unmounted/writer.nk" : null))
            .Throws<ArgumentException>();
        await Assert.That(controller!.Message).Contains("Controller roles must not receive journal-writer");

        var writer = await Assert.That(() => OrchestratorOptions.Parse(
                ["journal-writer"],
                name => name == "TS_ORCH_NATS_NKEY_FILE" ? "/unmounted/controller.nk" : null))
            .Throws<ArgumentException>();
        await Assert.That(writer!.Message).Contains("journal-writer role must not receive controller");
    }

    [Test]
    public async Task JournalWriterRoleLoadsOnlyWriterCredentialConfiguration()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-role-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var writerTlsKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var authorityKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var replyKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var writerTls = await WriteCertificateAsync(directory, "writer", writerTlsKey, isAuthority: true);
            var nkey = Path.Combine(directory, "writer.nk");
            var authority = Path.Combine(directory, "authority.pem");
            var reply = Path.Combine(directory, "reply.pem");
            await File.WriteAllTextAsync(nkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(authority, authorityKey.ExportSubjectPublicKeyInfoPem());
            await File.WriteAllTextAsync(reply, replyKey.ExportPkcs8PrivateKeyPem());
            foreach (var path in new[] { nkey, reply }) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_CELL"] = "gru",
                ["TS_ORCH_REPLICAS"] = "3",
                ["TS_ORCH_NATS_URL"] = "tls://control.example:4222",
                ["TS_ORCH_JOURNAL_NATS_NKEY_FILE"] = nkey,
                ["TS_ORCH_JOURNAL_NATS_TLS_CA_FILE"] = writerTls.Certificate,
                ["TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE"] = writerTls.Certificate,
                ["TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE"] = writerTls.PrivateKey,
                ["TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE"] = authority,
                ["TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"] = reply,
                ["TS_ORCH_JOURNAL_CONTROLLER_NKEYS"] = NATS.Client.Core.NKeys.PublicKeyFromSeed(File.ReadAllText(nkey)),
            };

            var options = OrchestratorOptions.Parse(["journal-writer"], values.GetValueOrDefault);
            await Assert.That(options.NatsNKeyFile).IsNull();
            await Assert.That(options.NatsTls).IsNull();
            await Assert.That(options.AuthoritativeJournal).IsNotNull();
            await Assert.That(options.AuthoritativeJournal!.NKeyFile).IsEqualTo(nkey);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task JournalAuthorityKeyCannotReuseWriterTlsIdentity()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-identity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var tlsKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=journal-writer", tlsKey, System.Security.Cryptography.HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            using var replyKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var nkey = Path.Combine(directory, "writer.nk");
            var ca = Path.Combine(directory, "ca.pem");
            var cert = Path.Combine(directory, "writer.pem");
            var tlsPrivate = Path.Combine(directory, "writer-key.pem");
            var authority = Path.Combine(directory, "authority.pem");
            var reply = Path.Combine(directory, "reply.pem");
            await File.WriteAllTextAsync(nkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(ca, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(cert, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(tlsPrivate, tlsKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(authority, tlsKey.ExportSubjectPublicKeyInfoPem());
            await File.WriteAllTextAsync(reply, replyKey.ExportPkcs8PrivateKeyPem());
            foreach (var path in new[] { nkey, tlsPrivate, reply }) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            await Assert.That(() => Messaging.NatsAuthoritativeJournalConfiguration.Resolve(
                    nkey, ca, cert, tlsPrivate, authority, reply, NATS.Client.Core.NKeys.PublicKeyFromSeed(File.ReadAllText(nkey))))
                .Throws<ArgumentException>();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task TlsIdentityComparisonRejectsDistinctCertificatesWithTheSameKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-tls-identity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var first = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=first", key, System.Security.Cryptography.HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            using var second = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=second", key, System.Security.Cryptography.HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var firstPath = Path.Combine(directory, "first.pem");
            var secondPath = Path.Combine(directory, "second.pem");
            await File.WriteAllTextAsync(firstPath, first.ExportCertificatePem());
            await File.WriteAllTextAsync(secondPath, second.ExportCertificatePem());

            await Assert.That(new Messaging.NatsTlsFiles(firstPath, firstPath, firstPath)
                .SameIdentity(new Messaging.NatsTlsFiles(secondPath, secondPath, secondPath))).IsTrue();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task JournalProvisioningRejectsControllerReplyAndIndependentWriterIdentityCollisions()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-reply-identity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var controllerKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var writerKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var infrastructureKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var authorityKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var safeReplyKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var controllerCa = await WriteCertificateAsync(directory, "controller-ca", controllerKey, isAuthority: true);
            var controllerRenewed = await WriteCertificateAsync(directory, "controller-renewed", controllerKey, isAuthority: false);
            var writer = await WriteCertificateAsync(directory, "writer", writerKey, isAuthority: true);
            var infrastructure = await WriteCertificateAsync(directory, "infrastructure", infrastructureKey, isAuthority: true);
            var controllerNkey = Path.Combine(directory, "controller.nk");
            var writerNkey = Path.Combine(directory, "writer.nk");
            var distinctControllerNkey = Path.Combine(directory, "distinct-controller.nk");
            var infrastructureNkey = Path.Combine(directory, "infrastructure.nk");
            var authority = Path.Combine(directory, "authority.pem");
            var safeReply = Path.Combine(directory, "safe-reply.pem");
            await File.WriteAllTextAsync(controllerNkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(writerNkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(distinctControllerNkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(infrastructureNkey, NATS.Client.Core.NKeys.CreateUserSeed());
            await File.WriteAllTextAsync(authority, authorityKey.ExportSubjectPublicKeyInfoPem());
            await File.WriteAllTextAsync(safeReply, safeReplyKey.ExportPkcs8PrivateKeyPem());
            foreach (var path in new[] { controllerNkey, writerNkey, distinctControllerNkey, infrastructureNkey, safeReply }) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_CELL"] = "gru",
                ["TS_ORCH_REPLICAS"] = "3",
                ["TS_ORCH_NATS_URL"] = "tls://control.example:4222",
                ["TS_ORCH_NATS_NKEY_FILE"] = controllerNkey,
                ["TS_ORCH_NATS_TLS_CA_FILE"] = controllerCa.Certificate,
                ["TS_ORCH_NATS_TLS_CERT_FILE"] = controllerRenewed.Certificate,
                ["TS_ORCH_NATS_TLS_KEY_FILE"] = controllerRenewed.PrivateKey,
                ["TS_ORCH_JOURNAL_NATS_NKEY_FILE"] = writerNkey,
                ["TS_ORCH_JOURNAL_NATS_TLS_CA_FILE"] = writer.Certificate,
                ["TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE"] = writer.Certificate,
                ["TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE"] = writer.PrivateKey,
                ["TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE"] = authority,
                ["TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"] = controllerRenewed.PrivateKey,
                ["TS_ORCH_JOURNAL_CONTROLLER_NKEYS"] = NATS.Client.Core.NKeys.PublicKeyFromSeed(File.ReadAllText(controllerNkey)),
            };
            await Assert.That(() => OrchestratorOptions.Parse(["check"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
            values["TS_ORCH_INFRA_NATS_NKEY_FILE"] = infrastructureNkey;
            values["TS_ORCH_INFRA_NATS_TLS_CA_FILE"] = infrastructure.Certificate;
            values["TS_ORCH_INFRA_NATS_TLS_CERT_FILE"] = infrastructure.Certificate;
            values["TS_ORCH_INFRA_NATS_TLS_KEY_FILE"] = infrastructure.PrivateKey;
            await Assert.That(() => OrchestratorOptions.Parse(["provision-journal"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
            values["TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"] = safeReply;
            values["TS_ORCH_NATS_NKEY_FILE"] = writerNkey;
            await Assert.That(() => OrchestratorOptions.Parse(["provision-journal"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
            values["TS_ORCH_NATS_NKEY_FILE"] = distinctControllerNkey;
            values["TS_ORCH_NATS_TLS_CA_FILE"] = writer.Certificate;
            values["TS_ORCH_NATS_TLS_CERT_FILE"] = writer.Certificate;
            values["TS_ORCH_NATS_TLS_KEY_FILE"] = writer.PrivateKey;
            await Assert.That(() => OrchestratorOptions.Parse(["provision-journal"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task ControllerNKeyMustBeAnExistingFile()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var path = Path.Combine(Path.GetTempPath(), $"ts-orch-option-{Guid.NewGuid():N}.nk");
        try
        {
            await File.WriteAllTextAsync(path, NATS.Client.Core.NKeys.CreateUserSeed());
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var options = OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null);

            await Assert.That(options.NatsNKeyFile).IsEqualTo(path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null))
                .Throws<ArgumentException>();
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await File.WriteAllTextAsync(path, "not-an-nkey-seed");
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null))
                .Throws<ArgumentException>();
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path + ".missing" : null))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task RemovedProfilesAndOptionsAreRejected()
    {
        foreach (var profile in new[] { "regions-smol", "dev-containers", "dev-containers-control" })
        {
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["lab", "plan", "--profile", profile],
                    _ => null))
                .Throws<ArgumentException>();
        }
        await Assert.That(() => OrchestratorOptions.Parse(
            ["lab", "plan", "--watch"],
            _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["lab", "plan", "--base-artifact", "/tmp/base.smolmachine"],
                _ => null))
            .Throws<ArgumentException>();
    }

    private static async Task<(string Certificate, string PrivateKey)> WriteCertificateAsync(
        string directory,
        string name,
        System.Security.Cryptography.ECDsa key,
        bool isAuthority)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            $"CN={name}", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(isAuthority, false, 0, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var certificatePath = Path.Combine(directory, $"{name}.pem");
        var keyPath = Path.Combine(directory, $"{name}-key.pem");
        await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem());
        await File.WriteAllTextAsync(keyPath, key.ExportPkcs8PrivateKeyPem());
        File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return (certificatePath, keyPath);
    }
}
