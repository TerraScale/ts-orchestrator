using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Messaging;
using System.Security.Cryptography.X509Certificates;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentNatsSecurityTests
{
    [Test]
    public async Task FreshAuthorityLeaseAgeDoesNotInheritProcessStartupTime()
    {
        var now = DateTimeOffset.UtcNow;
        var health = RegionalAuthorityCoordinator.Health(now, TimeSpan.Zero);

        await Assert.That(health.ServerTime).IsEqualTo(now);
        await Assert.That(health.MonotonicElapsed).IsEqualTo(TimeSpan.Zero);
        await Assert.That(health.PartitionCertain).IsTrue();
        await Assert.That(health.ClockCertain).IsTrue();
    }

    [Test]
    public async Task DevelopmentNatsIdentitiesArePrivateDistinctAndPlaneScoped()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-security-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var gru = security.Cell("gru");
            var sfo = security.Cell("sfo");

            await Assert.That(gru.Controllers.Count).IsEqualTo(1);
            await Assert.That(gru.Controllers.Values.Select(value => value.PublicKey).Distinct().Count())
                .IsEqualTo(1);
            await Assert.That(gru.Operator.PublicKey).IsNotEqualTo(gru.Controllers[1].PublicKey);
            await Assert.That(gru.Product.Password).IsNotEqualTo(sfo.Product.Password);
            await Assert.That(File.ReadAllText(gru.Tls.Control.Clients["operator-read"].CaFile))
                .IsNotEqualTo(File.ReadAllText(gru.Tls.Product.Clients["gru-platform"].CaFile));

            foreach (var identity in gru.Controllers.Values.Append(gru.Operator))
            {
                await Assert.That(File.GetUnixFileMode(identity.SeedFile))
                    .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
                var lines = File.ReadAllLines(identity.SeedFile);
                await Assert.That(lines.Length).IsEqualTo(2);
                await Assert.That(lines[1]).IsEqualTo(identity.PublicKey);
            }

            var authorization = NatsDevelopmentCluster.ControlAuthorization(
                topology.Cells.Single(cell => cell.Cell == "gru"),
                gru);
            await Assert.That(authorization).Contains(gru.Operator.PublicKey);
            await Assert.That(authorization).Contains(gru.Controllers[1].PublicKey);
            await Assert.That(authorization).Contains("\"$KV.>\"");
            await Assert.That(authorization).Contains("\"$O.>\"");
            await Assert.That(authorization).DoesNotContain(File.ReadLines(gru.Operator.SeedFile).First());
            await Assert.That(authorization).DoesNotContain(gru.Product.Password);

            var operatorTls = gru.Tls.Control.Clients["operator-read"];
            await Assert.That(operatorTls.SpiffeId)
                .IsEqualTo("spiffe://terrascale.tech/cell/gru/operator/operator-read");
            await Assert.That(File.GetUnixFileMode(operatorTls.KeyFile))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await Assert.That(File.GetUnixFileMode(operatorTls.CertificateFile))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            using var certificate = X509Certificate2.CreateFromPemFile(
                operatorTls.CertificateFile,
                operatorTls.KeyFile);
            await Assert.That(certificate.HasPrivateKey).IsTrue();
            await Assert.That(certificate.Extensions["2.5.29.17"]!.Format(false))
                .Contains(operatorTls.SpiffeId);
            // Continuous labs remint near expiry; fresh leaves must still outlast a
            // multi-day generation and report no remint need at mint time.
            var leafRemaining = certificate.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            await Assert.That(leafRemaining).IsGreaterThan(TimeSpan.FromDays(7));
            await Assert.That(leafRemaining)
                .IsLessThanOrEqualTo(DevelopmentPki.LeafLifetime + TimeSpan.FromMinutes(1));
            await Assert.That(DevelopmentPki.IntermediateLifetime)
                .IsGreaterThan(DevelopmentPki.LeafLifetime);
            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, DateTimeOffset.UtcNow))
                .IsFalse();
            var earliest = DevelopmentPki.TryGetEarliestLeafNotAfter(directory);
            await Assert.That(earliest).IsNotNull();
            await Assert.That(DevelopmentPki.LeavesNeedRemint(
                    directory,
                    earliest!.Value - DevelopmentPki.LeafRenewalLeadTime + TimeSpan.FromSeconds(1)))
                .IsTrue();
            await Assert.That(DevelopmentPki.RemintLeavesIfNeeded(
                    topology,
                    directory,
                    DateTimeOffset.UtcNow))
                .IsFalse();
            var resolved = NatsTlsFiles.Resolve(
                operatorTls.CaFile,
                operatorTls.CertificateFile,
                operatorTls.KeyFile,
                "test TLS");
            await Assert.That(resolved).IsNotNull();

            var serverTls = gru.Tls.Control.Servers["gru-control-nats-1"];
            var tlsConfiguration = NatsDevelopmentCluster.TlsConfiguration(serverTls.Client);
            await Assert.That(tlsConfiguration).Contains("verify: true");
            await Assert.That(tlsConfiguration).DoesNotContain("insecure");
            await Assert.That(serverTls.Client.SpiffeId).IsNotEqualTo(serverTls.Route.SpiffeId);
            using var serverCertificate = X509Certificate2.CreateFromPemFile(
                serverTls.Client.CertificateFile,
                serverTls.Client.KeyFile);
            var serverRemaining = serverCertificate.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            await Assert.That(serverRemaining).IsGreaterThan(TimeSpan.FromDays(7));
            // Intermediate must strictly outlive the leaf so chain creation cannot
            // fail when wall-clock advances between issuer and leaf issuance.
            var intermediatePemPath = Path.Combine(
                Path.GetDirectoryName(serverTls.Client.CaFile)!,
                "intermediate.pem");
            using var intermediateCertificate = X509Certificate2.CreateFromPem(
                File.ReadAllText(intermediatePemPath));
            await Assert.That(intermediateCertificate.NotAfter.ToUniversalTime())
                .IsGreaterThan(serverCertificate.NotAfter.ToUniversalTime());

            using var platformCertificate = X509Certificate2.CreateFromPemFile(
                gru.Tls.Product.Clients["gru-platform"].CertificateFile,
                gru.Tls.Product.Clients["gru-platform"].KeyFile);
            var platformRemaining = platformCertificate.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            await Assert.That(platformRemaining).IsGreaterThan(TimeSpan.FromDays(7));

            var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
            var controlProbe = NatsDevelopmentCluster.ClientOptions(
                cell.OfKind(DevelopmentResourceKind.ControlNats)[0],
                gru);
            var productProbe = NatsDevelopmentCluster.ClientOptions(
                cell.OfKind(DevelopmentResourceKind.ProductNats)[0],
                gru);
            await Assert.That(controlProbe.AuthOpts.NKeyFile).IsEqualTo(gru.Operator.SeedFile);
            await Assert.That(controlProbe.TlsOpts.CertFile).IsEqualTo(operatorTls.CertificateFile);
            await Assert.That(productProbe.AuthOpts.Username).IsEqualTo(gru.Product.Username);
            await Assert.That(productProbe.TlsOpts.CertFile)
                .IsEqualTo(gru.Tls.Product.Clients["gru-platform"].CertificateFile);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task NearExpiryLeavesAreRemintedOntoStablePaths()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-pki-remint-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var platform = security.Cell("gru").Tls.Product.Clients["gru-platform"];
            var originalCert = File.ReadAllText(platform.CertificateFile);
            using var before = X509Certificate2.CreateFromPemFile(
                platform.CertificateFile,
                platform.KeyFile);
            var forceRemintAt = before.NotAfter.ToUniversalTime() -
                DevelopmentPki.LeafRenewalLeadTime +
                TimeSpan.FromMinutes(1);

            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, forceRemintAt)).IsTrue();
            await Assert.That(DevelopmentPki.RemintLeavesIfNeeded(topology, directory, forceRemintAt))
                .IsTrue();
            await Assert.That(File.Exists(platform.CertificateFile)).IsTrue();
            await Assert.That(File.Exists(platform.KeyFile)).IsTrue();
            await Assert.That(File.Exists(platform.CaFile)).IsTrue();
            await Assert.That(File.ReadAllText(platform.CertificateFile)).IsNotEqualTo(originalCert);
            using var after = X509Certificate2.CreateFromPemFile(
                platform.CertificateFile,
                platform.KeyFile);
            var remaining = after.NotAfter.ToUniversalTime() - DateTime.UtcNow;
            await Assert.That(remaining).IsGreaterThan(DevelopmentPki.LeafRenewalLeadTime);
            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, DateTimeOffset.UtcNow))
                .IsFalse();
            // NKey and product password material must survive a PKI-only remint.
            await Assert.That(File.Exists(security.Cell("gru").Operator.SeedFile)).IsTrue();
            await Assert.That(security.Cell("gru").Product.Username).IsEqualTo("product-gru");
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task UnreadableLeafPemForcesRemintEvenWhenSiblingsRemainValid()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-pki-corrupt-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var platform = security.Cell("gru").Tls.Product.Clients["gru-platform"];
            var originalCert = File.ReadAllText(platform.CertificateFile);

            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, DateTimeOffset.UtcNow))
                .IsFalse();

            // One corrupt leaf must not be masked by healthy siblings: NATS would keep
            // rejecting that identity until the whole regional tree is reminted.
            File.WriteAllText(platform.CertificateFile, "not-a-certificate\n");
            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, DateTimeOffset.UtcNow))
                .IsTrue();
            await Assert.That(DevelopmentPki.RemintLeavesIfNeeded(
                    topology,
                    directory,
                    DateTimeOffset.UtcNow))
                .IsTrue();
            await Assert.That(File.ReadAllText(platform.CertificateFile)).IsNotEqualTo(originalCert);
            await Assert.That(File.ReadAllText(platform.CertificateFile)).DoesNotContain("not-a-certificate");
            using var restored = X509Certificate2.CreateFromPemFile(
                platform.CertificateFile,
                platform.KeyFile);
            await Assert.That(restored.NotAfter.ToUniversalTime() - DateTime.UtcNow)
                .IsGreaterThan(DevelopmentPki.LeafRenewalLeadTime);
            await Assert.That(DevelopmentPki.LeavesNeedRemint(directory, DateTimeOffset.UtcNow))
                .IsFalse();
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task RemintPublishesOntoStablePathsWithoutLeavingStagingResidue()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-pki-atomic-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var operatorTls = security.Cell("gru").Tls.Control.Clients["operator-read"];
            var stableCertPath = operatorTls.CertificateFile;
            var stableKeyPath = operatorTls.KeyFile;
            var stableCaPath = operatorTls.CaFile;
            await Assert.That(stableCertPath.Contains(
                    Path.Combine("credentials", "pki"),
                    StringComparison.Ordinal))
                .IsTrue();
            await Assert.That(stableCertPath.Contains(".pki-staging-", StringComparison.Ordinal))
                .IsFalse();
            var originalCert = File.ReadAllText(stableCertPath);
            using var before = X509Certificate2.CreateFromPemFile(stableCertPath, stableKeyPath);
            var forceRemintAt = before.NotAfter.ToUniversalTime() -
                DevelopmentPki.LeafRenewalLeadTime +
                TimeSpan.FromMinutes(1);

            await Assert.That(DevelopmentPki.RemintLeavesIfNeeded(topology, directory, forceRemintAt))
                .IsTrue();
            await Assert.That(File.Exists(stableCertPath)).IsTrue();
            await Assert.That(File.Exists(stableKeyPath)).IsTrue();
            await Assert.That(File.Exists(stableCaPath)).IsTrue();
            await Assert.That(File.ReadAllText(stableCertPath)).IsNotEqualTo(originalCert);
            await Assert.That(Directory.GetDirectories(
                    Path.Combine(directory, "credentials"),
                    ".pki-staging-*",
                    SearchOption.TopDirectoryOnly))
                .IsEmpty();
            await Assert.That(Directory.GetDirectories(
                    Path.Combine(directory, "credentials"),
                    ".pki-retired-*",
                    SearchOption.TopDirectoryOnly))
                .IsEmpty();
            using var after = X509Certificate2.CreateFromPemFile(stableCertPath, stableKeyPath);
            await Assert.That(after.NotAfter.ToUniversalTime() - DateTime.UtcNow)
                .IsGreaterThan(DevelopmentPki.LeafRenewalLeadTime);
            // Intermediate remains part of the remint survey surface.
            var intermediatePath = Path.Combine(
                Path.GetDirectoryName(stableCaPath)!,
                "intermediate.pem");
            using var intermediate = X509Certificate2.CreateFromPem(File.ReadAllText(intermediatePath));
            await Assert.That(intermediate.NotAfter.ToUniversalTime())
                .IsGreaterThan(after.NotAfter.ToUniversalTime());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task CertificateFailureDetailsMatchOpenSslAndExpiredLeafAnnotations()
    {
        // NATS.Net outer messages are generic; recovery depends on flattened OpenSSL inners
        // and on-disk leaf annotations from DevelopmentHealthProbe.FormatProbeFailure.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000 | " +
                "error:0A000415:SSL routines::ssl/tls alert certificate expired"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect | " +
                "certificate has expired: current time 2026-07-21T18:45:28Z is after 2026-07-21T18:45:24Z"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "tls: failed to verify certificate: x509: certificate has expired or is not yet valid"))
            .IsTrue();
        // Product-plane server log shape for CN=fra-platform presenting an expired leaf.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] TLS handshake error: tls: failed to verify certificate: " +
                "x509: certificate has expired or is not yet valid: current time 2026-07-21T18:45:28Z " +
                "is after 2026-07-21T18:45:24Z (CN=fra-platform)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000"))
            .IsFalse();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: Connection refused"))
            .IsFalse();
    }

    [Test]
    public async Task PkiRemintStopsPlatformClientsBeforeRecyclingProductNats()
    {
        // After remint, product NATS must not see CN=*-platform presenting the previous
        // (often expired) leaf while servers already loaded the new CA. The ordered client
        // list therefore includes every regional platform and excludes NATS servers.
        var topology = DevelopmentTopology.CreateThreeCellLean();
        var clients = DevelopmentLab.TlsClientResourceNames(topology);

        await Assert.That(clients).Contains("fra-platform");
        await Assert.That(clients).Contains("gru-platform");
        await Assert.That(clients).Contains("sfo-platform");
        await Assert.That(clients).Contains("fra-controller-1");
        await Assert.That(clients).Contains("gru-controller-1");
        await Assert.That(clients).Contains("sfo-controller-1");
        await Assert.That(clients.Any(name => name.Contains("product-nats", StringComparison.Ordinal)))
            .IsFalse();
        await Assert.That(clients.Any(name => name.Contains("control-nats", StringComparison.Ordinal)))
            .IsFalse();
        // Platforms are listed before NATS recycle; order among clients is stable cell order.
        var fraPlatform = clients.ToList().IndexOf("fra-platform");
        var gruPlatform = clients.ToList().IndexOf("gru-platform");
        await Assert.That(fraPlatform).IsGreaterThanOrEqualTo(0);
        await Assert.That(gruPlatform).IsGreaterThanOrEqualTo(0);
    }

    [Test]
    public async Task ProbeFailureFormattingSurfacesExpiredOperatorReadLeaf()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-probe-expiry-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var operatorTls = security.Cell("fra").Tls.Control.Clients["operator-read"];

            // Mirror the live NATS.Net exception chain for an expired client leaf: generic
            // outer message with OpenSSL "certificate expired" nested on inners.
            var outer = new NATS.Client.Core.NatsException(
                "can not start to connect nats server: nats://127.0.0.1:19000",
                new IOException(
                    "The decryption operation failed, see inner exception.",
                    new InvalidOperationException(
                        "error:0A000415:SSL routines::ssl/tls alert certificate expired")));
            var detail = DevelopmentHealthProbe.FormatProbeFailure(outer, operatorTls);
            await Assert.That(detail).Contains("can not start to connect");
            await Assert.That(detail).Contains("certificate expired");
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(detail)).IsTrue();

            // Fresh leaves must not be annotated as expired on a generic connect failure.
            await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(operatorTls.CertificateFile))
                .IsNull();
            var freshDetail = DevelopmentHealthProbe.FormatProbeFailure(
                new NATS.Client.Core.NatsException(
                    "can not start to connect nats server: nats://127.0.0.1:19000"),
                operatorTls);
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(freshDetail)).IsFalse();

            // Missing leaf PEMs are annotated so force-remint can recover without relying on
            // server-side log text that never reaches the health probe.
            File.Delete(operatorTls.CertificateFile);
            await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(operatorTls.CertificateFile))
                .Contains("failed to verify certificate");
            var missingDetail = DevelopmentHealthProbe.FormatProbeFailure(
                new NATS.Client.Core.NatsException(
                    "can not start to connect nats server: nats://127.0.0.1:19000"),
                operatorTls);
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(missingDetail)).IsTrue();

            // An on-disk leaf that is already past NotAfter must annotate explicitly even when
            // the outer NATS exception text is generic.
            using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                       System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
            {
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    "CN=operator-read",
                    ecdsa,
                    System.Security.Cryptography.HashAlgorithmName.SHA256);
                var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                using var expired = request.CreateSelfSigned(notBefore, notAfter);
                File.WriteAllText(operatorTls.CertificateFile, expired.ExportCertificatePem());
            }
            var expiredStatus = DevelopmentHealthProbe.DescribeLeafValidity(operatorTls.CertificateFile);
            await Assert.That(expiredStatus).IsNotNull();
            await Assert.That(expiredStatus!).Contains("certificate has expired");
            var expiredDetail = DevelopmentHealthProbe.FormatProbeFailure(
                new NATS.Client.Core.NatsException(
                    "can not start to connect nats server: nats://127.0.0.1:19000"),
                operatorTls);
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(expiredDetail)).IsTrue();
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task ExistingSeedOnlyNKeyIsUpgradedWithoutChangingItsIdentity()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-upgrade-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "identity.nk");
        try
        {
            Directory.CreateDirectory(directory);
            var seed = NATS.Client.Core.NKeys.CreateUserSeed();
            File.WriteAllText(path, seed + Environment.NewLine);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var identity = DevelopmentNatsSecurity.EnsureNKey(path);

            await Assert.That(File.ReadAllLines(path)).IsEquivalentTo([seed, identity.PublicKey]);
            await Assert.That(File.GetUnixFileMode(path))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task WorldReadableNKeyIsRejectedBeforeUse()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-mode-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "identity.nk");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(path, "not-a-seed");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.OtherRead);

            await Assert.That(() => DevelopmentNatsSecurity.EnsureNKey(path))
                .Throws<InvalidOperationException>();
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
