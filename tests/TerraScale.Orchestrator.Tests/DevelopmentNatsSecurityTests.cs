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
        // Exact fra-product-nats / CN=fra-platform multi-occurrence shape (fingerprint
        // 25ef0004168c…): same NotAfter (18:45:24Z) and bare product-NATS recycle pattern
        // (cid 14634 → 63 → 50 → 43 at 18:45:34Z / 18:46:34Z / 18:48:34Z / 18:50:34Z) as the
        // control-plane controller storms. The long-running fra-platform process presents
        // the product leaf; platform /health/ready can stay green while product NATS logs
        // every reconnect. Recovery must match every occurrence and force remint from
        // invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:34.133777 [ERR] 127.0.0.1:46776 - cid:14634 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:34.033522 [ERR] 127.0.0.1:32802 - cid:63 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:34.475586 [ERR] 127.0.0.1:38008 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:34.257829 [ERR] 127.0.0.1:54186 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform multi-occurrence shape (fingerprint
        // dacc95d0e7ba…): denser five-occurrence twin of 25ef0004168c… against the same
        // 7ef9d0a4… platform leaf and fra product issuer, with cid recycle 14635 → 67 → 38 →
        // 51 → 44 at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z. The
        // long-running fra-platform process presents the product leaf while product NATS
        // logs every reconnect. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for
        // every cell — bare RestartAsync of product NATS alone reloads the same expired
        // PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:40.092456 [ERR] 127.0.0.1:33866 - cid:14635 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:40.151056 [ERR] 127.0.0.1:42030 - cid:67 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:40.071746 [ERR] 127.0.0.1:59304 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:40.408407 [ERR] 127.0.0.1:38036 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:40.269650 [ERR] 127.0.0.1:42110 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform single-occurrence post-recycle shape
        // (fingerprint 1e8b88f75d43…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba…, observed once at 18:45:45Z with low
        // cid:31 on 127.0.0.1:34466 after product-NATS recycle (NotAfter still 18:45:24Z).
        // This is the post-bare-restart reconnect twin of the denser 25ef0004168c… /
        // dacc95d0e7ba… storms and the fra twin of gru 0b23b4fb5a75… / sfo d739f8d83bed…:
        // a single long-running fra-platform process re-presents the expired product leaf
        // against a freshly recycled product NATS listener. Recovery must match this line
        // and force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:45.533114 [ERR] 127.0.0.1:34466 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform six-occurrence post-recycle shape
        // (fingerprint 30e9c320e15b…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43…, observed six times after
        // product-NATS recycle (cid 32 → 71 → 41 → 42 → 52 → 45 at 18:45:46Z on
        // 127.0.0.1:34468, 18:46:46Z on 127.0.0.1:45732, 18:47:46Z on 127.0.0.1:49922 /
        // 49934 (dual cid 41+42), 18:48:46Z on 127.0.0.1:44248, and 18:50:46Z on
        // 127.0.0.1:58440; NotAfter still 18:45:24Z). This is the six-occurrence
        // post-bare-restart reconnect twin of the denser 25ef0004168c… / dacc95d0e7ba…
        // storms and single 1e8b88f75d43… line, and the fra twin of gru 0cbc78bc3a3a…: the
        // long-running fra-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:46.559103 [ERR] 127.0.0.1:34468 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:46.362005 [ERR] 127.0.0.1:45732 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:46.038396 [ERR] 127.0.0.1:49922 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:46.173282 [ERR] 127.0.0.1:49934 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:46.378173 [ERR] 127.0.0.1:44248 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:46.278446 [ERR] 127.0.0.1:58440 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint fc4e0317d2a1…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b…, observed
        // twice after product-NATS recycle (cid 33 → 72 at 18:45:48Z on 127.0.0.1:34476 and
        // 18:46:48Z on 127.0.0.1:45738; NotAfter still 18:45:24Z). This is a sparse two-
        // occurrence post-bare-restart reconnect twin of the six-occurrence 30e9c320e15b…
        // (cid 32 → 71… on adjacent ports 34468/45732), denser 25ef0004168c… / dacc95d0e7ba…,
        // and single 1e8b88f75d43… storms, and the fra twin of gru 6a1c43a93378…: the
        // long-running fra-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:48.650638 [ERR] 127.0.0.1:34476 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:48.433105 [ERR] 127.0.0.1:45738 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence post-recycle shape
        // (fingerprint 92ed0baffd5b…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1…, observed four times after product-NATS recycle (cid 34 → 35 → 74 →
        // 36 at 18:45:50Z on 127.0.0.1:34504 / 34506 dual reconnect, 18:46:50Z on
        // 127.0.0.1:45768, and 18:49:50Z on 127.0.0.1:59726; NotAfter still 18:45:24Z). This
        // is a four-occurrence post-bare-restart reconnect twin of the sparse two-occurrence
        // fc4e0317d2a1… pair (cid 33 → 72 on adjacent early ports 34476/45738), six-occurrence
        // 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single 1e8b88f75d43… storms,
        // and the fra twin of gru ed3f4504d5e1… / sfo 146c64f3fc52… / operator-read twins
        // f4f92376efda… / 62860f83eeb6… / 7421834a4183… at the same wall-clock pair: the
        // long-running fra-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:50.108851 [ERR] 127.0.0.1:34504 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:50.733470 [ERR] 127.0.0.1:34506 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:50.487691 [ERR] 127.0.0.1:45768 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:49:50.278407 [ERR] 127.0.0.1:59726 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence post-recycle shape
        // (fingerprint 7904dd055f87…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b…, observed four times after product-NATS recycle
        // (cid 36 → 75 → 53 → 46 at 18:45:52Z on 127.0.0.1:34510, 18:46:52Z on
        // 127.0.0.1:45778, 18:48:52Z on 127.0.0.1:44268, and 18:50:52Z on
        // 127.0.0.1:58444; NotAfter still 18:45:24Z). This is a four-occurrence post-bare-
        // restart reconnect twin of the 92ed0baffd5b… four-occurrence storm (cid 34 → 35 →
        // 74 → 36 on adjacent early ports 34504/34506/45768), sparse two-occurrence
        // fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…,
        // and single 1e8b88f75d43… storms, and the fra twin of gru b22018f7aa7b… at the
        // same wall-clock :52 steps: the long-running fra-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence
        // and force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:52.782341 [ERR] 127.0.0.1:34510 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:52.539703 [ERR] 127.0.0.1:45778 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:52.391092 [ERR] 127.0.0.1:44268 - cid:53 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:52.354794 [ERR] 127.0.0.1:58444 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint 5804cb3aaf61…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87…, observed twice after product-NATS
        // recycle (cid 37 → 76 at 18:45:54Z on 127.0.0.1:50978 and 18:46:54Z on
        // 127.0.0.1:38754; NotAfter still 18:45:24Z). This is a sparse two-occurrence post-
        // bare-restart reconnect twin of the 7904dd055f87… four-occurrence storm (cid 36 →
        // 75 → 53 → 46 on adjacent early ports 34510/45778), 92ed0baffd5b… four-occurrence
        // storm, sparse two-occurrence fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser
        // 25ef0004168c… / dacc95d0e7ba…, and single 1e8b88f75d43… storms, and the product-
        // plane peer of gru 9371738eec92… (cid 38 → 77 at :54) / b22018f7aa7b… (cid 37 → 76
        // at :52) / sfo e33d87402e17… / operator-read twins at adjacent wall-clock
        // :52/:53/:54 steps: the long-running fra-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:54.793099 [ERR] 127.0.0.1:50978 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:54Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:54.622135 [ERR] 127.0.0.1:38754 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:54Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence post-recycle shape
        // (fingerprint 5d30a28d7f44…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61…, observed four times
        // after product-NATS recycle (cid 38 → 39 → 78 → 37 at 18:45:56Z on 127.0.0.1:51008 /
        // 127.0.0.1:51016 dual reconnect, 18:46:56Z on 127.0.0.1:38782, and 18:49:56Z on
        // 127.0.0.1:52794; NotAfter still 18:45:24Z). This is a four-occurrence post-bare-
        // restart reconnect twin of the sparse two-occurrence 5804cb3aaf61… pair (cid 37 → 76
        // two seconds earlier on 50978/38754), 7904dd055f87… four-occurrence storm,
        // 92ed0baffd5b… four-occurrence storm, sparse two-occurrence fc4e0317d2a1…, six-
        // occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru be7bee33b946… (cid 39 → 40 →
        // 79 → 37 at :56) / sfo 26b95f54769c… (cid 38 → 37 at :56) / gru operator-read
        // b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
        // fra operator-read c74671d2c0e4… / fra-controller 5e5b835252fe… at the same wall-clock
        // :56 steps: the long-running fra-platform process re-presents the expired product
        // leaf against a freshly recycled product NATS listener while platform HTTP readiness
        // can stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell — bare
        // RestartAsync of product NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:56.054175 [ERR] 127.0.0.1:51008 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:56.840629 [ERR] 127.0.0.1:51016 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:56.686516 [ERR] 127.0.0.1:38782 - cid:78 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:49:56.235917 [ERR] 127.0.0.1:52794 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform three-occurrence post-recycle shape
        // (fingerprint 639501fa4228…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44…,
        // observed three times after product-NATS recycle (cid 40 → 79 → 54 at 18:45:58Z on
        // 127.0.0.1:51030, 18:46:58Z on 127.0.0.1:38798, and 18:48:58Z on 127.0.0.1:38302;
        // NotAfter still 18:45:24Z). This is a three-occurrence post-bare-restart reconnect
        // twin of the four-occurrence 5d30a28d7f44… storm (cid 38 → 39 → 78 → 37 two seconds
        // earlier on 51008/51016/38782/52794), sparse two-occurrence 5804cb3aaf61…,
        // 7904dd055f87… four-occurrence storm, 92ed0baffd5b… four-occurrence storm, sparse
        // two-occurrence fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser 25ef0004168c… /
        // dacc95d0e7ba…, and single 1e8b88f75d43… storms, and the product-plane peer of gru
        // a2e01c16a27c… (cid 41 → 80 → 53 at :58) / sfo 9b960cc93f83… (cid 39 → 78 → 43 at
        // :57) / gru operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo
        // operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent
        // wall-clock :56/:57/:58 steps: the long-running fra-platform process re-presents
        // the expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:45:58.879318 [ERR] 127.0.0.1:51030 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:58.774201 [ERR] 127.0.0.1:38798 - cid:79 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:58.442477 [ERR] 127.0.0.1:38302 - cid:54 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint eebfa17cec6b…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228…, observed twice after product-NATS recycle (cid 41 → 80 at
        // 18:46:00Z on 127.0.0.1:51046 and 18:47:00Z on 127.0.0.1:38810; NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the
        // three-occurrence 639501fa4228… storm (cid 40 → 79 → 54 two seconds earlier on
        // 51030/38798/38302), four-occurrence 5d30a28d7f44…, sparse two-occurrence
        // 5804cb3aaf61…, 7904dd055f87… four-occurrence storm, 92ed0baffd5b… four-
        // occurrence storm, sparse two-occurrence fc4e0317d2a1…, six-occurrence
        // 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single 1e8b88f75d43…
        // storms, and the product-plane peer of gru 764b28c3439a… (cid 42 → 81 at
        // 18:46:00Z / 18:47:00Z) / gru a2e01c16a27c… (cid 41 → 80 → 53 at :58) / sfo
        // 9b960cc93f83… (cid 39 → 78 → 43 at :57) / gru operator-read b252d8996050… /
        // gru-controller a9bf884a363b… / 25b92b919c66… / sfo operator-read 97d33257778a… /
        // fra operator-read c74671d2c0e4… at the same wall-clock 18:46:00Z / 18:47:00Z
        // steps: the long-running fra-platform process re-presents the expired product
        // leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for
        // every cell — bare RestartAsync of product NATS alone reloads the same expired
        // PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:00.913152 [ERR] 127.0.0.1:51046 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:00.843856 [ERR] 127.0.0.1:38810 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint 669e26dad203…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b…, observed twice after product-NATS recycle (cid 42 →
        // 81 at 18:46:01Z on 127.0.0.1:51068 and 18:47:01Z on 127.0.0.1:38828; NotAfter
        // still 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the
        // two-occurrence eebfa17cec6b… storm (cid 41 → 80 one second earlier on 51046/38810),
        // three-occurrence 639501fa4228…, four-occurrence 5d30a28d7f44…, sparse two-
        // occurrence 5804cb3aaf61…, 7904dd055f87… four-occurrence storm, 92ed0baffd5b…
        // four-occurrence storm, sparse two-occurrence fc4e0317d2a1…, six-occurrence
        // 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single 1e8b88f75d43…
        // storms, and the product-plane peer of gru 6d84bda1e560… (cid 43 → 82 at
        // 18:46:01Z / 18:47:01Z) / gru 764b28c3439a… (cid 42 → 81 at 18:46:00Z / 18:47:00Z) /
        // sfo eacb3282ca0c… (dual cid 41+42 → 80+81) at the same wall-clock 18:46:01Z /
        // 18:47:01Z steps: the long-running fra-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for
        // every cell — bare RestartAsync of product NATS alone reloads the same expired
        // PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:01.971372 [ERR] 127.0.0.1:51068 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:01.737105 [ERR] 127.0.0.1:38828 - cid:81 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence sparse post-recycle shape
        // (fingerprint 67d134aeab25…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203…, observed twice after product-NATS
        // recycle (cid 43 → 38 at 18:46:03Z on 127.0.0.1:51072 and 18:50:03Z on
        // 127.0.0.1:52810; NotAfter still 18:45:24Z). This is a sparse two-occurrence
        // post-bare-restart reconnect twin of the denser two-occurrence 669e26dad203…
        // storm (cid 42 → 81 two seconds earlier on adjacent 51068/38828), two-occurrence
        // eebfa17cec6b…, three-occurrence 639501fa4228…, four-occurrence 5d30a28d7f44…,
        // sparse two-occurrence 5804cb3aaf61…, 7904dd055f87… four-occurrence storm,
        // 92ed0baffd5b… four-occurrence storm, sparse two-occurrence fc4e0317d2a1…,
        // six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru 6d84bda1e560… (cid 43 → 82
        // at 18:46:01Z / 18:47:01Z) / gru 764b28c3439a… (cid 42 → 81 at 18:46:00Z /
        // 18:47:00Z) / sfo eacb3282ca0c… (dual cid 41+42 → 80+81) at the adjacent wall-clock
        // 18:46:01Z / 18:47:01Z steps: the long-running fra-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:03.000337 [ERR] 127.0.0.1:51072 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:03Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:03.094143 [ERR] 127.0.0.1:52810 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:03Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform single-occurrence post-recycle shape
        // (fingerprint b8e719ba13ca…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25…, observed once after
        // product-NATS recycle (cid:44 at 18:46:05Z on 127.0.0.1:38810; NotAfter still
        // 18:45:24Z). This is a single-occurrence post-bare-restart reconnect twin of the
        // sparse two-occurrence 67d134aeab25… storm (cid 43 → 38 two seconds earlier on
        // 51072/52810), two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence
        // 639501fa4228…, four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…,
        // 7904dd055f87… / 92ed0baffd5b… four-occurrence storms, sparse two-occurrence
        // fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…,
        // and single 1e8b88f75d43… storms, and the product-plane peer of gru 3f4dc73e62f2…
        // (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde… (cid 44 → 83 at :02) / sfo
        // c907c56a7c0c… (cid 43 → 82 → 38 at :03) at the adjacent wall-clock 18:46:02Z /
        // 18:46:03Z / 18:46:04Z / 18:46:05Z steps: the long-running fra-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match this
        // line and force remint from invalid product-plane client leaves (platforms) on the
        // NATS resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on the next
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:05.023890 [ERR] 127.0.0.1:38810 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence dual-cid post-recycle shape
        // (fingerprint aae9c8a6b484…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca…,
        // observed four times after product-NATS recycle (cid 45 → 46 at 18:46:07Z on
        // 127.0.0.1:38812 / 127.0.0.1:38824, and cid 84 → 85 at 18:47:07Z on 127.0.0.1:40184 /
        // 127.0.0.1:40196; NotAfter still 18:45:24Z). This is a four-occurrence dual-cid
        // post-bare-restart reconnect twin of the single-occurrence b8e719ba13ca… storm
        // (cid:44 two seconds earlier on 38810), sparse two-occurrence 67d134aeab25…,
        // two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence 639501fa4228…,
        // four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…, 7904dd055f87… /
        // 92ed0baffd5b… four-occurrence storms, sparse two-occurrence fc4e0317d2a1…,
        // six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru e962f4a49508… (cid 46 → 85
        // at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde…
        // (cid 44 → 83 at :02) / sfo b439248687d8… (cid 44 → 83 at :05) / sfo c907c56a7c0c…
        // (cid 43 → 82 → 38 at :03) at the adjacent wall-clock 18:46:02Z / 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:02Z / 18:47:05Z / 18:47:06Z /
        // 18:47:07Z steps: the long-running fra-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for
        // every cell — bare RestartAsync of product NATS alone reloads the same expired PEM
        // and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:07.061440 [ERR] 127.0.0.1:38812 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:07.925624 [ERR] 127.0.0.1:38824 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:07.057775 [ERR] 127.0.0.1:40184 - cid:84 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:07.648386 [ERR] 127.0.0.1:40196 - cid:85 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform three-occurrence sparse post-recycle shape
        // (fingerprint a66e03d58e6a…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca… /
        // aae9c8a6b484…, observed three times after product-NATS recycle (cid 47 → 86 → 39
        // at 18:46:09Z on 127.0.0.1:38828, 18:47:09Z on 127.0.0.1:40210, and 18:50:09Z on
        // 127.0.0.1:48084; NotAfter still 18:45:24Z). This is a three-occurrence sparse
        // post-bare-restart reconnect twin of the four-occurrence dual-cid aae9c8a6b484…
        // storm (cid 45 → 46 → 84 → 85 two seconds earlier on 38812/38824/40184/40196),
        // single-occurrence b8e719ba13ca…, sparse two-occurrence 67d134aeab25…,
        // two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence 639501fa4228…,
        // four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…, 7904dd055f87… /
        // 92ed0baffd5b… four-occurrence storms, sparse two-occurrence fc4e0317d2a1…,
        // six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru 6be7ec00050d… (cid 48 → 87
        // at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 → 85
        // at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde…
        // (cid 44 → 83 at :02) / sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / sfo
        // b439248687d8… (cid 44 → 83 at :05) / sfo c907c56a7c0c… (cid 43 → 82 → 38 at :03)
        // at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
        // 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:50:09Z steps: the long-running fra-platform
        // process re-presents the expired product leaf against a freshly recycled product
        // NATS listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:09.165229 [ERR] 127.0.0.1:38828 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:09.113273 [ERR] 127.0.0.1:40210 - cid:86 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:09.326070 [ERR] 127.0.0.1:48084 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint a87539b37de1…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca… /
        // aae9c8a6b484… / a66e03d58e6a…, observed twice after product-NATS recycle (cid
        // 48 → 87 at 18:46:11Z on 127.0.0.1:38842 and 18:47:11Z on 127.0.0.1:40216;
        // NotAfter still 18:45:24Z). This is a two-occurrence post-bare-restart reconnect
        // twin of the three-occurrence sparse a66e03d58e6a… storm (cid 47 → 86 → 39 two
        // seconds earlier on 38828/40210/48084), four-occurrence dual-cid aae9c8a6b484…,
        // single-occurrence b8e719ba13ca…, sparse two-occurrence 67d134aeab25…,
        // two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence 639501fa4228…,
        // four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…, 7904dd055f87… /
        // 92ed0baffd5b… four-occurrence storms, sparse two-occurrence fc4e0317d2a1…,
        // six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru 8a0aaf8cb1da… (cid 49 →
        // 88 → 45 → 55 at :10) / gru 6be7ec00050d… (cid 48 → 87 at :08) / gru 0401b56675fd…
        // (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 → 85 at :06) / gru 3f4dc73e62f2…
        // (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde… (cid 44 → 83 at :02) / sfo
        // 02525de8dfa3… (cid 47 → 86 → 39 at :09) / sfo ef71b6e32493… (dual cid 45+46 →
        // 84+85 at :07) / sfo b439248687d8… (cid 44 → 83 at :05) / sfo c907c56a7c0c… (cid
        // 43 → 82 → 38 at :03) at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
        // 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:50:09Z steps: the long-running
        // fra-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:11.174468 [ERR] 127.0.0.1:38842 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:11.163383 [ERR] 127.0.0.1:40216 - cid:87 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence dual-cid post-recycle shape
        // (fingerprint d86f81358e32…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca… /
        // aae9c8a6b484… / a66e03d58e6a… / a87539b37de1…, observed four times after
        // product-NATS recycle (cid 49 → 50 → 88 → 89 at 18:46:13Z on 127.0.0.1:38852 /
        // 127.0.0.1:38860 dual cid 49+50 and 18:47:13Z on 127.0.0.1:40222 /
        // 127.0.0.1:40240 dual cid 88+89; NotAfter still 18:45:24Z). This is a four-
        // occurrence dual-cid post-bare-restart reconnect twin of the two-occurrence
        // a87539b37de1… storm (cid 48 → 87 two seconds earlier on 38842/40216), three-
        // occurrence sparse a66e03d58e6a… storm, four-occurrence dual-cid aae9c8a6b484…,
        // single-occurrence b8e719ba13ca…, sparse two-occurrence 67d134aeab25…,
        // two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence 639501fa4228…,
        // four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…, 7904dd055f87… /
        // 92ed0baffd5b… four-occurrence storms, sparse two-occurrence fc4e0317d2a1…,
        // six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…, and single
        // 1e8b88f75d43… storms, and the product-plane peer of gru 897b9ff7b37e… (cid 50 →
        // 89 at :12) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at :10) / gru 6be7ec00050d…
        // (cid 48 → 87 at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508…
        // (cid 46 → 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru
        // 5990e53d2fde… (cid 44 → 83 at :02) / sfo 02525de8dfa3… (cid 47 → 86 → 39 at :09) /
        // sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / sfo b439248687d8… (cid 44 →
        // 83 at :05) / sfo c907c56a7c0c… (cid 43 → 82 → 38 at :03) at the adjacent wall-
        // clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:48:10Z / 18:49:10Z /
        // 18:50:09Z steps: the long-running fra-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform
        // HTTP readiness can stay green. Recovery must match every occurrence and force
        // remint from invalid product-plane client leaves (platforms) on the NATS resource
        // for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:13.258332 [ERR] 127.0.0.1:38852 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:13.978748 [ERR] 127.0.0.1:38860 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:13.181095 [ERR] 127.0.0.1:40222 - cid:88 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:13.816729 [ERR] 127.0.0.1:40240 - cid:89 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform four-occurrence sparse post-recycle shape
        // (fingerprint bf210e609e7f…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca… /
        // aae9c8a6b484… / a66e03d58e6a… / a87539b37de1… / d86f81358e32…, observed four
        // times after product-NATS recycle (cid 51 → 90 → 47 → 40 at 18:46:15Z on
        // 127.0.0.1:47532, 18:47:15Z on 127.0.0.1:48208, 18:48:15Z on 127.0.0.1:42916, and
        // 18:50:15Z on 127.0.0.1:56668; NotAfter still 18:45:24Z). This is a four-
        // occurrence sparse post-bare-restart reconnect twin of the four-occurrence dual-
        // cid d86f81358e32… storm (cid 49 → 50 → 88 → 89 two seconds earlier on
        // 38852/38860/40222/40240), two-occurrence a87539b37de1… storm (cid 48 → 87 on
        // 38842/40216), three-occurrence sparse a66e03d58e6a… storm, four-occurrence dual-
        // cid aae9c8a6b484…, single-occurrence b8e719ba13ca…, sparse two-occurrence
        // 67d134aeab25…, two-occurrence 669e26dad203… / eebfa17cec6b…, three-occurrence
        // 639501fa4228…, four-occurrence 5d30a28d7f44…, sparse two-occurrence 5804cb3aaf61…,
        // 7904dd055f87… / 92ed0baffd5b… four-occurrence storms, sparse two-occurrence
        // fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser 25ef0004168c… / dacc95d0e7ba…,
        // and single 1e8b88f75d43… storms, and the product-plane peer of gru f106e39e815f…
        // (cid 52 → 91 at :14) / gru 88ff8c404d3b… (cid 51 → 90 at :13) / gru 897b9ff7b37e…
        // (cid 50 → 89 at :12) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at :10) / gru
        // 6be7ec00050d… (cid 48 → 87 at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru
        // e962f4a49508… (cid 46 → 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at
        // :04) / gru 5990e53d2fde… (cid 44 → 83 at :02) / sfo e583d837318a… (dual cid 49+50
        // → 88+89 at :13) / sfo 02525de8dfa3… (cid 47 → 86 → 39 at :09) / sfo ef71b6e32493…
        // (dual cid 45+46 → 84+85 at :07) / sfo b439248687d8… (cid 44 → 83 at :05) / sfo
        // c907c56a7c0c… (cid 43 → 82 → 38 at :03) at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
        // 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
        // 18:47:15Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z / 18:50:15Z steps: the
        // long-running fra-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:15.355253 [ERR] 127.0.0.1:47532 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:15.257555 [ERR] 127.0.0.1:48208 - cid:90 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:48:15.979352 [ERR] 127.0.0.1:42916 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:50:15.304023 [ERR] 127.0.0.1:56668 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact fra-product-nats / CN=fra-platform two-occurrence post-recycle shape
        // (fingerprint ec156a1db321…): same 7ef9d0a4… fra-platform leaf and fra product
        // issuer as 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… / 30e9c320e15b… /
        // fc4e0317d2a1… / 92ed0baffd5b… / 7904dd055f87… / 5804cb3aaf61… / 5d30a28d7f44… /
        // 639501fa4228… / eebfa17cec6b… / 669e26dad203… / 67d134aeab25… / b8e719ba13ca… /
        // aae9c8a6b484… / a66e03d58e6a… / a87539b37de1… / d86f81358e32… / bf210e609e7f…,
        // observed twice after product-NATS recycle (cid 52 → 91 at 18:46:17Z on
        // 127.0.0.1:47542 and 18:47:17Z on 127.0.0.1:48210; NotAfter still 18:45:24Z).
        // This is a two-occurrence post-bare-restart reconnect twin of the four-
        // occurrence sparse bf210e609e7f… storm (cid 51 → 90 → 47 → 40 two seconds earlier
        // on 47532/48208/42916/56668), four-occurrence dual-cid d86f81358e32… storm
        // (cid 49 → 50 → 88 → 89 on 38852/38860/40222/40240), two-occurrence a87539b37de1…
        // storm (cid 48 → 87 on 38842/40216), three-occurrence sparse a66e03d58e6a… storm,
        // four-occurrence dual-cid aae9c8a6b484…, single-occurrence b8e719ba13ca…, sparse
        // two-occurrence 67d134aeab25…, two-occurrence 669e26dad203… / eebfa17cec6b…,
        // three-occurrence 639501fa4228…, four-occurrence 5d30a28d7f44…, sparse two-
        // occurrence 5804cb3aaf61…, 7904dd055f87… / 92ed0baffd5b… four-occurrence storms,
        // sparse two-occurrence fc4e0317d2a1…, six-occurrence 30e9c320e15b…, denser
        // 25ef0004168c… / dacc95d0e7ba…, and single 1e8b88f75d43… storms, and the product-
        // plane peer of gru f106e39e815f… (cid 52 → 91 at :14) / gru d0feba5039c6… (cid:53
        // at :17) / gru 88ff8c404d3b… (cid 51 → 90 at :13) / gru 897b9ff7b37e… (cid 50 → 89
        // at :12) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at :10) / gru 6be7ec00050d…
        // (cid 48 → 87 at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508…
        // (cid 46 → 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru
        // 5990e53d2fde… (cid 44 → 83 at :02) / sfo e583d837318a… (dual cid 49+50 → 88+89 at
        // :13) / sfo 02525de8dfa3… (cid 47 → 86 → 39 at :09) / sfo ef71b6e32493… (dual cid
        // 45+46 → 84+85 at :07) / sfo b439248687d8… (cid 44 → 83 at :05) / sfo
        // c907c56a7c0c… (cid 43 → 82 → 38 at :03) at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z /
        // 18:46:17Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
        // 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z / 18:49:10Z /
        // 18:50:09Z / 18:50:15Z steps: the long-running fra-platform process re-presents
        // the expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:46:17.414230 [ERR] 127.0.0.1:47542 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-product-nats-1] [1] 2026/07/21 18:47:17.278810 [ERR] 127.0.0.1:48210 - cid:91 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-platform SHA-256: 7ef9d0a4a20b2b246d34be40d06dca81207252b94bc45bc610d911a85bfec4da; " +
                "CN=TerraScale fra product issuer SHA-256: 30a54ec8645211468d9411300dec823e30338a5cd4326f6ace64815d58dc1c0b)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform incident shape (fingerprint
        // 57ae70882ed5…): the platform process (not the HTTP health path) presents the
        // product-plane leaf. When NotAfter elapses, product NATS logs this server-side
        // line every reconnect while platform /health/ready stays green. Recovery must
        // match it, and platform probes must refuse the leaf so force-remint runs
        // without relying solely on product-NATS ConnectAsync failures.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:34.132719 [ERR] 127.0.0.1:54008 - cid:14634 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform multi-occurrence shape (fingerprint
        // 54fea6c92b78…): same 6b500765… gru-platform leaf and gru product issuer as
        // 57ae70882ed5…, with a denser cid recycle (14635 → 38 → 50 → 44 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z). This is the gru product-plane twin of
        // fra 25ef0004168c… and sfo b1723b879b59…, and the denser four-occurrence twin
        // of 57ae70882ed5…: the long-running gru-platform process presents the product
        // leaf; platform /health/ready can stay green while product NATS logs every
        // reconnect, and bare RestartAsync of product NATS while the platform PEM stays
        // expired re-emits every reconnect. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:40.091310 [ERR] 127.0.0.1:39438 - cid:14635 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:40.071006 [ERR] 127.0.0.1:38346 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:40.406032 [ERR] 127.0.0.1:54932 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:50:40.270545 [ERR] 127.0.0.1:56300 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform single-occurrence shape (fingerprint
        // 0b23b4fb5a75…): same 6b500765… gru-platform leaf and gru product issuer as
        // 57ae70882ed5… / 54fea6c92b78…, observed once at 18:45:42Z with low cid:31 on
        // 127.0.0.1:39462 after product-NATS recycle (NotAfter still 18:45:24Z). This is the
        // post-bare-restart reconnect twin of the denser 54fea6c92b78… storm: a single
        // long-running gru-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener. Recovery must match this line and force
        // remint from invalid product-plane client leaves (platforms) on the NATS resource
        // for every cell — bare RestartAsync of product NATS alone reloads the same expired
        // PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:42.859250 [ERR] 127.0.0.1:39462 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:42Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint 1364f1b0cdbc…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75…, observed four times after
        // product-NATS recycle (cid 32 → 70 → 71 → 40 at 18:45:43Z on 127.0.0.1:39470,
        // 18:46:43Z on 127.0.0.1:47014, 18:46:43Z on 127.0.0.1:47034 dual reconnect, and
        // 18:47:43Z on 127.0.0.1:38360; NotAfter still 18:45:24Z). This is the multi-
        // occurrence post-bare-restart reconnect twin of the single 0b23b4fb5a75… line and
        // the denser 54fea6c92b78… storm: the long-running gru-platform process re-presents
        // the expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence
        // and force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:43.941828 [ERR] 127.0.0.1:39470 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:43.962806 [ERR] 127.0.0.1:47014 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:43.968076 [ERR] 127.0.0.1:47034 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:43.732344 [ERR] 127.0.0.1:38360 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform five-occurrence post-recycle shape
        // (fingerprint 0cbc78bc3a3a…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc…, observed
        // five times after product-NATS recycle (cid 33 → 72 → 41 → 51 → 45 at 18:45:46Z on
        // 127.0.0.1:48834, 18:46:46Z on 127.0.0.1:60204, 18:47:46Z on 127.0.0.1:56364,
        // 18:48:46Z on 127.0.0.1:39346, and 18:50:46Z on 127.0.0.1:48414; NotAfter still
        // 18:45:24Z). This is the five-occurrence post-bare-restart reconnect twin of the
        // four-occurrence 1364f1b0cdbc… and single 0b23b4fb5a75… lines and the denser
        // 54fea6c92b78… storm: the long-running gru-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:46.027718 [ERR] 127.0.0.1:48834 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:46.050192 [ERR] 127.0.0.1:60204 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:46.037946 [ERR] 127.0.0.1:56364 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:46.375756 [ERR] 127.0.0.1:39346 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:50:46.277094 [ERR] 127.0.0.1:48414 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 6a1c43a93378…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a…, observed twice after product-NATS recycle (cid 34 → 73 at 18:45:48Z
        // on 127.0.0.1:48846 and 18:46:48Z on 127.0.0.1:60214; NotAfter still 18:45:24Z).
        // This is a sparse two-occurrence post-bare-restart reconnect twin of the five-
        // occurrence 0cbc78bc3a3a… (cid 33 → 72… on adjacent ports 48834/60204), four-
        // occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…, and denser 54fea6c92b78… storms:
        // the long-running gru-platform process re-presents the expired product leaf against
        // a freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:48.090538 [ERR] 127.0.0.1:48846 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:48.122114 [ERR] 127.0.0.1:60214 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint ed3f4504d5e1…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378…, observed four times after product-NATS recycle
        // (cid 35 → 36 → 75 → 36 at 18:45:50Z on 127.0.0.1:48870 / 48878 dual reconnect,
        // 18:46:50Z on 127.0.0.1:60244, and 18:49:50Z on 127.0.0.1:41546; NotAfter still
        // 18:45:24Z). This is a four-occurrence post-bare-restart reconnect twin of the
        // sparse two-occurrence 6a1c43a93378… pair (cid 34 → 73 on adjacent early ports
        // 48846/60214), five-occurrence 0cbc78bc3a3a…, four-occurrence 1364f1b0cdbc…,
        // single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-plane peer of
        // sfo 146c64f3fc52… / operator-read twins f4f92376efda… / 62860f83eeb6… at the same
        // wall-clock pair: the long-running gru-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:50.107351 [ERR] 127.0.0.1:48870 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:50.163987 [ERR] 127.0.0.1:48878 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:50.172433 [ERR] 127.0.0.1:60244 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:49:50.277225 [ERR] 127.0.0.1:41546 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint b22018f7aa7b…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1…, observed four times after
        // product-NATS recycle (cid 37 → 76 → 52 → 46 at 18:45:52Z on 127.0.0.1:48880,
        // 18:46:52Z on 127.0.0.1:60260, 18:48:52Z on 127.0.0.1:39364, and 18:50:52Z on
        // 127.0.0.1:48432; NotAfter still 18:45:24Z). This is a four-occurrence post-bare-
        // restart reconnect twin of the ed3f4504d5e1… four-occurrence storm (cid 35 → 36 →
        // 75 → 36 on adjacent early ports 48870/48878/60244), five-occurrence 0cbc78bc3a3a…
        // (cid 33 → 72… on adjacent ports 48834/60204/39346/48414), sparse two-occurrence
        // 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…, denser
        // 54fea6c92b78… storms, and the product-plane peer of sfo eaa27086a65c… / fra
        // 92ed0baffd5b… / operator-read twins at adjacent wall-clock :50/:51/:52 steps: the
        // long-running gru-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:52.210966 [ERR] 127.0.0.1:48880 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:52.220762 [ERR] 127.0.0.1:60260 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:52.388325 [ERR] 127.0.0.1:39364 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:50:52.353830 [ERR] 127.0.0.1:48432 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 9371738eec92…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b…, observed twice after
        // product-NATS recycle (cid 38 → 77 at 18:45:54Z on 127.0.0.1:48886 and 18:46:54Z on
        // 127.0.0.1:60264; NotAfter still 18:45:24Z). This is a sparse two-occurrence post-
        // bare-restart reconnect twin of the b22018f7aa7b… four-occurrence storm (cid 37 →
        // 76 → 52 → 46 on adjacent early ports 48880/60260), ed3f4504d5e1… four-occurrence
        // storm (cid 35 → 36 → 75 → 36), five-occurrence 0cbc78bc3a3a…, sparse two-occurrence
        // 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…, denser
        // 54fea6c92b78… storms, and the product-plane peer of sfo e33d87402e17… (cid 36 → 75
        // at :53) / fra 7904dd055f87… / operator-read twins at adjacent wall-clock
        // :52/:53/:54 steps: the long-running gru-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:54.250712 [ERR] 127.0.0.1:48886 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:54Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:54.237990 [ERR] 127.0.0.1:60264 - cid:77 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:54Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform single-occurrence post-recycle shape
        // (fingerprint 02a670a12fe6…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92…,
        // observed once after product-NATS recycle (cid:78 at 18:46:55Z on 127.0.0.1:53194;
        // NotAfter still 18:45:24Z). This is a single post-bare-restart reconnect twin of the
        // sparse two-occurrence 9371738eec92… pair (cid 38 → 77 one second earlier on
        // 48886/60264), four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence
        // 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…,
        // single 0b23b4fb5a75…, and denser 54fea6c92b78… storms: the long-running gru-platform
        // process re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match this line
        // and force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:55.784802 [ERR] 127.0.0.1:53194 - cid:78 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint be7bee33b946…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6…, observed four times after product-NATS recycle (cid 39 → 40 → 79 →
        // 37 at 18:45:56Z on 127.0.0.1:35188 / 127.0.0.1:35204 dual reconnect, 18:46:56Z on
        // 127.0.0.1:53210, and 18:49:56Z on 127.0.0.1:49142; NotAfter still 18:45:24Z). This
        // is a four-occurrence post-bare-restart reconnect twin of the single 02a670a12fe6…
        // (cid:78 one second earlier on 53194), sparse two-occurrence 9371738eec92…, four-
        // occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse
        // two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of gru operator-read
        // b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
        // fra operator-read c74671d2c0e4… at the same wall-clock :56 steps: the long-running
        // gru-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:56.052593 [ERR] 127.0.0.1:35188 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:56.327642 [ERR] 127.0.0.1:35204 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:56.270505 [ERR] 127.0.0.1:53210 - cid:79 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:49:56.238563 [ERR] 127.0.0.1:49142 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform three-occurrence post-recycle shape
        // (fingerprint a2e01c16a27c…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946…, observed three times after product-NATS recycle
        // (cid 41 → 80 → 53 at 18:45:58Z on 127.0.0.1:35206, 18:46:58Z on 127.0.0.1:53226,
        // and 18:48:58Z on 127.0.0.1:54632; NotAfter still 18:45:24Z). This is a three-
        // occurrence post-bare-restart reconnect twin of the four-occurrence be7bee33b946…
        // storm (cid 39 → 40 → 79 → 37 two seconds earlier on 35188/35204/53210/49142),
        // single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-occurrence
        // b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse two-
        // occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of sfo 9b960cc93f83…
        // (cid 39 → 78 → 43 at :57) / fra 5d30a28d7f44… / gru operator-read b252d8996050… /
        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
        // c74671d2c0e4… at adjacent wall-clock :56/:57/:58 steps: the long-running
        // gru-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:45:58.419347 [ERR] 127.0.0.1:35206 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:58.317437 [ERR] 127.0.0.1:53226 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:58.439337 [ERR] 127.0.0.1:54632 - cid:53 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:58Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 764b28c3439a…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c…, observed twice after product-NATS
        // recycle (cid 42 → 81 at 18:46:00Z on 127.0.0.1:35222 and 18:47:00Z on
        // 127.0.0.1:53234; NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the three-occurrence a2e01c16a27c… storm (cid 41 → 80 →
        // 53 two seconds earlier on 35206/53226/54632), four-occurrence be7bee33b946…,
        // single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-occurrence
        // b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse two-
        // occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of gru-controller
        // 25b92b919c66… (cid 36 → 68 → 77 → 52 at the same wall-clock 18:46:00Z /
        // 18:47:00Z steps): the long-running gru-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform
        // HTTP readiness can stay green. Recovery must match every occurrence and force
        // remint from invalid product-plane client leaves (platforms) on the NATS resource
        // for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:00.437399 [ERR] 127.0.0.1:35222 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:00.351163 [ERR] 127.0.0.1:53234 - cid:81 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 6d84bda1e560…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a…, observed twice after
        // product-NATS recycle (cid 43 → 82 at 18:46:01Z on 127.0.0.1:35228 and 18:47:01Z on
        // 127.0.0.1:53246; NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the two-occurrence 764b28c3439a… storm (cid 42 → 81 one
        // second earlier on 35222/53234), three-occurrence a2e01c16a27c…, four-occurrence
        // be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence 9371738eec92…,
        // four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…,
        // sparse two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single
        // 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-plane peer of sfo
        // eacb3282ca0c… (dual cid 41+42 → 80+81) / fra eebfa17cec6b… (cid 41 → 80) at the
        // same wall-clock 18:46:01Z / 18:47:01Z steps: the long-running gru-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match every
        // occurrence and force remint from invalid product-plane client leaves (platforms)
        // on the NATS resource for every cell — bare RestartAsync of product NATS alone
        // reloads the same expired PEM and re-emits the server-side handshake error on each
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:01.969358 [ERR] 127.0.0.1:35228 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:01.734673 [ERR] 127.0.0.1:53246 - cid:82 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 5990e53d2fde…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560…,
        // observed twice after product-NATS recycle (cid 44 → 83 at 18:46:02Z on
        // 127.0.0.1:35234 and 18:47:02Z on 127.0.0.1:53260; NotAfter still 18:45:24Z). This
        // is a two-occurrence post-bare-restart reconnect twin of the two-occurrence
        // 6d84bda1e560… storm (cid 43 → 82 one second earlier on 35228/53246), two-
        // occurrence 764b28c3439a…, three-occurrence a2e01c16a27c…, four-occurrence
        // be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence 9371738eec92…,
        // four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…,
        // sparse two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single
        // 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-plane peer of sfo
        // eacb3282ca0c… (dual cid 41+42 → 80+81) / fra eebfa17cec6b… (cid 41 → 80) / fra
        // 669e26dad203… (cid 42 → 81) at the adjacent wall-clock 18:46:01Z / 18:47:01Z
        // steps: the long-running gru-platform process re-presents the expired product leaf
        // against a freshly recycled product NATS listener while platform HTTP readiness can
        // stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:02.528667 [ERR] 127.0.0.1:35234 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:02Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:02.408164 [ERR] 127.0.0.1:53260 - cid:83 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:02Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint 3f4dc73e62f2…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde…, observed four times after product-NATS recycle (cid 45 → 84 → 44 →
        // 54 at 18:46:04Z on 127.0.0.1:44042, 18:47:04Z on 127.0.0.1:48200, 18:48:04Z on
        // 127.0.0.1:42712, and 18:49:04Z on 127.0.0.1:48152; NotAfter still 18:45:24Z). This
        // is a four-occurrence post-bare-restart reconnect twin of the two-occurrence
        // 5990e53d2fde… storm (cid 44 → 83 two seconds earlier on 35234/53260), two-
        // occurrence 6d84bda1e560…, two-occurrence 764b28c3439a…, three-occurrence
        // a2e01c16a27c…, four-occurrence be7bee33b946…, single 02a670a12fe6…, sparse two-
        // occurrence 9371738eec92…, four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-
        // occurrence 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence
        // 1364f1b0cdbc…, single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-
        // plane peer of sfo c907c56a7c0c… (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 →
        // 38) at the adjacent wall-clock 18:46:03Z / 18:47:03Z / 18:50:03Z steps: the long-
        // running gru-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:04.594459 [ERR] 127.0.0.1:44042 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:04Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:04.455137 [ERR] 127.0.0.1:48200 - cid:84 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:04Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:04.024127 [ERR] 127.0.0.1:42712 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:04Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:49:04.815578 [ERR] 127.0.0.1:48152 - cid:54 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:04Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint e962f4a49508…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2…, observed twice after product-NATS recycle (cid 46 →
        // 85 at 18:46:06Z on 127.0.0.1:44054 and 18:47:06Z on 127.0.0.1:48204; NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the four-
        // occurrence 3f4dc73e62f2… storm (cid 45 → 84 → 44 → 54 two seconds earlier on
        // 44042/48200/42712/48152), two-occurrence 5990e53d2fde… / 6d84bda1e560… /
        // 764b28c3439a…, three-occurrence a2e01c16a27c…, four-occurrence be7bee33b946…,
        // single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-occurrence
        // b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse two-
        // occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of sfo b439248687d8… (cid
        // 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo c907c56a7c0c… (cid 43 →
        // 82 → 38) / fra 67d134aeab25… (cid 43 → 38) at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z
        // steps: the long-running gru-platform process re-presents the expired product leaf
        // against a freshly recycled product NATS listener while platform HTTP readiness can
        // stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell — bare
        // RestartAsync of product NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:06.670127 [ERR] 127.0.0.1:44054 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:06Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:06.512832 [ERR] 127.0.0.1:48204 - cid:85 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:06Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 0401b56675fd…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508…, observed twice after product-NATS
        // recycle (cid 47 → 86 at 18:46:07Z on 127.0.0.1:44066 and 18:47:07Z on
        // 127.0.0.1:48220; NotAfter still 18:45:24Z). This is a two-occurrence
        // post-bare-restart reconnect twin of the two-occurrence e962f4a49508… storm (cid
        // 46 → 85 one second earlier on 44054/48204), four-occurrence 3f4dc73e62f2… storm
        // (cid 45 → 84 → 44 → 54 on 44042/48200/42712/48152), two-occurrence 5990e53d2fde… /
        // 6d84bda1e560… / 764b28c3439a…, three-occurrence a2e01c16a27c…, four-occurrence
        // be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-
        // occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse
        // two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of sfo ef71b6e32493… (dual
        // cid 45+46 → 84+85 at :07) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) /
        // sfo b439248687d8… (cid 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo
        // c907c56a7c0c… (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 → 38) at the adjacent
        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps: the long-running gru-platform
        // process re-presents the expired product leaf against a freshly recycled product
        // NATS listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:07.924416 [ERR] 127.0.0.1:44066 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:07.646690 [ERR] 127.0.0.1:48220 - cid:86 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 6be7ec00050d…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd…, observed twice
        // after product-NATS recycle (cid 48 → 87 at 18:46:08Z on 127.0.0.1:44070 and
        // 18:47:08Z on 127.0.0.1:48226; NotAfter still 18:45:24Z). This is a two-occurrence
        // post-bare-restart reconnect twin of the two-occurrence 0401b56675fd… storm (cid
        // 47 → 86 one second earlier on 44066/48220), two-occurrence e962f4a49508… storm
        // (cid 46 → 85 on 44054/48204), four-occurrence 3f4dc73e62f2… storm (cid 45 → 84 →
        // 44 → 54 on 44042/48200/42712/48152), two-occurrence 5990e53d2fde… /
        // 6d84bda1e560… / 764b28c3439a…, three-occurrence a2e01c16a27c…, four-occurrence
        // be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-
        // occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse
        // two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of sfo ef71b6e32493… (dual
        // cid 45+46 → 84+85 at :07) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) /
        // sfo b439248687d8… (cid 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo
        // c907c56a7c0c… (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 → 38) at the adjacent
        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z steps: the
        // long-running gru-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:08.747474 [ERR] 127.0.0.1:44070 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:08Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:08.574956 [ERR] 127.0.0.1:48226 - cid:87 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:08Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform four-occurrence post-recycle shape
        // (fingerprint 8a0aaf8cb1da…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd… / 6be7ec00050d…,
        // observed four times after product-NATS recycle (cid 49 → 88 → 45 → 55 at
        // 18:46:10Z on 127.0.0.1:44074, 18:47:10Z on 127.0.0.1:48238, 18:48:10Z on
        // 127.0.0.1:52880, and 18:49:10Z on 127.0.0.1:48166; NotAfter still 18:45:24Z).
        // This is a four-occurrence post-bare-restart reconnect twin of the two-occurrence
        // 6be7ec00050d… storm (cid 48 → 87 two seconds earlier on 44070/48226), two-
        // occurrence 0401b56675fd… storm (cid 47 → 86 on 44066/48220), two-occurrence
        // e962f4a49508… storm (cid 46 → 85 on 44054/48204), four-occurrence 3f4dc73e62f2…
        // storm (cid 45 → 84 → 44 → 54 on 44042/48200/42712/48152), two-occurrence
        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a…, three-occurrence a2e01c16a27c…,
        // four-occurrence be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence
        // 9371738eec92…, four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence
        // 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…,
        // single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-plane peer of
        // sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / fra aae9c8a6b484… (dual cid
        // 45+46 → 84+85 at :07) / sfo 02525de8dfa3… (cid 47 → 86 → 39 at :09) / fra
        // a66e03d58e6a… (cid 47 → 86 → 39 at :09) / sfo b439248687d8… (cid 44 → 83 at :05) /
        // fra b8e719ba13ca… (cid:44 at :05) / sfo c907c56a7c0c… (cid 43 → 82 → 38) / fra
        // 67d134aeab25… (cid 43 → 38) at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
        // 18:47:09Z / 18:47:10Z / 18:48:10Z / 18:49:10Z steps: the long-running
        // gru-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:10.792114 [ERR] 127.0.0.1:44074 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:10.682944 [ERR] 127.0.0.1:48238 - cid:88 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:48:10.024304 [ERR] 127.0.0.1:52880 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:49:10.769492 [ERR] 127.0.0.1:48166 - cid:55 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 897b9ff7b37e…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd… / 6be7ec00050d… /
        // 8a0aaf8cb1da…, observed twice after product-NATS recycle (cid 50 → 89 at
        // 18:46:12Z on 127.0.0.1:44082 and 18:47:12Z on 127.0.0.1:48252; NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the
        // four-occurrence 8a0aaf8cb1da… storm (cid 49 → 88 → 45 → 55 two seconds earlier on
        // 44074/48238/52880/48166), two-occurrence 6be7ec00050d… storm (cid 48 → 87 on
        // 44070/48226), two-occurrence 0401b56675fd… storm (cid 47 → 86 on 44066/48220),
        // two-occurrence e962f4a49508… storm (cid 46 → 85 on 44054/48204), four-occurrence
        // 3f4dc73e62f2… storm (cid 45 → 84 → 44 → 54 on 44042/48200/42712/48152), two-
        // occurrence 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a…, three-occurrence
        // a2e01c16a27c…, four-occurrence be7bee33b946…, single 02a670a12fe6…, sparse two-
        // occurrence 9371738eec92…, four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-
        // occurrence 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence
        // 1364f1b0cdbc…, single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the
        // product-plane peer of sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / fra
        // aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / sfo 02525de8dfa3… (cid 47 → 86 →
        // 39 at :09) / fra a66e03d58e6a… (cid 47 → 86 → 39 at :09) / sfo b439248687d8…
        // (cid 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo c907c56a7c0c…
        // (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 → 38) / fra a87539b37de1… (cid
        // 48 → 87 at :11) at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:46:12Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:48:10Z /
        // 18:49:10Z steps: the long-running gru-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform
        // HTTP readiness can stay green. Recovery must match every occurrence and force
        // remint from invalid product-plane client leaves (platforms) on the NATS resource
        // for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:12.882170 [ERR] 127.0.0.1:44082 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:12Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:12.766568 [ERR] 127.0.0.1:48252 - cid:89 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:12Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint 88ff8c404d3b…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd… / 6be7ec00050d… /
        // 8a0aaf8cb1da… / 897b9ff7b37e…, observed twice after product-NATS recycle (cid
        // 51 → 90 at 18:46:13Z on 127.0.0.1:44104 and 18:47:13Z on 127.0.0.1:48274;
        // NotAfter still 18:45:24Z). This is a two-occurrence post-bare-restart reconnect
        // twin of the two-occurrence 897b9ff7b37e… storm (cid 50 → 89 one second earlier on
        // 44082/48252), four-occurrence 8a0aaf8cb1da… storm (cid 49 → 88 → 45 → 55 on
        // 44074/48238/52880/48166), two-occurrence 6be7ec00050d… storm (cid 48 → 87 on
        // 44070/48226), two-occurrence 0401b56675fd… storm (cid 47 → 86 on 44066/48220),
        // two-occurrence e962f4a49508… storm (cid 46 → 85 on 44054/48204), four-occurrence
        // 3f4dc73e62f2… storm (cid 45 → 84 → 44 → 54 on 44042/48200/42712/48152), two-
        // occurrence 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a…, three-occurrence
        // a2e01c16a27c…, four-occurrence be7bee33b946…, single 02a670a12fe6…, sparse two-
        // occurrence 9371738eec92…, four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-
        // occurrence 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence
        // 1364f1b0cdbc…, single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the
        // product-plane peer of sfo e583d837318a… (dual cid 49+50 → 88+89 at :13) / fra
        // d86f81358e32… (dual cid 49+50 → 88+89 at :13) / sfo ef71b6e32493… (dual cid 45+46
        // → 84+85 at :07) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / sfo
        // 02525de8dfa3… (cid 47 → 86 → 39 at :09) / fra a66e03d58e6a… (cid 47 → 86 → 39 at
        // :09) / sfo b439248687d8… (cid 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05)
        // / sfo c907c56a7c0c… (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 → 38) / fra
        // a87539b37de1… (cid 48 → 87 at :11) at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
        // 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:48:10Z / 18:49:10Z steps: the long-
        // running gru-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-
        // emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:13.978893 [ERR] 127.0.0.1:44104 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:13.815682 [ERR] 127.0.0.1:48274 - cid:90 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform two-occurrence post-recycle shape
        // (fingerprint f106e39e815f…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd… / 6be7ec00050d… /
        // 8a0aaf8cb1da… / 897b9ff7b37e… / 88ff8c404d3b…, observed twice after product-NATS
        // recycle (cid 52 → 91 at 18:46:14Z on 127.0.0.1:38738 and 18:47:14Z on
        // 127.0.0.1:47750; NotAfter still 18:45:24Z). This is a two-occurrence
        // post-bare-restart reconnect twin of the two-occurrence 88ff8c404d3b… storm (cid
        // 51 → 90 one second earlier on 44104/48274), two-occurrence 897b9ff7b37e… storm
        // (cid 50 → 89 on 44082/48252), four-occurrence 8a0aaf8cb1da… storm (cid 49 → 88 →
        // 45 → 55 on 44074/48238/52880/48166), two-occurrence 6be7ec00050d… storm (cid 48 →
        // 87 on 44070/48226), two-occurrence 0401b56675fd… storm (cid 47 → 86 on
        // 44066/48220), two-occurrence e962f4a49508… storm (cid 46 → 85 on 44054/48204),
        // four-occurrence 3f4dc73e62f2… storm (cid 45 → 84 → 44 → 54 on
        // 44042/48200/42712/48152), two-occurrence 5990e53d2fde… / 6d84bda1e560… /
        // 764b28c3439a…, three-occurrence a2e01c16a27c…, four-occurrence be7bee33b946…,
        // single 02a670a12fe6…, sparse two-occurrence 9371738eec92…, four-occurrence
        // b22018f7aa7b… / ed3f4504d5e1…, five-occurrence 0cbc78bc3a3a…, sparse two-
        // occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…, single 0b23b4fb5a75…,
        // denser 54fea6c92b78… storms, and the product-plane peer of sfo e583d837318a…
        // (dual cid 49+50 → 88+89 at :13) / fra d86f81358e32… (dual cid 49+50 → 88+89 at
        // :13) / sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / fra aae9c8a6b484…
        // (dual cid 45+46 → 84+85 at :07) / sfo 02525de8dfa3… (cid 47 → 86 → 39 at :09) /
        // fra a66e03d58e6a… (cid 47 → 86 → 39 at :09) / sfo b439248687d8… (cid 44 → 83 at
        // :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo c907c56a7c0c… (cid 43 → 82 → 38) /
        // fra 67d134aeab25… (cid 43 → 38) / fra a87539b37de1… (cid 48 → 87 at :11) at the
        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
        // 18:46:14Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
        // 18:47:14Z / 18:48:10Z / 18:49:10Z steps: the long-running gru-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:14.930085 [ERR] 127.0.0.1:38738 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:14Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:47:14.822558 [ERR] 127.0.0.1:47750 - cid:91 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:14Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact gru-product-nats / CN=gru-platform single post-recycle shape
        // (fingerprint d0feba5039c6…): same 6b500765… gru-platform leaf and gru product
        // issuer as 57ae70882ed5… / 54fea6c92b78… / 0b23b4fb5a75… / 1364f1b0cdbc… /
        // 0cbc78bc3a3a… / 6a1c43a93378… / ed3f4504d5e1… / b22018f7aa7b… / 9371738eec92… /
        // 02a670a12fe6… / be7bee33b946… / a2e01c16a27c… / 764b28c3439a… / 6d84bda1e560… /
        // 5990e53d2fde… / 3f4dc73e62f2… / e962f4a49508… / 0401b56675fd… / 6be7ec00050d… /
        // 8a0aaf8cb1da… / 897b9ff7b37e… / 88ff8c404d3b… / f106e39e815f…, observed once after
        // product-NATS recycle (cid:53 at 18:46:17Z on 127.0.0.1:38752; NotAfter still
        // 18:45:24Z). This is a single post-bare-restart reconnect twin of the two-
        // occurrence f106e39e815f… storm (cid 52 → 91 three seconds earlier on
        // 38738/47750), two-occurrence 88ff8c404d3b… storm (cid 51 → 90 on 44104/48274),
        // two-occurrence 897b9ff7b37e… storm (cid 50 → 89 on 44082/48252), four-occurrence
        // 8a0aaf8cb1da… storm (cid 49 → 88 → 45 → 55), two-occurrence 6be7ec00050d… /
        // 0401b56675fd… / e962f4a49508…, four-occurrence 3f4dc73e62f2…, two-occurrence
        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a…, three-occurrence a2e01c16a27c…,
        // four-occurrence be7bee33b946…, single 02a670a12fe6…, sparse two-occurrence
        // 9371738eec92…, four-occurrence b22018f7aa7b… / ed3f4504d5e1…, five-occurrence
        // 0cbc78bc3a3a…, sparse two-occurrence 6a1c43a93378…, four-occurrence 1364f1b0cdbc…,
        // single 0b23b4fb5a75…, denser 54fea6c92b78… storms, and the product-plane peer of
        // sfo e583d837318a… (dual cid 49+50 → 88+89 at :13) / fra d86f81358e32… (dual cid
        // 49+50 → 88+89 at :13) / sfo ef71b6e32493… (dual cid 45+46 → 84+85 at :07) / fra
        // aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / sfo 02525de8dfa3… (cid 47 → 86 →
        // 39 at :09) / fra a66e03d58e6a… (cid 47 → 86 → 39 at :09) / sfo b439248687d8…
        // (cid 44 → 83 at :05) / fra b8e719ba13ca… (cid:44 at :05) / sfo c907c56a7c0c…
        // (cid 43 → 82 → 38) / fra 67d134aeab25… (cid 43 → 38) / fra a87539b37de1… (cid 48 →
        // 87 at :11) at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:17Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
        // 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:48:10Z / 18:49:10Z steps:
        // the long-running gru-platform process re-presents the expired product leaf against
        // a freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match this line and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-product-nats-1] [1] 2026/07/21 18:46:17.011790 [ERR] 127.0.0.1:38752 - cid:53 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-platform SHA-256: 6b500765eae962a8835795ccf60d79845ff36ef550a6646cdd9b45d64c07feb7; " +
                "CN=TerraScale gru product issuer SHA-256: 299d23e4d124cc154d4e3646a1ddaa6b53965e55e5526eed35e140107150361f)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform multi-occurrence shape (fingerprint
        // b1723b879b59…): same NotAfter (18:45:24Z) as the fra-platform product-plane twin
        // (25ef0004168c…), with cid recycle 14634 → 63 → 34 → 49 → 43 at 18:45:34Z /
        // 18:46:34Z / 18:47:34Z / 18:48:34Z / 18:50:34Z against the a914ebca… leaf and the
        // sfo product issuer. The long-running sfo-platform process (not the HTTP health
        // path) presents the product leaf; platform /health/ready can stay green while
        // product NATS logs every reconnect, and bare RestartAsync of product NATS while
        // the platform PEM stays expired re-emits every reconnect. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:34.135787 [ERR] 127.0.0.1:50184 - cid:14634 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:34.482478 [ERR] 127.0.0.1:59092 - cid:63 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:34.318498 [ERR] 127.0.0.1:43072 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:48:34.475349 [ERR] 127.0.0.1:55720 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:34.253808 [ERR] 127.0.0.1:56280 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform multi-occurrence shape (fingerprint
        // 77220dace263…): denser six-occurrence twin of b1723b879b59… against the same
        // a914ebca… platform leaf and sfo product issuer, with cid recycle 14635 → 67 → 37 →
        // 38 → 50 → 44 at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:47:40Z / 18:48:40Z /
        // 18:50:40Z (dual reconnect at 18:47:40Z). The long-running sfo-platform process
        // presents the product leaf while product NATS logs every reconnect. Recovery must
        // match every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:40.091213 [ERR] 127.0.0.1:60286 - cid:14635 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:40.710574 [ERR] 127.0.0.1:59136 - cid:67 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:40.073463 [ERR] 127.0.0.1:36992 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:40.490094 [ERR] 127.0.0.1:36994 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:48:40.410073 [ERR] 127.0.0.1:55738 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:40.269187 [ERR] 127.0.0.1:35360 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform four-occurrence post-recycle shape
        // (fingerprint d739f8d83bed…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263…, observed four times after product-NATS
        // recycle (cid 31 → 70 → 40 → 35 at 18:45:44Z on 127.0.0.1:39116, 18:46:44Z on
        // 127.0.0.1:59792, 18:47:44Z on 127.0.0.1:47888, and 18:49:44Z on 127.0.0.1:42228;
        // NotAfter still 18:45:24Z). This is the multi-occurrence post-bare-restart reconnect
        // twin of the denser b1723b879b59… / 77220dace263… storms and the gru post-recycle
        // twins 1364f1b0cdbc… / 0b23b4fb5a75…: the long-running sfo-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match every
        // occurrence and force remint from invalid product-plane client leaves (platforms)
        // on the NATS resource for every cell — bare RestartAsync of product NATS alone
        // reloads the same expired PEM and re-emits the server-side handshake error on each
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:44.812141 [ERR] 127.0.0.1:39116 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:44Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:44.815446 [ERR] 127.0.0.1:59792 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:44Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:44.675027 [ERR] 127.0.0.1:47888 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:44Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:49:44.344854 [ERR] 127.0.0.1:42228 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:44Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform five-occurrence post-recycle shape
        // (fingerprint a42bd88ac488…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed…, observed five times after
        // product-NATS recycle (cid 32 → 71 → 41 → 51 → 45 at 18:45:46Z on 127.0.0.1:39118,
        // 18:46:46Z on 127.0.0.1:59808, 18:47:46Z on 127.0.0.1:47908, 18:48:46Z on
        // 127.0.0.1:54714, and 18:50:46Z on 127.0.0.1:60650; NotAfter still 18:45:24Z). This
        // is the five-occurrence post-bare-restart reconnect twin of the four-occurrence
        // d739f8d83bed… and denser b1723b879b59… / 77220dace263… storms, and the sfo twin of
        // gru 0cbc78bc3a3a… / fra 30e9c320e15b…: the long-running sfo-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match every
        // occurrence and force remint from invalid product-plane client leaves (platforms)
        // on the NATS resource for every cell — bare RestartAsync of product NATS alone
        // reloads the same expired PEM and re-emits the server-side handshake error on each
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:46.916378 [ERR] 127.0.0.1:39118 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:46.916906 [ERR] 127.0.0.1:59808 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:46.037959 [ERR] 127.0.0.1:47908 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:48:46.388970 [ERR] 127.0.0.1:54714 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:46.291443 [ERR] 127.0.0.1:60650 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint 9f8f5f2cd955…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488…, observed
        // twice after product-NATS recycle (cid 33 → 72 at 18:45:48Z on 127.0.0.1:39126 and
        // 18:46:48Z on 127.0.0.1:59822; NotAfter still 18:45:24Z). This is a sparse two-
        // occurrence post-bare-restart reconnect twin of the five-occurrence a42bd88ac488…
        // (cid 32 → 71… on adjacent ports 39118/59808), four-occurrence d739f8d83bed…, denser
        // b1723b879b59… / 77220dace263… storms, and the sfo twin of gru 6a1c43a93378… /
        // fra fc4e0317d2a1…: the long-running sfo-platform process re-presents the expired
        // product leaf against a freshly recycled product NATS listener while platform HTTP
        // readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:48.974340 [ERR] 127.0.0.1:39126 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:48.993363 [ERR] 127.0.0.1:59822 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint 146c64f3fc52…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955…, observed twice after product-NATS recycle (cid 34 → 36 at
        // 18:45:50Z on 127.0.0.1:39142 and 18:49:50Z on 127.0.0.1:57178; NotAfter still
        // 18:45:24Z). This is a sparse two-occurrence post-bare-restart reconnect twin of
        // the one-minute 9f8f5f2cd955… pair (cid 33 → 72 on adjacent early ports), five-
        // occurrence a42bd88ac488…, four-occurrence d739f8d83bed…, denser b1723b879b59… /
        // 77220dace263… storms, and the product-plane peer of operator-read twins
        // f4f92376efda… / 62860f83eeb6… at the same wall-clock pair: the long-running
        // sfo-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:50.106850 [ERR] 127.0.0.1:39142 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:49:50.277983 [ERR] 127.0.0.1:57178 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform three-occurrence post-recycle shape
        // (fingerprint eaa27086a65c…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52…, observed three times after product-NATS recycle
        // (cid 35 → 74 → 42 at 18:45:51Z on 127.0.0.1:39154, 18:46:51Z on 127.0.0.1:59850,
        // and 18:47:51Z on 127.0.0.1:47938; NotAfter still 18:45:24Z). This is a three-
        // occurrence post-bare-restart reconnect twin of the sparse two-occurrence
        // 146c64f3fc52… pair (cid 34 → 36 on adjacent early port 39142), one-minute
        // 9f8f5f2cd955… pair, five-occurrence a42bd88ac488…, four-occurrence d739f8d83bed…,
        // denser b1723b879b59… / 77220dace263… storms, and the product-plane peer of gru
        // ed3f4504d5e1… / fra 92ed0baffd5b… / operator-read twins f4f92376efda… /
        // 62860f83eeb6… at adjacent wall-clock :50/:51 steps: the long-running sfo-platform
        // process re-presents the expired product leaf against a freshly recycled product
        // NATS listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:51.036413 [ERR] 127.0.0.1:39154 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:51.033157 [ERR] 127.0.0.1:59850 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:51.963045 [ERR] 127.0.0.1:47938 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint e33d87402e17…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c…, observed twice after product-NATS
        // recycle (cid 36 → 75 at 18:45:53Z on 127.0.0.1:39168 and 18:46:53Z on
        // 127.0.0.1:59854; NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the three-occurrence eaa27086a65c… storm (cid 35 → 74 →
        // 42 on adjacent early ports 39154/59850), sparse two-occurrence 146c64f3fc52… /
        // 9f8f5f2cd955…, five-occurrence a42bd88ac488…, four-occurrence d739f8d83bed…,
        // denser b1723b879b59… / 77220dace263… storms, and the sfo twin of fra 7904dd055f87…
        // (cid 36 → 75 at :52) / gru b22018f7aa7b… at adjacent wall-clock :52/:53 steps: the
        // long-running sfo-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:53.124160 [ERR] 127.0.0.1:39168 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:53Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:53.058304 [ERR] 127.0.0.1:59854 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:53Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform three-occurrence post-recycle shape
        // (fingerprint 16f64e5cf6e5…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17…, observed three times
        // after product-NATS recycle (cid 37 → 76 → 77 at 18:45:55Z on 127.0.0.1:45918 and
        // 18:46:55Z on 127.0.0.1:39530 / 127.0.0.1:39552 dual reconnect; NotAfter still
        // 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of the
        // two-occurrence e33d87402e17… pair (cid 36 → 75 on adjacent early ports), three-
        // occurrence eaa27086a65c… (cid 35 → 74 → 42), sparse two-occurrence 146c64f3fc52… /
        // 9f8f5f2cd955…, five-occurrence a42bd88ac488…, denser b1723b879b59… / 77220dace263…
        // storms, and the sfo twin of fra 5804cb3aaf61… (cid 37 → 76 at :54) / gru
        // 9371738eec92… at adjacent wall-clock :54/:55 steps: the long-running sfo-platform
        // process re-presents the expired product leaf against a freshly recycled product
        // NATS listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:55.234207 [ERR] 127.0.0.1:45918 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:55.099996 [ERR] 127.0.0.1:39530 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:55.785506 [ERR] 127.0.0.1:39552 - cid:77 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint 26b95f54769c…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5…,
        // observed twice after product-NATS recycle (cid 38 → 37 at 18:45:56Z on
        // 127.0.0.1:45940 and 18:49:56Z on 127.0.0.1:41844; NotAfter still 18:45:24Z). This
        // is a two-occurrence post-bare-restart reconnect twin of the three-occurrence
        // 16f64e5cf6e5… storm (cid 37 → 76 → 77 one second earlier on 45918/39530/39552),
        // two-occurrence e33d87402e17…, three-occurrence eaa27086a65c…, sparse two-occurrence
        // 146c64f3fc52… / 9f8f5f2cd955…, five-occurrence a42bd88ac488…, denser b1723b879b59… /
        // 77220dace263… storms, and the sfo twin of gru be7bee33b946… (cid 39 → 40 → 79 → 37
        // at the same wall-clock :56 steps) / gru operator-read b252d8996050… /
        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
        // c74671d2c0e4…: the long-running sfo-platform process re-presents the expired product
        // leaf against a freshly recycled product NATS listener while platform HTTP readiness
        // can stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell — bare
        // RestartAsync of product NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:56.051926 [ERR] 127.0.0.1:45940 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:49:56.232915 [ERR] 127.0.0.1:41844 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform three-occurrence post-recycle shape
        // (fingerprint 9b960cc93f83…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c…, observed three times after product-NATS recycle (cid 39 → 78 → 43
        // at 18:45:57Z on 127.0.0.1:45942, 18:46:57Z on 127.0.0.1:39560, and 18:47:57Z on
        // 127.0.0.1:52548; NotAfter still 18:45:24Z). This is a three-occurrence post-bare-
        // restart reconnect twin of the two-occurrence 26b95f54769c… pair (cid 38 → 37 one
        // second earlier on 45940/41844), three-occurrence 16f64e5cf6e5… storm (cid 37 → 76
        // → 77), two-occurrence e33d87402e17…, three-occurrence eaa27086a65c…, sparse two-
        // occurrence 146c64f3fc52… / 9f8f5f2cd955…, five-occurrence a42bd88ac488…, denser
        // b1723b879b59… / 77220dace263… storms, and the sfo twin of gru be7bee33b946…
        // (cid 39 → 40 → 79 → 37 at :56) / fra 5d30a28d7f44… (cid 38 → 39 → 78 → 37 at :56)
        // / gru operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
        // 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent wall-clock :56/:57
        // steps: the long-running sfo-platform process re-presents the expired product leaf
        // against a freshly recycled product NATS listener while platform HTTP readiness can
        // stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell — bare
        // RestartAsync of product NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:57.302817 [ERR] 127.0.0.1:45942 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:57.152385 [ERR] 127.0.0.1:39560 - cid:78 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:57.983112 [ERR] 127.0.0.1:52548 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint bf521ed338de…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83…, observed twice after product-NATS recycle (cid 40 →
        // 79 at 18:45:59Z on 127.0.0.1:45954 and 18:46:59Z on 127.0.0.1:39572; NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the three-
        // occurrence 9b960cc93f83… storm (cid 39 → 78 → 43 two seconds earlier on
        // 45942/39560/52548), two-occurrence 26b95f54769c… pair, three-occurrence
        // 16f64e5cf6e5… storm, two-occurrence e33d87402e17…, three-occurrence eaa27086a65c…,
        // sparse two-occurrence 146c64f3fc52… / 9f8f5f2cd955…, five-occurrence a42bd88ac488…,
        // denser b1723b879b59… / 77220dace263… storms, and the sfo twin of gru a2e01c16a27c…
        // (cid 41 → 80 → 53 at :58) / fra 639501fa4228… (cid 40 → 79 → 54 at :58) / gru
        // be7bee33b946… / fra 5d30a28d7f44… / gru operator-read b252d8996050… / gru-controller
        // a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read c74671d2c0e4…
        // at adjacent wall-clock :57/:58/:59 steps: the long-running sfo-platform process
        // re-presents the expired product leaf against a freshly recycled product NATS
        // listener while platform HTTP readiness can stay green. Recovery must match every
        // occurrence and force remint from invalid product-plane client leaves (platforms) on
        // the NATS resource for every cell — bare RestartAsync of product NATS alone reloads
        // the same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:45:59.338197 [ERR] 127.0.0.1:45954 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:59Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:59.249103 [ERR] 127.0.0.1:39572 - cid:79 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:59Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform four-occurrence dual-reconnect post-recycle
        // shape (fingerprint eacb3282ca0c…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de…, observed four times after product-NATS
        // recycle (cid 41 → 42 → 80 → 81 at 18:46:01Z on 127.0.0.1:45962 / 127.0.0.1:45986 dual
        // reconnect and 18:47:01Z on 127.0.0.1:39584 / 127.0.0.1:39598 dual reconnect; NotAfter
        // still 18:45:24Z). This is a four-occurrence dual-reconnect post-bare-restart twin of
        // the two-occurrence bf521ed338de… pair (cid 40 → 79 two seconds earlier on
        // 45954/39572), three-occurrence 9b960cc93f83… storm, two-occurrence 26b95f54769c…,
        // three-occurrence 16f64e5cf6e5…, denser b1723b879b59… / 77220dace263… storms, and the
        // sfo dual-reconnect denser twin of fra eebfa17cec6b… (cid 41 → 80 at 18:46:00Z /
        // 18:47:00Z) / gru 764b28c3439a… (cid 42 → 81 at 18:46:00Z / 18:47:00Z) / gru
        // a2e01c16a27c… / fra 639501fa4228… / gru be7bee33b946… / fra 5d30a28d7f44… / gru
        // operator-read b252d8996050… / gru-controller a9bf884a363b… / 25b92b919c66… / sfo
        // operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at the same wall-clock
        // 18:46:01Z / 18:47:01Z steps: the long-running sfo-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while platform
        // HTTP readiness can stay green. Recovery must match every occurrence and force remint
        // from invalid product-plane client leaves (platforms) on the NATS resource for every
        // cell — bare RestartAsync of product NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:01.384773 [ERR] 127.0.0.1:45962 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:01.969900 [ERR] 127.0.0.1:45986 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:01.321230 [ERR] 127.0.0.1:39584 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:01.736172 [ERR] 127.0.0.1:39598 - cid:81 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform three-occurrence post-recycle shape
        // (fingerprint c907c56a7c0c…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c…, observed three times
        // after product-NATS recycle (cid 43 → 82 → 38 at 18:46:03Z on 127.0.0.1:45990,
        // 18:47:03Z on 127.0.0.1:39600, and 18:50:03Z on 127.0.0.1:41872; NotAfter still
        // 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of the
        // four-occurrence dual-reconnect eacb3282ca0c… storm (cid 41 → 42 → 80 → 81 two
        // seconds earlier on 45962/45986/39584/39598), two-occurrence bf521ed338de… pair,
        // three-occurrence 9b960cc93f83…, denser b1723b879b59… / 77220dace263… storms, and the
        // product-plane peer of fra 67d134aeab25… (cid 43 → 38 at 18:46:03Z / 18:50:03Z) / gru
        // 6d84bda1e560… (cid 43 → 82 at 18:46:01Z / 18:47:01Z) / gru 5990e53d2fde… (cid 44 →
        // 83 at 18:46:02Z / 18:47:02Z) / gru 764b28c3439a… (cid 42 → 81) / fra 669e26dad203…
        // (cid 42 → 81) at the adjacent wall-clock 18:46:01Z / 18:46:02Z / 18:46:03Z /
        // 18:47:01Z / 18:47:02Z / 18:47:03Z / 18:50:03Z steps: the long-running sfo-platform
        // process re-presents the expired product leaf against a freshly recycled product
        // NATS listener while platform HTTP readiness can stay green. Recovery must match
        // every occurrence and force remint from invalid product-plane client leaves
        // (platforms) on the NATS resource for every cell — bare RestartAsync of product NATS
        // alone reloads the same expired PEM and re-emits the server-side handshake error on
        // each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:03.470539 [ERR] 127.0.0.1:45990 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:03Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:03.424097 [ERR] 127.0.0.1:39600 - cid:82 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:03Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:03.100574 [ERR] 127.0.0.1:41872 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:03Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint b439248687d8…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c…,
        // observed twice after product-NATS recycle (cid 44 → 83 at 18:46:05Z on
        // 127.0.0.1:36238 and 18:47:05Z on 127.0.0.1:46560; NotAfter still 18:45:24Z). This
        // is a two-occurrence post-bare-restart reconnect twin of the three-occurrence
        // c907c56a7c0c… storm (cid 43 → 82 → 38 two seconds earlier on 45990/39600/41872),
        // four-occurrence dual-reconnect eacb3282ca0c…, two-occurrence bf521ed338de…,
        // denser b1723b879b59… / 77220dace263… storms, and the product-plane peer of gru
        // 5990e53d2fde… (cid 44 → 83 at 18:46:02Z / 18:47:02Z) / fra b8e719ba13ca… (cid:44
        // at 18:46:05Z) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 6d84bda1e560…
        // (cid 43 → 82) / fra 67d134aeab25… (cid 43 → 38) at the adjacent wall-clock
        // 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:47:02Z / 18:47:03Z / 18:47:05Z
        // steps: the long-running sfo-platform process re-presents the expired product leaf
        // against a freshly recycled product NATS listener while platform HTTP readiness can
        // stay green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell — bare
        // RestartAsync of product NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:05.488768 [ERR] 127.0.0.1:36238 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:05.487022 [ERR] 127.0.0.1:46560 - cid:83 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform four-occurrence dual-cid post-recycle shape
        // (fingerprint ef71b6e32493…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8…, observed four times after product-NATS recycle (cid 45 → 46 at
        // 18:46:07Z on 127.0.0.1:36252 / 127.0.0.1:36270, and cid 84 → 85 at 18:47:07Z on
        // 127.0.0.1:46566 / 127.0.0.1:46574; NotAfter still 18:45:24Z). This is a
        // four-occurrence dual-cid post-bare-restart reconnect twin of the two-occurrence
        // b439248687d8… storm (cid 44 → 83 two seconds earlier on 36238/46560), three-
        // occurrence c907c56a7c0c…, four-occurrence dual-reconnect eacb3282ca0c…, two-
        // occurrence bf521ed338de…, denser b1723b879b59… / 77220dace263… storms, and the
        // product-plane peer of fra aae9c8a6b484… (cid 45 → 46 → 84 → 85 at :07) / gru
        // e962f4a49508… (cid 46 → 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at
        // :04) / gru 5990e53d2fde… (cid 44 → 83 at :02) / fra b8e719ba13ca… (cid:44 at :05)
        // / gru 6d84bda1e560… (cid 43 → 82) / fra 67d134aeab25… (cid 43 → 38) at the
        // adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
        // 18:46:07Z / 18:47:02Z / 18:47:03Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps: the
        // long-running sfo-platform process re-presents the expired product leaf against a
        // freshly recycled product NATS listener while platform HTTP readiness can stay
        // green. Recovery must match every occurrence and force remint from invalid
        // product-plane client leaves (platforms) on the NATS resource for every cell —
        // bare RestartAsync of product NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:07.514594 [ERR] 127.0.0.1:36252 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:07.925036 [ERR] 127.0.0.1:36270 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:07.543715 [ERR] 127.0.0.1:46566 - cid:84 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:07.646630 [ERR] 127.0.0.1:46574 - cid:85 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform three-occurrence sparse post-recycle shape
        // (fingerprint 02525de8dfa3…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8… / ef71b6e32493…, observed three times after product-NATS recycle
        // (cid 47 → 86 → 39 at 18:46:09Z on 127.0.0.1:36278, 18:47:09Z on 127.0.0.1:46582,
        // and 18:50:09Z on 127.0.0.1:45784; NotAfter still 18:45:24Z). This is a three-
        // occurrence sparse post-bare-restart reconnect twin of the four-occurrence dual-cid
        // ef71b6e32493… storm (cid 45 → 46 → 84 → 85 two seconds earlier on 36252/36270/
        // 46566/46574), two-occurrence b439248687d8…, three-occurrence c907c56a7c0c…, four-
        // occurrence dual-reconnect eacb3282ca0c…, two-occurrence bf521ed338de…, denser
        // b1723b879b59… / 77220dace263… storms, and the product-plane peer of fra
        // a66e03d58e6a… (cid 47 → 86 → 39 at :09) / gru 6be7ec00050d… (cid 48 → 87 at :08) /
        // gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 → 85 at :06) /
        // gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde… (cid 44 → 83
        // at :02) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / fra b8e719ba13ca…
        // (cid:44 at :05) / fra 67d134aeab25… (cid 43 → 38 at :03) at the adjacent
        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:46:09Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
        // 18:47:09Z / 18:50:09Z steps: the long-running sfo-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:09.545660 [ERR] 127.0.0.1:36278 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:09.609482 [ERR] 127.0.0.1:46582 - cid:86 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:09.326015 [ERR] 127.0.0.1:45784 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:09Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint 67300e8b3fe0…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8… / ef71b6e32493… / 02525de8dfa3…, observed twice after product-NATS
        // recycle (cid 48 → 87 at 18:46:11Z on 127.0.0.1:36290 and 18:47:11Z on
        // 127.0.0.1:46596; NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the three-occurrence sparse 02525de8dfa3… storm (cid
        // 47 → 86 → 39 two seconds earlier on 36278/46582/45784), four-occurrence dual-cid
        // ef71b6e32493…, two-occurrence b439248687d8…, three-occurrence c907c56a7c0c…,
        // four-occurrence dual-reconnect eacb3282ca0c…, two-occurrence bf521ed338de…,
        // denser b1723b879b59… / 77220dace263… storms, and the product-plane peer of fra
        // a87539b37de1… (cid 48 → 87 at :11) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at
        // :10) / fra a66e03d58e6a… (cid 47 → 86 → 39 at :09) / gru 6be7ec00050d… (cid 48 →
        // 87 at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 →
        // 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde…
        // (cid 44 → 83 at :02) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / fra
        // b8e719ba13ca… (cid:44 at :05) / fra 67d134aeab25… (cid 43 → 38 at :03) at the
        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
        // 18:47:11Z / 18:50:09Z steps: the long-running sfo-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:11.624036 [ERR] 127.0.0.1:36290 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:11.704418 [ERR] 127.0.0.1:46596 - cid:87 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform four-occurrence dual-cid post-recycle shape
        // (fingerprint e583d837318a…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8… / ef71b6e32493… / 02525de8dfa3… / 67300e8b3fe0…, observed four times
        // after product-NATS recycle (cid 49 → 50 → 88 → 89 at 18:46:13Z on 127.0.0.1:36302 /
        // 127.0.0.1:36324 dual cid 49+50 and 18:47:13Z on 127.0.0.1:46602 /
        // 127.0.0.1:46614 dual cid 88+89; NotAfter still 18:45:24Z). This is a four-
        // occurrence dual-cid post-bare-restart reconnect twin of the two-occurrence
        // 67300e8b3fe0… storm (cid 48 → 87 two seconds earlier on 36290/46596), three-
        // occurrence sparse 02525de8dfa3… storm, four-occurrence dual-cid ef71b6e32493…,
        // two-occurrence b439248687d8…, three-occurrence c907c56a7c0c…, four-occurrence
        // dual-reconnect eacb3282ca0c…, two-occurrence bf521ed338de…, denser b1723b879b59… /
        // 77220dace263… storms, and the product-plane peer of fra d86f81358e32… (cid 49 →
        // 50 → 88 → 89 at :13) / fra a87539b37de1… (cid 48 → 87 at :11) / gru 897b9ff7b37e…
        // (cid 50 → 89 at :12) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at :10) / fra
        // a66e03d58e6a… (cid 47 → 86 → 39 at :09) / gru 6be7ec00050d… (cid 48 → 87 at :08) /
        // gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 → 85 at :06) /
        // gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde… (cid 44 → 83
        // at :02) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / fra b8e719ba13ca…
        // (cid:44 at :05) / fra 67d134aeab25… (cid 43 → 38 at :03) at the adjacent wall-
        // clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:50:09Z steps: the long-running
        // sfo-platform process re-presents the expired product leaf against a freshly
        // recycled product NATS listener while platform HTTP readiness can stay green.
        // Recovery must match every occurrence and force remint from invalid product-plane
        // client leaves (platforms) on the NATS resource for every cell — bare RestartAsync
        // of product NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:13.649559 [ERR] 127.0.0.1:36302 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:13.979266 [ERR] 127.0.0.1:36324 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:13.786178 [ERR] 127.0.0.1:46602 - cid:88 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:13.816530 [ERR] 127.0.0.1:46614 - cid:89 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform four-occurrence sparse post-recycle shape
        // (fingerprint e7810573222a…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8… / ef71b6e32493… / 02525de8dfa3… / 67300e8b3fe0… / e583d837318a…,
        // observed four times after product-NATS recycle (cid 51 → 90 → 46 → 40 at
        // 18:46:15Z on 127.0.0.1:59838, 18:47:15Z on 127.0.0.1:55568, 18:48:15Z on
        // 127.0.0.1:35124, and 18:50:15Z on 127.0.0.1:42264; NotAfter still 18:45:24Z). This
        // is a four-occurrence sparse post-bare-restart reconnect twin of the four-
        // occurrence dual-cid e583d837318a… storm (cid 49 → 50 → 88 → 89 two seconds
        // earlier on 36302/36324/46602/46614), two-occurrence 67300e8b3fe0… storm (cid 48 →
        // 87 on 36290/46596), three-occurrence sparse 02525de8dfa3… storm, four-occurrence
        // dual-cid ef71b6e32493…, two-occurrence b439248687d8…, three-occurrence
        // c907c56a7c0c…, four-occurrence dual-reconnect eacb3282ca0c…, two-occurrence
        // bf521ed338de…, denser b1723b879b59… / 77220dace263… storms, and the product-plane
        // peer of fra bf210e609e7f… (cid 51 → 90 → 47 → 40 at :15) / gru f106e39e815f…
        // (cid 52 → 91 at :14) / gru 88ff8c404d3b… (cid 51 → 90 at :13) / fra d86f81358e32…
        // (cid 49 → 50 → 88 → 89 at :13) / gru 897b9ff7b37e… (cid 50 → 89 at :12) / gru
        // 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at :10) / fra a87539b37de1… (cid 48 → 87 at
        // :11) / fra a66e03d58e6a… (cid 47 → 86 → 39 at :09) / gru 6be7ec00050d… (cid 48 →
        // 87 at :08) / gru 0401b56675fd… (cid 47 → 86 at :07) / gru e962f4a49508… (cid 46 →
        // 85 at :06) / gru 3f4dc73e62f2… (cid 45 → 84 → 44 → 54 at :04) / gru 5990e53d2fde…
        // (cid 44 → 83 at :02) / fra aae9c8a6b484… (dual cid 45+46 → 84+85 at :07) / fra
        // b8e719ba13ca… (cid:44 at :05) / fra 67d134aeab25… (cid 43 → 38 at :03) at the
        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z /
        // 18:46:14Z / 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
        // 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:48:10Z / 18:48:15Z / 18:49:10Z /
        // 18:50:09Z / 18:50:15Z steps: the long-running sfo-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:15.688001 [ERR] 127.0.0.1:59838 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:15.865089 [ERR] 127.0.0.1:55568 - cid:90 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:48:15.980588 [ERR] 127.0.0.1:35124 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:50:15.303294 [ERR] 127.0.0.1:42264 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Exact sfo-product-nats / CN=sfo-platform two-occurrence post-recycle shape
        // (fingerprint e7adbe3390eb…): same a914ebca… sfo-platform leaf and sfo product
        // issuer as b1723b879b59… / 77220dace263… / d739f8d83bed… / a42bd88ac488… /
        // 9f8f5f2cd955… / 146c64f3fc52… / eaa27086a65c… / e33d87402e17… / 16f64e5cf6e5… /
        // 26b95f54769c… / 9b960cc93f83… / bf521ed338de… / eacb3282ca0c… / c907c56a7c0c… /
        // b439248687d8… / ef71b6e32493… / 02525de8dfa3… / 67300e8b3fe0… / e583d837318a… /
        // e7810573222a…, observed twice after product-NATS recycle (cid 52 → 91 at
        // 18:46:17Z on 127.0.0.1:59852 and 18:47:17Z on 127.0.0.1:55584; NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the
        // four-occurrence sparse e7810573222a… storm (cid 51 → 90 → 46 → 40 two seconds
        // earlier on 59838/55568/35124/42264), four-occurrence dual-cid e583d837318a…
        // storm (cid 49 → 50 → 88 → 89 on 36302/36324/46602/46614), two-occurrence
        // 67300e8b3fe0… storm (cid 48 → 87 on 36290/46596), three-occurrence sparse
        // 02525de8dfa3… storm, four-occurrence dual-cid ef71b6e32493…, two-occurrence
        // b439248687d8…, three-occurrence c907c56a7c0c…, four-occurrence dual-reconnect
        // eacb3282ca0c…, two-occurrence bf521ed338de…, denser b1723b879b59… /
        // 77220dace263… storms, and the product-plane peer of fra ec156a1db321… (cid 52 →
        // 91 at :17) / gru d0feba5039c6… (cid:53 at :17) / fra bf210e609e7f… (cid 51 → 90 →
        // 47 → 40 at :15) / gru f106e39e815f… (cid 52 → 91 at :14) / gru 88ff8c404d3b…
        // (cid 51 → 90 at :13) / fra d86f81358e32… (cid 49 → 50 → 88 → 89 at :13) / gru
        // 897b9ff7b37e… (cid 50 → 89 at :12) / gru 8a0aaf8cb1da… (cid 49 → 88 → 45 → 55 at
        // :10) / fra a87539b37de1… (cid 48 → 87 at :11) / fra a66e03d58e6a… (cid 47 → 86 →
        // 39 at :09) / gru 6be7ec00050d… (cid 48 → 87 at :08) / gru 0401b56675fd… (cid 47 →
        // 86 at :07) / gru e962f4a49508… (cid 46 → 85 at :06) / gru 3f4dc73e62f2… (cid 45 →
        // 84 → 44 → 54 at :04) / gru 5990e53d2fde… (cid 44 → 83 at :02) / fra aae9c8a6b484…
        // (dual cid 45+46 → 84+85 at :07) / fra b8e719ba13ca… (cid:44 at :05) / fra
        // 67d134aeab25… (cid 43 → 38 at :03) at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z /
        // 18:46:17Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
        // 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z / 18:49:10Z /
        // 18:50:09Z / 18:50:15Z steps: the long-running sfo-platform process re-presents the
        // expired product leaf against a freshly recycled product NATS listener while
        // platform HTTP readiness can stay green. Recovery must match every occurrence and
        // force remint from invalid product-plane client leaves (platforms) on the NATS
        // resource for every cell — bare RestartAsync of product NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on each reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:46:17.791630 [ERR] 127.0.0.1:59852 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-product-nats-1] [1] 2026/07/21 18:47:17.884440 [ERR] 127.0.0.1:55584 - cid:91 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-platform SHA-256: a914ebcaf4028d5320fafe933d8a5b04c669a6ff5a65809a534783fdd48f3c18; " +
                "CN=TerraScale sfo product issuer SHA-256: fc09889c352d90574951becc5dfd4bbbea50beb48c000d3e7ed8dfdb02aff45d)"))
            .IsTrue();
        // Control-plane twin: CN=fra-controller-1 against fra-control-nats (same NotAfter
        // window as the continuous-lab remint race that must stop NATS before clients
        // finish draining, otherwise server logs keep recording expired handshakes).
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:28.168910 [ERR] 127.0.0.1:55276 - cid:29236 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:28Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 incident shape (fingerprint
        // ca1ca558…): remint must stop NATS before sequential client teardown so this
        // server-side line cannot keep firing for every still-running peer.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:28.167747 [ERR] 127.0.0.1:45732 - cid:29236 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:28Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 multi-occurrence shape (fingerprint
        // f490b625…): same NotAfter (18:45:24Z) and cid recycle pattern as the operator-read
        // twins (29238 → 63 → 70 at 18:45:34Z / 18:48:34Z / 18:50:34Z). The long-running
        // controller process (not the operator-read probe) presents this leaf; bare
        // RestartAsync of NATS while the controller PEM stays expired re-emits every
        // reconnect. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:34.133150 [ERR] 127.0.0.1:45756 - cid:29238 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:34.475657 [ERR] 127.0.0.1:51920 - cid:63 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:34.259157 [ERR] 127.0.0.1:55514 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 multi-occurrence shape (fingerprint
        // 9815ef5a…): same f56fe7a4… sfo-controller-1 leaf and sfo control issuer as
        // f490b625…, with a denser cid recycle (29240 → 34 → 35 → 66 → 73 at 18:45:40Z /
        // 18:47:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z, dual reconnect at 18:47:40Z). The
        // long-running sfo-controller-1 process (not the operator-read probe) presents this
        // leaf; bare RestartAsync of NATS while the controller PEM stays expired re-emits
        // every reconnect. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:40.092139 [ERR] 127.0.0.1:55370 - cid:29240 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:40.071730 [ERR] 127.0.0.1:34612 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:40.470050 [ERR] 127.0.0.1:34620 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:40.410764 [ERR] 127.0.0.1:51952 - cid:66 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:40.270161 [ERR] 127.0.0.1:41748 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 two-occurrence post-recycle shape
        // (fingerprint 4eeeee0520a1…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a…, observed twice after control-NATS recycle
        // (cid 28 → 36 at 18:45:45Z on 127.0.0.1:50552 and 18:47:45Z on 127.0.0.1:37302,
        // NotAfter still 18:45:24Z). This is the sparse post-bare-restart reconnect twin of
        // the denser 9815ef5a… storm and the sfo twin of gru 003657d51ecd…: the long-running
        // sfo-controller-1 process re-presents the expired control leaf against a freshly
        // recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:45.341713 [ERR] 127.0.0.1:50552 - cid:28 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:45.579662 [ERR] 127.0.0.1:37302 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 two-occurrence post-recycle shape
        // (fingerprint e8e55fe0bef9…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1…, observed twice after control-NATS
        // recycle (cid 29 → 61 at 18:45:47Z on 127.0.0.1:50560 and 18:46:47Z on
        // 127.0.0.1:55476, NotAfter still 18:45:24Z). This is a second sparse two-occurrence
        // post-bare-restart reconnect twin of the denser 9815ef5a… storm and the already-
        // locked 4eeeee0520a1… pair (cid 28 → 36), and the sfo twin of the leading cid 29 → 61
        // steps of gru b9dc4dd1a8ef…: the long-running sfo-controller-1 process re-presents
        // the expired control leaf against a freshly recycled control NATS listener while
        // probes still present only operator-read. Recovery must match every occurrence and
        // force remint from invalid control-plane client leaves (including controllers) on the
        // NATS resource for every cell — bare RestartAsync of control NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:47.421255 [ERR] 127.0.0.1:50560 - cid:29 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:47Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:47.179544 [ERR] 127.0.0.1:55476 - cid:61 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:47Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 three-occurrence post-recycle shape
        // (fingerprint 412baaa56842…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9…, observed three times
        // after control-NATS recycle (cid 31 → 39 → 47 at 18:45:50Z on 127.0.0.1:50606,
        // 18:47:50Z on 127.0.0.1:37360, and 18:49:50Z on 127.0.0.1:34092, NotAfter still
        // 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of the denser
        // 9815ef5a… storm and the already-locked sparse 4eeeee0520a1… / e8e55fe0bef9… pairs,
        // and the sfo twin of the cid 30/31-leading steps of gru 7b6a047263d8…: the long-running
        // sfo-controller-1 process re-presents the expired control leaf against a freshly
        // recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:50.106811 [ERR] 127.0.0.1:50606 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:50.652430 [ERR] 127.0.0.1:37360 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:50.277910 [ERR] 127.0.0.1:34092 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 four-occurrence post-recycle shape
        // (fingerprint 71cf8514f4d6…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842…,
        // observed four times after control-NATS recycle (cid 32 → 41 → 71 → 48 at 18:45:51Z
        // on 127.0.0.1:50616, 18:47:51Z on 127.0.0.1:37414, 18:48:51Z on 127.0.0.1:58882, and
        // 18:49:51Z on 127.0.0.1:34106, NotAfter still 18:45:24Z). This is a four-occurrence
        // post-bare-restart reconnect twin of the denser 9815ef5a… storm and the already-
        // locked sparse 4eeeee0520a1… / e8e55fe0bef9… pairs and three-occurrence
        // 412baaa56842… (cid 31 → 39 → 47 one second earlier), and the sfo twin of the denser
        // mid-window reconnects of gru 7b6a047263d8…: the long-running sfo-controller-1
        // process re-presents the expired control leaf against a freshly recycled control
        // NATS listener while probes still present only operator-read. Recovery must match
        // every occurrence and force remint from invalid control-plane client leaves
        // (including controllers) on the NATS resource for every cell — bare RestartAsync of
        // control NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:51.525529 [ERR] 127.0.0.1:50616 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:51.964205 [ERR] 127.0.0.1:37414 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:51.216974 [ERR] 127.0.0.1:58882 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:51.128857 [ERR] 127.0.0.1:34106 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:51Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 four-occurrence post-recycle shape
        // (fingerprint ce40d219dc90…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6…, observed four times after control-NATS recycle (cid 64 → 73 → 78 → 80
        // at 18:46:52Z on 127.0.0.1:55524, 18:48:52Z on 127.0.0.1:58922, and 18:50:52Z on
        // 127.0.0.1:52222 / 127.0.0.1:52258 dual, NotAfter still 18:45:24Z). This is a
        // four-occurrence post-bare-restart reconnect twin of the already-locked 71cf8514f4d6…
        // storm (cid 32 → 41 → 71 → 48 one minute earlier) and the denser mid-window
        // reconnects of gru-platform / fra-controller at adjacent wall-clock :52 steps: the
        // long-running sfo-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:52.195072 [ERR] 127.0.0.1:55524 - cid:64 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:52.388950 [ERR] 127.0.0.1:58922 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:52.033035 [ERR] 127.0.0.1:52222 - cid:78 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:52.362663 [ERR] 127.0.0.1:52258 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 five-occurrence post-recycle shape
        // (fingerprint fc867739e2e2…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90…, observed five times after control-NATS recycle
        // (cid 34 → 35 → 74 → 49 → 51 at 18:45:56Z on 127.0.0.1:52202 / 127.0.0.1:52218 dual,
        // 18:48:56Z on 127.0.0.1:51334, and 18:49:56Z on 127.0.0.1:36626 / 127.0.0.1:36656 dual,
        // NotAfter still 18:45:24Z). This is a five-occurrence post-bare-restart reconnect twin
        // of the already-locked ce40d219dc90… / 71cf8514f4d6… storms and the sfo twin of the
        // same wall-clock :56 steps as gru a9bf884a363b… / operator-read b252d8996050…: the
        // long-running sfo-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:56.053162 [ERR] 127.0.0.1:52202 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:56.613942 [ERR] 127.0.0.1:52218 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:56.270610 [ERR] 127.0.0.1:51334 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:56.196890 [ERR] 127.0.0.1:36626 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:56.240291 [ERR] 127.0.0.1:36656 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 five-occurrence post-recycle shape
        // (fingerprint 3db5efff618c…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2…, observed five times after control-NATS
        // recycle (cid 36 → 38 → 69 → 77 → 52 at 18:46:01Z on 127.0.0.1:52226 /
        // 127.0.0.1:52264 dual, 18:47:01Z on 127.0.0.1:34778, 18:49:01Z on 127.0.0.1:51374, and
        // 18:50:01Z on 127.0.0.1:36672, NotAfter still 18:45:24Z). This is a five-occurrence
        // post-bare-restart reconnect twin of the already-locked fc867739e2e2… / ce40d219dc90…
        // / 71cf8514f4d6… storms and the sfo twin of the same wall-clock :01 steps as sfo-
        // platform eacb3282ca0c… / gru-platform 764b28c3439a… / fra-platform eebfa17cec6b…: the
        // long-running sfo-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:01.672775 [ERR] 127.0.0.1:52226 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:01.969455 [ERR] 127.0.0.1:52264 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:01.736855 [ERR] 127.0.0.1:34778 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:01.344112 [ERR] 127.0.0.1:51374 - cid:77 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:01.299457 [ERR] 127.0.0.1:36672 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 three-occurrence post-recycle shape
        // (fingerprint c9f4a06686ba…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c…, observed three times
        // after control-NATS recycle (cid 39 → 80 → 55 at 18:46:06Z on 127.0.0.1:49160,
        // 18:49:06Z on 127.0.0.1:37578, and 18:50:06Z on 127.0.0.1:48750, NotAfter still
        // 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of the
        // already-locked 3db5efff618c… / fc867739e2e2… storms and the sfo peer of gru
        // 024cbd22bdf4… (cid 39 → 71 → 80 → 55 at the adjacent :05 steps, sparse without the
        // mid-window cid 71): the long-running sfo-controller-1 process re-presents the
        // expired control leaf against a freshly recycled control NATS listener while probes
        // still present only operator-read. Recovery must match every occurrence and force
        // remint from invalid control-plane client leaves (including controllers) on the NATS
        // resource for every cell — bare RestartAsync of control NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:06.776401 [ERR] 127.0.0.1:49160 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:06Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:06.433222 [ERR] 127.0.0.1:37578 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:06Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:06.405293 [ERR] 127.0.0.1:48750 - cid:55 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:06Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 three-occurrence post-recycle shape
        // (fingerprint a5ee4c55235d…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… / c9f4a06686ba…,
        // observed three times after control-NATS recycle (cid 41 → 71 → 73 at 18:46:07Z on
        // 127.0.0.1:49206 and 18:47:07Z on 127.0.0.1:53864 / 127.0.0.1:53886 dual, NotAfter
        // still 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of
        // the already-locked c9f4a06686ba… storm and the sfo peer of gru e7ad7a71e395… (cid
        // 41 → 73 at the same wall-clock :07 steps on 49008/42932), operator-read
        // 58dda0785551… (cid 40 → 72), gru 5c56829c01e4…, fra d26af782af24…, fra-controller
        // 88eec19ebb94…, sfo-platform ef71b6e32493…, and gru-platform 0401b56675fd…: the
        // long-running sfo-controller-1 process re-presents the expired control leaf against
        // a freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:07.925172 [ERR] 127.0.0.1:49206 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:07.329900 [ERR] 127.0.0.1:53864 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:07.647042 [ERR] 127.0.0.1:53886 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 three-occurrence post-recycle shape
        // (fingerprint 914b99d5fbc6…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… / c9f4a06686ba… /
        // a5ee4c55235d…, observed three times after control-NATS recycle (cid 42 → 83 → 58 at
        // 18:46:11Z on 127.0.0.1:49220, 18:49:11Z on 127.0.0.1:37634, and 18:50:11Z on
        // 127.0.0.1:48798, NotAfter still 18:45:24Z). This is a three-occurrence post-bare-
        // restart reconnect twin of the already-locked a5ee4c55235d… storm (cid 41 → 71 → 73
        // four seconds earlier on adjacent port 49206) and the sfo peer of gru 96fe8dda09bb…
        // (cid 42 → 74 → 50 → 51 → 81 → 83 → 58 at the adjacent :10 steps, sparse without the
        // mid-window dual-cid reconnects): the long-running sfo-controller-1 process
        // re-presents the expired control leaf against a freshly recycled control NATS
        // listener while probes still present only operator-read. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:11.805563 [ERR] 127.0.0.1:49220 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:11.476872 [ERR] 127.0.0.1:37634 - cid:83 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:11.455260 [ERR] 127.0.0.1:48798 - cid:58 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:11Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 two-occurrence post-recycle shape
        // (fingerprint 53b4362b4444…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… / c9f4a06686ba… /
        // a5ee4c55235d… / 914b99d5fbc6…, observed twice after control-NATS recycle (cid 44 →
        // 76 at 18:46:13Z on 127.0.0.1:49260 and 18:47:13Z on 127.0.0.1:53940, NotAfter still
        // 18:45:24Z). This is a two-occurrence post-bare-restart reconnect twin of the
        // already-locked 914b99d5fbc6… storm (cid 42 → 83 → 58 two seconds earlier on adjacent
        // port 49220) and the sfo peer of gru operator-read 9dd8feb97fa2… (cid 43 → 75) / fra
        // operator-read 424b0b6af457… (cid 43 → 75) / sfo-platform e583d837318a… / fra-platform
        // d86f81358e32… at the same wall-clock :13 steps: the long-running sfo-controller-1
        // process re-presents the expired control leaf against a freshly recycled control NATS
        // listener while probes still present only operator-read. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:13.979358 [ERR] 127.0.0.1:49260 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:13.817191 [ERR] 127.0.0.1:53940 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=sfo-controller-1 three-occurrence post-recycle shape
        // (fingerprint bbdb6e0d6006…): same f56fe7a4… sfo-controller-1 leaf and sfo control
        // issuer as f490b625… / 9815ef5a… / 4eeeee0520a1… / e8e55fe0bef9… / 412baaa56842… /
        // 71cf8514f4d6… / ce40d219dc90… / fc867739e2e2… / 3db5efff618c… / c9f4a06686ba… /
        // a5ee4c55235d… / 914b99d5fbc6… / 53b4362b4444…, observed three times after
        // control-NATS recycle (cid 45 → 29 → 61 at 18:46:16Z on 127.0.0.1:40982,
        // 18:49:16Z on 127.0.0.1:35628, and 18:50:16Z on 127.0.0.1:52900, NotAfter still
        // 18:45:24Z). This is a three-seconds-later three-occurrence post-bare-restart
        // reconnect twin of the already-locked 53b4362b4444… storm (cid 44 → 76 on
        // 49260/53940 at :13) and the sfo peer of gru d00ef05a1026… (cid 45 → 77 → 52 →
        // 54 → 29 → 60 → 61 at the adjacent wall-clock :15 steps): the long-running
        // sfo-controller-1 process re-presents the expired control leaf against a freshly
        // recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:16.858017 [ERR] 127.0.0.1:40982 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:16Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:16.818899 [ERR] 127.0.0.1:35628 - cid:29 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:16Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:16.549258 [ERR] 127.0.0.1:52900 - cid:61 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:16Z is after 2026-07-21T18:45:24Z " +
                "(CN=sfo-controller-1 SHA-256: f56fe7a4496ad6cfa1b263537e88f65c11105efa67c23db7d1bebfa35b5cfcc7; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 multi-occurrence shape (fingerprint
        // c2bf6b539a62…): same NotAfter (18:45:24Z) as the sfo controller twin, with an
        // extra mid-window reconnect (cid 29238 → 32 → 63 → 70 at 18:45:34Z / 18:47:34Z /
        // 18:48:34Z / 18:50:34Z). The long-running gru-controller-1 process (not the
        // operator-read probe) presents this leaf; bare RestartAsync of NATS while the
        // controller PEM stays expired re-emits every reconnect. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell, not only sfo.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:34.132839 [ERR] 127.0.0.1:49506 - cid:29238 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:34.670147 [ERR] 127.0.0.1:36448 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:34.476555 [ERR] 127.0.0.1:41090 - cid:63 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:34.253711 [ERR] 127.0.0.1:56314 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 multi-occurrence shape (fingerprint
        // 782d6308…): same d467c210… gru-controller-1 leaf and gru control issuer as
        // c2bf6b539a62…, with a denser cid recycle (29240 → 58 → 35 → 65 → 67 → 42 → 73 at
        // 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:48:40Z / 18:49:40Z / 18:50:40Z,
        // dual reconnect at 18:48:40Z). The long-running gru-controller-1 process (not the
        // operator-read probe) presents this leaf; bare RestartAsync of NATS while the
        // controller PEM stays expired re-emits every reconnect. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control
        // NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:40.091718 [ERR] 127.0.0.1:49778 - cid:29240 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:40.559716 [ERR] 127.0.0.1:60278 - cid:58 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:40.071156 [ERR] 127.0.0.1:36482 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:40.329006 [ERR] 127.0.0.1:41108 - cid:65 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:40.407154 [ERR] 127.0.0.1:41158 - cid:67 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:40.356169 [ERR] 127.0.0.1:45270 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:40.268871 [ERR] 127.0.0.1:50988 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 two-occurrence post-recycle shape
        // (fingerprint 003657d51ecd…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308…, observed twice after control-NATS recycle
        // (cid 28 → 60 at 18:45:43Z on 127.0.0.1:49796 and 18:46:43Z on 127.0.0.1:60312,
        // NotAfter still 18:45:24Z). This is the sparse post-bare-restart reconnect twin of
        // the denser 782d6308… storm: the long-running gru-controller-1 process re-presents
        // the expired control leaf against a freshly recycled control NATS listener while
        // health probes still present only operator-read. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:43.820561 [ERR] 127.0.0.1:49796 - cid:28 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:43.968468 [ERR] 127.0.0.1:60312 - cid:60 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:43Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 four-occurrence post-recycle shape
        // (fingerprint b9dc4dd1a8ef…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd…, observed four times after
        // control-NATS recycle (cid 29 → 61 → 68 → 45 at 18:45:45Z on 127.0.0.1:56146,
        // 18:46:45Z on 127.0.0.1:57182, 18:48:45Z on 127.0.0.1:55606, and 18:49:45Z on
        // 127.0.0.1:45982, NotAfter still 18:45:24Z). This is the denser four-occurrence
        // post-bare-restart reconnect twin of the sparse 003657d51ecd… pair and the denser
        // 782d6308… storm: the long-running gru-controller-1 process re-presents the expired
        // control leaf against a freshly recycled control NATS listener while health probes
        // still present only operator-read. Recovery must match every occurrence and force
        // remint from invalid control-plane client leaves (including controllers) on the NATS
        // resource for every cell — bare RestartAsync of control NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:45.934665 [ERR] 127.0.0.1:56146 - cid:29 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:45.643628 [ERR] 127.0.0.1:57182 - cid:61 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:45.341187 [ERR] 127.0.0.1:55606 - cid:68 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:45.380336 [ERR] 127.0.0.1:45982 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:45Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 six-occurrence post-recycle shape
        // (fingerprint 7b6a047263d8…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef…, observed six
        // times after control-NATS recycle (cid 30 → 32 → 64 → 71 → 47 → 48 at 18:45:50Z on
        // 127.0.0.1:56154 / 127.0.0.1:56178 dual, 18:46:50Z on 127.0.0.1:57224, 18:48:50Z on
        // 127.0.0.1:55652, and 18:49:50Z on 127.0.0.1:46006 / 127.0.0.1:46018 dual, NotAfter
        // still 18:45:24Z). This is the denser six-occurrence post-bare-restart reconnect twin
        // of the four-occurrence b9dc4dd1a8ef… storm and the sparse 003657d51ecd… pair: the
        // long-running gru-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:50.007272 [ERR] 127.0.0.1:56154 - cid:30 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:50.105789 [ERR] 127.0.0.1:56178 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:50.678251 [ERR] 127.0.0.1:57224 - cid:64 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:50.439729 [ERR] 127.0.0.1:55652 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:50.276994 [ERR] 127.0.0.1:46006 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:50.487734 [ERR] 127.0.0.1:46018 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 five-occurrence post-recycle shape
        // (fingerprint 87f7f1566c88…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8…,
        // observed five times after control-NATS recycle (cid 33 → 67 → 65 → 74 → 49 at
        // 18:45:55Z on 127.0.0.1:54390, 18:46:55Z on 127.0.0.1:57284 / 127.0.0.1:57238 dual,
        // 18:48:55Z on 127.0.0.1:46006, and 18:49:55Z on 127.0.0.1:35748, NotAfter still
        // 18:45:24Z). This is a five-occurrence post-bare-restart reconnect twin of the six-
        // occurrence 7b6a047263d8… storm and the four-occurrence b9dc4dd1a8ef… storm: the
        // long-running gru-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:55.111043 [ERR] 127.0.0.1:54390 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:55.785095 [ERR] 127.0.0.1:57284 - cid:67 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:55.788706 [ERR] 127.0.0.1:57238 - cid:65 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:55.528481 [ERR] 127.0.0.1:46006 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:55.511943 [ERR] 127.0.0.1:35748 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:55Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 three-occurrence post-recycle shape
        // (fingerprint a9bf884a363b…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88…, observed three times after control-NATS recycle (cid 35 → 50 → 81 at
        // 18:45:56Z on 127.0.0.1:54434, 18:49:56Z on 127.0.0.1:35776, and 18:50:56Z on
        // 127.0.0.1:34540, NotAfter still 18:45:24Z). This is a three-occurrence post-bare-
        // restart reconnect twin of the five-occurrence 87f7f1566c88… storm and the six-
        // occurrence 7b6a047263d8… storm: the long-running gru-controller-1 process re-presents
        // the expired control leaf against a freshly recycled control NATS listener while
        // probes still present only operator-read. Recovery must match every occurrence and
        // force remint from invalid control-plane client leaves (including controllers) on the
        // NATS resource for every cell — bare RestartAsync of control NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:56.051898 [ERR] 127.0.0.1:54434 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:56.231902 [ERR] 127.0.0.1:35776 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:56.112227 [ERR] 127.0.0.1:34540 - cid:81 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 four-occurrence post-recycle shape
        // (fingerprint 25b92b919c66…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b…, observed four times after control-NATS recycle
        // (cid 36 → 68 → 77 → 52 at 18:46:00Z on 127.0.0.1:54442, 18:47:00Z on
        // 127.0.0.1:57286, 18:49:00Z on 127.0.0.1:46044, and 18:50:00Z on 127.0.0.1:35784,
        // NotAfter still 18:45:24Z). This is a four-occurrence post-bare-restart reconnect twin
        // of the three-occurrence a9bf884a363b… storm and the five-occurrence 87f7f1566c88…
        // storm: the long-running gru-controller-1 process re-presents the expired control leaf
        // against a freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:00.140931 [ERR] 127.0.0.1:54442 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:00.846457 [ERR] 127.0.0.1:57286 - cid:68 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:00.620845 [ERR] 127.0.0.1:46044 - cid:77 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:00.541979 [ERR] 127.0.0.1:35784 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:00Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 two-occurrence post-recycle shape
        // (fingerprint 34c89dedb769…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66…, observed twice after control-NATS
        // recycle (cid 38 → 70 at 18:46:01Z on 127.0.0.1:54492 and 18:47:01Z on
        // 127.0.0.1:57318, NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the four-occurrence 25b92b919c66… storm (cid 36 → 68 at
        // the adjacent :00 steps on 54442/57286) and the gru peer of sfo 3db5efff618c… (dual
        // cid 36+38 → 69 at the same wall-clock :01 steps): the long-running gru-controller-1
        // process re-presents the expired control leaf against a freshly recycled control NATS
        // listener while probes still present only operator-read. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control NATS
        // alone reloads the same expired PEM and re-emits the server-side handshake error on
        // the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:01.969487 [ERR] 127.0.0.1:54492 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:01.734794 [ERR] 127.0.0.1:57318 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 four-occurrence post-recycle shape
        // (fingerprint 024cbd22bdf4…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769…, observed four times
        // after control-NATS recycle (cid 39 → 71 → 80 → 55 at 18:46:05Z on 127.0.0.1:48986,
        // 18:47:05Z on 127.0.0.1:42886, 18:49:05Z on 127.0.0.1:51702, and 18:50:05Z on
        // 127.0.0.1:35504, NotAfter still 18:45:24Z). This is a four-occurrence post-bare-
        // restart reconnect twin of the two-occurrence 34c89dedb769… storm (cid 38 → 70 at
        // the adjacent :01 steps on 54492/57318) and the four-occurrence 25b92b919c66… storm
        // (cid 36 → 68 → 77 → 52 at the :00 steps on 54442/57286/46044/35784): the long-
        // running gru-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only operator-
        // read. Recovery must match every occurrence and force remint from invalid control-
        // plane client leaves (including controllers) on the NATS resource for every cell —
        // bare RestartAsync of control NATS alone reloads the same expired PEM and re-emits
        // the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:05.188513 [ERR] 127.0.0.1:48986 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:05.861881 [ERR] 127.0.0.1:42886 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:05.683069 [ERR] 127.0.0.1:51702 - cid:80 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:05.634665 [ERR] 127.0.0.1:35504 - cid:55 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:05Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 two-occurrence post-recycle shape
        // (fingerprint e7ad7a71e395…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4…,
        // observed twice after control-NATS recycle (cid 41 → 73 at 18:46:07Z on
        // 127.0.0.1:49008 and 18:47:07Z on 127.0.0.1:42932, NotAfter still 18:45:24Z). This is
        // a two-occurrence post-bare-restart reconnect twin of the four-occurrence
        // 024cbd22bdf4… storm (cid 39 → 71 → 80 → 55 at the adjacent :05 steps on
        // 48986/42886/51702/35504) and the gru peer of operator-read 5c56829c01e4… (cid 40 →
        // 72 at the same wall-clock :07 steps on 48998/42902), sfo 58dda0785551…, fra
        // d26af782af24…, fra-controller 88eec19ebb94…, sfo-platform ef71b6e32493…, and
        // gru-platform 0401b56675fd…: the long-running gru-controller-1 process re-presents
        // the expired control leaf against a freshly recycled control NATS listener while
        // probes still present only operator-read. Recovery must match every occurrence and
        // force remint from invalid control-plane client leaves (including controllers) on the
        // NATS resource for every cell — bare RestartAsync of control NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:07.925035 [ERR] 127.0.0.1:49008 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:07.646298 [ERR] 127.0.0.1:42932 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 seven-occurrence post-recycle shape
        // (fingerprint 96fe8dda09bb…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
        // e7ad7a71e395…, observed seven times after control-NATS recycle (cid 42 → 74 → 50 →
        // 51 → 81 → 83 → 58 at 18:46:10Z on 127.0.0.1:49018, 18:47:10Z on 127.0.0.1:42948,
        // 18:48:10Z on 127.0.0.1:40182 / 127.0.0.1:40194 dual, 18:49:10Z on 127.0.0.1:51716 /
        // 127.0.0.1:51744 dual, and 18:50:10Z on 127.0.0.1:35554, NotAfter still 18:45:24Z).
        // This is a denser seven-occurrence post-bare-restart reconnect twin of the two-
        // occurrence e7ad7a71e395… pair (cid 41 → 73 three seconds earlier on 49008/42932) and
        // the four-occurrence 024cbd22bdf4… storm (cid 39 → 71 → 80 → 55 at the adjacent :05
        // steps on 48986/42886/51702/35504): the long-running gru-controller-1 process
        // re-presents the expired control leaf against a freshly recycled control NATS
        // listener while probes still present only operator-read. Recovery must match every
        // occurrence and force remint from invalid control-plane client leaves (including
        // controllers) on the NATS resource for every cell — bare RestartAsync of control
        // NATS alone reloads the same expired PEM and re-emits the server-side handshake
        // error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:10.239965 [ERR] 127.0.0.1:49018 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:10.886788 [ERR] 127.0.0.1:42948 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:10.025295 [ERR] 127.0.0.1:40182 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:10.064940 [ERR] 127.0.0.1:40194 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:10.767788 [ERR] 127.0.0.1:51716 - cid:81 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:10.770138 [ERR] 127.0.0.1:51744 - cid:83 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:10.670529 [ERR] 127.0.0.1:35554 - cid:58 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:10Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 three-occurrence post-recycle shape
        // (fingerprint d2538c612184…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
        // e7ad7a71e395… / 96fe8dda09bb…, observed three times after control-NATS recycle
        // (cid 44 → 76 → 28 at 18:46:13Z on 127.0.0.1:49052, 18:47:13Z on 127.0.0.1:42988, and
        // 18:49:13Z on 127.0.0.1:51756, NotAfter still 18:45:24Z). This is a three-seconds-
        // later sparse post-bare-restart reconnect twin of the denser seven-occurrence
        // 96fe8dda09bb… storm (cid 42 → 74 → 50 → 51 → 81 → 83 → 58 three seconds earlier on
        // adjacent ports 49018 → 49052 / 42948 → 42988 / 51716 → 51756), the control-plane peer
        // of fra-controller 7063631384a4… (cid 44 → 74 → 76 → 83 at the same wall-clock :13
        // steps), and the product-plane peer of gru-platform 88ff8c404d3b… (cid 51 → 90 at the
        // same :13 steps): the long-running gru-controller-1 process re-presents the expired
        // control leaf against a freshly recycled control NATS listener while probes still
        // present only operator-read. Recovery must match every occurrence and force remint
        // from invalid control-plane client leaves (including controllers) on the NATS resource
        // for every cell — bare RestartAsync of control NATS alone reloads the same expired
        // PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:13.979383 [ERR] 127.0.0.1:49052 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:13.815867 [ERR] 127.0.0.1:42988 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:13.872891 [ERR] 127.0.0.1:51756 - cid:28 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=gru-controller-1 seven-occurrence post-recycle shape
        // (fingerprint d00ef05a1026…): same d467c210… gru-controller-1 leaf and gru control
        // issuer as c2bf6b539a62… / 782d6308… / 003657d51ecd… / b9dc4dd1a8ef… / 7b6a047263d8… /
        // 87f7f1566c88… / a9bf884a363b… / 25b92b919c66… / 34c89dedb769… / 024cbd22bdf4… /
        // e7ad7a71e395… / 96fe8dda09bb… / d2538c612184…, observed seven times after
        // control-NATS recycle (cid 45 → 77 → 52 → 54 → 29 → 60 → 61 at 18:46:15Z on
        // 127.0.0.1:37246, 18:47:15Z on 127.0.0.1:34118, 18:48:15Z on 127.0.0.1:52154 /
        // 127.0.0.1:52194 dual, 18:49:15Z on 127.0.0.1:45258, and 18:50:15Z on
        // 127.0.0.1:57522 / 127.0.0.1:57524 dual, NotAfter still 18:45:24Z). This is a
        // two-seconds-later denser post-bare-restart reconnect twin of the three-occurrence
        // d2538c612184… storm (cid 44 → 76 → 28 two seconds earlier on 49052/42988/51756) and
        // a denser seven-occurrence peer of 96fe8dda09bb… (cid 42 → 74 → 50 → 51 → 81 → 83 →
        // 58 at the adjacent wall-clock :10 steps on 49018/42948/40182/40194/51716/51744/
        // 35554): the long-running gru-controller-1 process re-presents the expired control
        // leaf against a freshly recycled control NATS listener while probes still present
        // only operator-read. Recovery must match every occurrence and force remint from
        // invalid control-plane client leaves (including controllers) on the NATS resource
        // for every cell — bare RestartAsync of control NATS alone reloads the same expired
        // PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:15.300030 [ERR] 127.0.0.1:37246 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:15.964565 [ERR] 127.0.0.1:34118 - cid:77 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:15.131521 [ERR] 127.0.0.1:52154 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:15.978408 [ERR] 127.0.0.1:52194 - cid:54 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:15.941940 [ERR] 127.0.0.1:45258 - cid:29 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:15.302991 [ERR] 127.0.0.1:57522 - cid:60 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:15.684462 [ERR] 127.0.0.1:57524 - cid:61 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:15Z is after 2026-07-21T18:45:24Z " +
                "(CN=gru-controller-1 SHA-256: d467c210a9b55640d2132d9a7a80c1758af1faebf0971568defc06d3f1df1361; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 multi-occurrence shape (fingerprint
        // 91b5b852…): same NotAfter (18:45:24Z) and bare control-NATS recycle pattern as the
        // sfo/gru controller twins (cid 29238 → 62 → 69 → 70 at 18:45:34Z / 18:48:34Z /
        // 18:50:34Z). The long-running fra-controller-1 process (not the operator-read probe)
        // presents this leaf; bare RestartAsync of NATS while the controller PEM stays expired
        // re-emits every reconnect. Recovery must match every occurrence and force remint from
        // invalid control-plane client leaves (including controllers) on the NATS resource for
        // every cell — bare RestartAsync of control NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:34.134988 [ERR] 127.0.0.1:55318 - cid:29238 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:34.476639 [ERR] 127.0.0.1:40568 - cid:62 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:34.258927 [ERR] 127.0.0.1:51928 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:34.269531 [ERR] 127.0.0.1:51934 - cid:70 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 multi-occurrence shape (fingerprint
        // ffcef075c58c…): same 8f6e801c… fra-controller-1 leaf and fra control issuer as
        // 91b5b852…, with a denser cid recycle (29240 → 34 → 66 → 73 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z). The long-running fra-controller-1 process
        // (not the operator-read probe) presents this leaf; bare RestartAsync of NATS while
        // the controller PEM stays expired re-emits every reconnect. Recovery must match
        // every occurrence and force remint from invalid control-plane client leaves
        // (including controllers) on the NATS resource for every cell — bare RestartAsync of
        // control NATS alone reloads the same expired PEM.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:40.092029 [ERR] 127.0.0.1:41324 - cid:29240 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:40.071705 [ERR] 127.0.0.1:53178 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:40.408243 [ERR] 127.0.0.1:40624 - cid:66 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:40.269036 [ERR] 127.0.0.1:59620 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 four-occurrence post-recycle shape
        // (fingerprint bca21682b315…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c…, observed four times after control-NATS recycle
        // (cid 28 → 37 → 69 → 76 at 18:45:46Z on 127.0.0.1:34624, 18:47:46Z on
        // 127.0.0.1:60304, 18:48:46Z on 127.0.0.1:50796, and 18:50:46Z on 127.0.0.1:54352,
        // NotAfter still 18:45:24Z). This is the four-occurrence post-bare-restart reconnect
        // twin of 91b5b852… / ffcef075c58c… and the fra twin of gru b9dc4dd1a8ef…: the
        // long-running fra-controller-1 process re-presents the expired control leaf against a
        // freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:46.101832 [ERR] 127.0.0.1:34624 - cid:28 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:46.039050 [ERR] 127.0.0.1:60304 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:46.384308 [ERR] 127.0.0.1:50796 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:46.280486 [ERR] 127.0.0.1:54352 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:46Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 single-occurrence post-recycle shape
        // (fingerprint 23eafce842f6…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315…, observed once after control-NATS
        // recycle (cid:29 at 18:45:48Z on 127.0.0.1:34626, NotAfter still 18:45:24Z). This is
        // the single post-bare-restart reconnect twin of the denser bca21682b315… storm (cid 28
        // on adjacent port 34624 at 18:45:46Z) and the fra twin of the leading cid 29 step of
        // gru b9dc4dd1a8ef… / sfo e8e55fe0bef9…: the long-running fra-controller-1 process
        // re-presents the expired control leaf against a freshly recycled control NATS listener
        // while probes still present only operator-read. Recovery must match this line and force
        // remint from invalid control-plane client leaves (including controllers) on the NATS
        // resource for every cell — bare RestartAsync of control NATS alone reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:48.220999 [ERR] 127.0.0.1:34626 - cid:29 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:48Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 two-occurrence post-recycle shape
        // (fingerprint 4046b92fa615…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6…, observed twice
        // after control-NATS recycle (cid 31 → 47 at 18:45:50Z on 127.0.0.1:34668 and
        // 18:49:50Z on 127.0.0.1:33784, NotAfter still 18:45:24Z). This is a sparse two-
        // occurrence post-bare-restart reconnect twin of the denser storms and the fra peer of
        // sfo 412baaa56842… cid 31/47 steps and operator-read twins f4f92376efda… /
        // 62860f83eeb6… at the same wall-clock pair: the long-running fra-controller-1 process
        // re-presents the expired control leaf against a freshly recycled control NATS listener
        // while probes still present only operator-read. Recovery must match every occurrence
        // and force remint from invalid control-plane client leaves (including controllers) on
        // the NATS resource for every cell — bare RestartAsync of control NATS alone reloads
        // the same expired PEM and re-emits the server-side handshake error on the next
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:50.106856 [ERR] 127.0.0.1:34668 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:50.279014 [ERR] 127.0.0.1:33784 - cid:47 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 seven-occurrence post-recycle shape
        // (fingerprint 87c737a0ed10…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615…,
        // observed seven times after control-NATS recycle (cid 32 → 64 → 41 → 72 → 73 → 48 →
        // 79 at 18:45:52Z on 127.0.0.1:34674, 18:46:52Z on 127.0.0.1:53654, 18:47:52Z on
        // 127.0.0.1:60380, 18:48:52Z on 127.0.0.1:50844 / 50858 dual, 18:49:52Z on
        // 127.0.0.1:33786, and 18:50:52Z on 127.0.0.1:54412, NotAfter still 18:45:24Z). This
        // is a seven-occurrence post-bare-restart reconnect twin of the denser storms and the
        // fra peer of sfo 71cf8514f4d6… cid 32/41/48 steps and gru-platform b22018f7aa7b… at
        // adjacent wall-clock :52 steps: the long-running fra-controller-1 process re-presents
        // the expired control leaf against a freshly recycled control NATS listener while
        // probes still present only operator-read. Recovery must match every occurrence and
        // force remint from invalid control-plane client leaves (including controllers) on the
        // NATS resource for every cell — bare RestartAsync of control NATS alone reloads the
        // same expired PEM and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:52.278615 [ERR] 127.0.0.1:34674 - cid:32 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:52.998037 [ERR] 127.0.0.1:53654 - cid:64 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:52.229632 [ERR] 127.0.0.1:60380 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:52.389926 [ERR] 127.0.0.1:50844 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:52.993636 [ERR] 127.0.0.1:50858 - cid:73 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:52.653949 [ERR] 127.0.0.1:33786 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:52.355180 [ERR] 127.0.0.1:54412 - cid:79 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:52Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 two-occurrence post-recycle shape
        // (fingerprint 5e5b835252fe…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10…, observed twice after control-NATS recycle (cid 34 → 50 at 18:45:56Z
        // on 127.0.0.1:43900 and 18:49:56Z on 127.0.0.1:37150, NotAfter still 18:45:24Z). This
        // is a sparse two-occurrence post-bare-restart reconnect twin of the denser storms and
        // the fra peer of gru a9bf884a363b… cid 35/50 steps at the same wall-clock :56 pair:
        // the long-running fra-controller-1 process re-presents the expired control leaf against
        // a freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:56.053060 [ERR] 127.0.0.1:43900 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:56.244898 [ERR] 127.0.0.1:37150 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 four-occurrence post-recycle shape
        // (fingerprint 6e08a77cd4b6…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe…, observed four times after control-NATS recycle (cid
        // 35 → 42 → 44 → 51 at 18:45:57Z on 127.0.0.1:43906, 18:47:57Z on 127.0.0.1:44698 /
        // 127.0.0.1:44730 dual cid 42+44, and 18:49:57Z on 127.0.0.1:37152, NotAfter still
        // 18:45:24Z). This is a four-occurrence post-bare-restart reconnect twin of the denser
        // storms and the adjacent :57 peer of 5e5b835252fe… (cid 34 → 50 at :56 on nearby
        // 43900/37150) / gru a9bf884a363b… / sfo-platform 9b960cc93f83… at adjacent wall-clock
        // :56/:57 steps: the long-running fra-controller-1 process re-presents the expired
        // control leaf against a freshly recycled control NATS listener while probes still
        // present only operator-read. Recovery must match every occurrence and force remint
        // from invalid control-plane client leaves (including controllers) on the NATS resource
        // for every cell — bare RestartAsync of control NATS alone reloads the same expired PEM
        // and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:57.306940 [ERR] 127.0.0.1:43906 - cid:35 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:57.327289 [ERR] 127.0.0.1:44698 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:57.983436 [ERR] 127.0.0.1:44730 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:57.705522 [ERR] 127.0.0.1:37152 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:57Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 two-occurrence post-recycle shape
        // (fingerprint 876de6711801…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6…, observed twice after control-NATS
        // recycle (cid 37 → 69 at 18:46:01Z on 127.0.0.1:43944 and 18:47:01Z on
        // 127.0.0.1:42784, NotAfter still 18:45:24Z). This is a two-occurrence post-bare-
        // restart reconnect twin of the denser storms and the fra peer of gru 34c89dedb769…
        // (cid 38 → 70 at the same wall-clock :01 steps) / sfo 3db5efff618c… (dual cid 36+38 →
        // 69 at the same wall-clock :01 steps): the long-running fra-controller-1 process
        // re-presents the expired control leaf against a freshly recycled control NATS listener
        // while probes still present only operator-read. Recovery must match every occurrence
        // and force remint from invalid control-plane client leaves (including controllers) on
        // the NATS resource for every cell — bare RestartAsync of control NATS alone reloads
        // the same expired PEM and re-emits the server-side handshake error on the next
        // reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:01.971355 [ERR] 127.0.0.1:43944 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:01.736261 [ERR] 127.0.0.1:42784 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 three-occurrence post-recycle shape
        // (fingerprint 52a227218acf…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801…, observed three times
        // after control-NATS recycle (cid 38 → 45 → 52 at 18:46:02Z on 127.0.0.1:43948,
        // 18:48:02Z on 127.0.0.1:44744, and 18:50:02Z on 127.0.0.1:37162, NotAfter still
        // 18:45:24Z). This is a three-occurrence post-bare-restart reconnect twin of the denser
        // storms and the adjacent :02 second after 876de6711801… (cid 37 at 18:46:01Z on nearby
        // 43944), with ~2 min reconnect gaps matching the denser 91b5b852… / ffcef075c58c…
        // wall-clock cadence: the long-running fra-controller-1 process re-presents the expired
        // control leaf against a freshly recycled control NATS listener while probes still
        // present only operator-read. Recovery must match every occurrence and force remint
        // from invalid control-plane client leaves (including controllers) on the NATS resource
        // for every cell — bare RestartAsync of control NATS alone reloads the same expired PEM
        // and re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:02.387573 [ERR] 127.0.0.1:43948 - cid:38 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:02Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:02.349541 [ERR] 127.0.0.1:44744 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:02Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:02.723007 [ERR] 127.0.0.1:37162 - cid:52 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:02Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 five-occurrence post-recycle shape
        // (fingerprint 88eec19ebb94…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf…,
        // observed five times after control-NATS recycle (cid 39 → 41 → 72 → 48 → 55 at
        // 18:46:07Z on 127.0.0.1:48674 / 127.0.0.1:48694 dual cid 39+41, 18:47:07Z on
        // 127.0.0.1:46502, 18:48:07Z on 127.0.0.1:55402, and 18:50:07Z on 127.0.0.1:60620,
        // NotAfter still 18:45:24Z). This is a five-occurrence post-bare-restart reconnect
        // twin of the denser storms and the fra peer of gru 024cbd22bdf4… (cid 39 → 71 →
        // 80 → 55 at adjacent wall-clock :05 steps) at the :07 second: the long-running
        // fra-controller-1 process re-presents the expired control leaf against a freshly
        // recycled control NATS listener while probes still present only operator-read.
        // Recovery must match every occurrence and force remint from invalid control-plane
        // client leaves (including controllers) on the NATS resource for every cell — bare
        // RestartAsync of control NATS alone reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:07.479782 [ERR] 127.0.0.1:48674 - cid:39 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:07.925807 [ERR] 127.0.0.1:48694 - cid:41 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:07.647639 [ERR] 127.0.0.1:46502 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:07.423219 [ERR] 127.0.0.1:55402 - cid:48 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:07.801959 [ERR] 127.0.0.1:60620 - cid:55 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 three-occurrence post-recycle shape
        // (fingerprint 49ec50da2e2a…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf… /
        // 88eec19ebb94…, observed three times after control-NATS recycle (cid 42 → 51 → 58 at
        // 18:46:12Z on 127.0.0.1:48696, 18:48:12Z on 127.0.0.1:55440, and 18:50:12Z on
        // 127.0.0.1:60662, NotAfter still 18:45:24Z). This is a three-occurrence post-bare-
        // restart reconnect twin of the already-locked five-occurrence 88eec19ebb94… storm
        // (cid 39 → 41 → 72 → 48 → 55 five seconds earlier on adjacent ports 48674/48694 /
        // 55402 / 60620) and the fra peer of sfo 914b99d5fbc6… (cid 42 → 83 → 58 at the
        // adjacent :11 steps) / gru 96fe8dda09bb… (cid 42 → 74 → 50 → 51 → 81 → 83 → 58 at
        // the adjacent :10/:11 steps, sparse without the mid-window dual-cid reconnects):
        // the long-running fra-controller-1 process re-presents the expired control leaf
        // against a freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:12.519870 [ERR] 127.0.0.1:48696 - cid:42 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:12Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:12.435863 [ERR] 127.0.0.1:55440 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:12Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:12.912224 [ERR] 127.0.0.1:60662 - cid:58 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:12Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 four-occurrence post-recycle shape
        // (fingerprint 7063631384a4…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf… /
        // 88eec19ebb94… / 49ec50da2e2a…, observed four times after control-NATS recycle
        // (cid 44 → 74 → 76 → 83 at 18:46:13Z on 127.0.0.1:48726, 18:47:13Z on
        // 127.0.0.1:46524 / 127.0.0.1:46564 dual cid 74+76, and 18:49:13Z on 127.0.0.1:52176,
        // NotAfter still 18:45:24Z). This is a four-occurrence post-bare-restart reconnect
        // twin of the already-locked three-occurrence 49ec50da2e2a… storm (cid 42 → 51 → 58
        // one second earlier on adjacent port 48696 → 48726) and five-occurrence
        // 88eec19ebb94… storm (cid 39 → 41 → 72 → 48 → 55 six seconds earlier on
        // 48674/48694 / 46502 / 55402 / 60620), denser mid-window dual reconnect than the
        // sparse :12 triple, and the control-plane peer of gru-platform 88ff8c404d3b…
        // (cid 51 → 90 at the same wall-clock :13 steps): the long-running fra-controller-1
        // process re-presents the expired control leaf against a freshly recycled control
        // NATS listener while probes still present only operator-read. Recovery must match
        // every occurrence and force remint from invalid control-plane client leaves
        // (including controllers) on the NATS resource for every cell — bare RestartAsync of
        // control NATS alone reloads the same expired PEM and re-emits the server-side
        // handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:13.978965 [ERR] 127.0.0.1:48726 - cid:44 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:13.210104 [ERR] 127.0.0.1:46524 - cid:74 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:13.816716 [ERR] 127.0.0.1:46564 - cid:76 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:13.151440 [ERR] 127.0.0.1:52176 - cid:83 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=fra-controller-1 three-occurrence post-recycle shape
        // (fingerprint d7de94966c92…): same 8f6e801c… fra-controller-1 leaf and fra control
        // issuer as 91b5b852… / ffcef075c58c… / bca21682b315… / 23eafce842f6… / 4046b92fa615… /
        // 87c737a0ed10… / 5e5b835252fe… / 6e08a77cd4b6… / 876de6711801… / 52a227218acf… /
        // 88eec19ebb94… / 49ec50da2e2a… / 7063631384a4…, observed three times after
        // control-NATS recycle (cid 45 → 54 → 61 at 18:46:17Z on 127.0.0.1:45396,
        // 18:48:17Z on 127.0.0.1:33434, and 18:50:17Z on 127.0.0.1:58410, NotAfter still
        // 18:45:24Z). This is a four-seconds-later three-occurrence post-bare-restart
        // reconnect twin of the already-locked 7063631384a4… storm (cid 44 → 74 → 76 → 83
        // on 48726/46524/46564/52176 at :13), the fra peer of sfo bbdb6e0d6006… (cid 45 →
        // 29 → 61 at the adjacent wall-clock :16 steps) and gru d00ef05a1026… (cid 45 → 77 →
        // 52 → 54 → 29 → 60 → 61 at the adjacent wall-clock :15 steps), and the product-plane
        // peer of fra-platform ec156a1db321… (cid 52 → 91 at the same wall-clock :17 steps):
        // the long-running fra-controller-1 process re-presents the expired control leaf
        // against a freshly recycled control NATS listener while probes still present only
        // operator-read. Recovery must match every occurrence and force remint from invalid
        // control-plane client leaves (including controllers) on the NATS resource for every
        // cell — bare RestartAsync of control NATS alone reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:17.567269 [ERR] 127.0.0.1:45396 - cid:45 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:17.497453 [ERR] 127.0.0.1:33434 - cid:54 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:17.944081 [ERR] 127.0.0.1:58410 - cid:61 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:17Z is after 2026-07-21T18:45:24Z " +
                "(CN=fra-controller-1 SHA-256: 8f6e801cbe068b0be8e9ee937fe5b8b61734098484a76d87ff2210493ef38566; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // operator-read health probes also present leaves; once expired they appear on
        // the same NATS server log stream and must match force-remint detection.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] TLS handshake error: tls: failed to verify certificate: " +
                "x509: certificate has expired or is not yet valid (CN=operator-read)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read incident shape (fingerprint
        // ffc463abefcb…): control-plane health probes present operator-read every
        // cycle; when NotAfter elapses NATS logs this server-side line. Recovery must
        // match it, and probes must refuse the leaf before ConnectAsync so this line
        // is not re-emitted while remint restarts TLS consumers.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:28.171942 [ERR] 127.0.0.1:45714 - cid:29235 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:28Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read incident shape (fingerprint
        // c6627a56bf45…): same NotAfter window as the sfo twin, but health-driven
        // RestartAsync recycled NATS without reminting PEMs so the expired leaf kept
        // being presented after each recycle (cid 29237 → 62 → 69 at ~2–3 min gaps).
        // Recovery must match every occurrence, skip startup grace for cert failures,
        // and force remint instead of bare restart so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:34.131618 [ERR] 127.0.0.1:49494 - cid:29237 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:34.476021 [ERR] 127.0.0.1:41086 - cid:62 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:34.254117 [ERR] 127.0.0.1:56294 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read multi-occurrence shape (fingerprint
        // c48cbf142a9a…): same 4e40db2b… operator-read leaf and gru control issuer as
        // c6627a56bf45…, with a denser cid recycle (29239 → 34 → 66 → 72 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z). Health probes present operator-read every
        // cycle; bare RestartAsync of NATS while that PEM stays expired re-emits every
        // reconnect. Recovery must match every occurrence, skip startup grace for cert
        // failures, and force remint from invalid on-disk probe leaves so the recycle
        // loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:40.091148 [ERR] 127.0.0.1:49762 - cid:29239 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:40.072373 [ERR] 127.0.0.1:36462 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:48:40.406064 [ERR] 127.0.0.1:41136 - cid:66 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:50:40.269492 [ERR] 127.0.0.1:50968 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint f4f92376efda…): same 4e40db2b… operator-read leaf and gru control
        // issuer as c6627a56bf45… / c48cbf142a9a…, observed twice after control-NATS recycle
        // (cid 31 → 46 at 18:45:50Z on 127.0.0.1:56170 and 18:49:50Z on 127.0.0.1:45996,
        // NotAfter still 18:45:24Z). This is the sparse two-occurrence post-bare-restart
        // reconnect twin of the denser c6627a56… / c48cbf142a9a… storms and the gru twin of
        // sfo 62860f83eeb6…: health probes present operator-read every cycle while bare
        // RestartAsync of NATS reloads the same expired PEM and re-emits the server-side
        // handshake error on the next reconnect. Recovery must match every occurrence, skip
        // startup grace for cert failures, and force remint from invalid on-disk probe
        // leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:50.106158 [ERR] 127.0.0.1:56170 - cid:31 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:50.277494 [ERR] 127.0.0.1:45996 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint b252d8996050…): same 4e40db2b… operator-read leaf and gru control
        // issuer as c6627a56bf45… / c48cbf142a9a… / f4f92376efda…, observed twice after
        // control-NATS recycle (cid 34 → 51 at 18:45:56Z on 127.0.0.1:54410 and 18:49:56Z
        // on 127.0.0.1:35762, NotAfter still 18:45:24Z). This is a second sparse two-
        // occurrence post-bare-restart reconnect twin of the denser c6627a56… /
        // c48cbf142a9a… storms and of the earlier f4f92376efda… pair (cid 31 → 46 at
        // 18:45:50Z / 18:49:50Z), and the gru twin of sfo 97d33257778a… at the same
        // wall-clock :56 steps: health probes present operator-read every cycle while
        // bare RestartAsync of NATS reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:45:56.051908 [ERR] 127.0.0.1:54410 - cid:34 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:49:56.236172 [ERR] 127.0.0.1:35762 - cid:51 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 6a650c470be6…): same 4e40db2b… operator-read leaf and gru control
        // issuer as c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050…, observed
        // twice after control-NATS recycle (cid 37 → 69 at 18:46:01Z on 127.0.0.1:54470 and
        // 18:47:01Z on 127.0.0.1:57302, NotAfter still 18:45:24Z). This is a third sparse
        // two-occurrence post-bare-restart reconnect twin of the denser c6627a56… /
        // c48cbf142a9a… storms and of the earlier f4f92376efda… (cid 31 → 46 at 18:45:50Z /
        // 18:49:50Z) and b252d8996050… (cid 34 → 51 at 18:45:56Z / 18:49:56Z) pairs, and the
        // gru peer of sfo d80a6067f126… (cid 37 → 68) at the same wall-clock :01 steps:
        // health probes present operator-read every cycle while bare RestartAsync of NATS
        // reloads the same expired PEM and re-emits the server-side handshake error on the
        // next reconnect. Recovery must match every occurrence, skip startup grace for cert
        // failures, and force remint from invalid on-disk probe leaves so the recycle loop
        // cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:01.970227 [ERR] 127.0.0.1:54470 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:01.734321 [ERR] 127.0.0.1:57302 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 5c56829c01e4…): same 4e40db2b… operator-read leaf and gru control
        // issuer as c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… /
        // 6a650c470be6…, observed twice after control-NATS recycle (cid 40 → 72 at
        // 18:46:07Z on 127.0.0.1:48998 and 18:47:07Z on 127.0.0.1:42902, NotAfter still
        // 18:45:24Z). This is a fourth sparse two-occurrence post-bare-restart reconnect
        // twin of the denser c6627a56… / c48cbf142a9a… storms and of the earlier
        // f4f92376efda… (cid 31 → 46 at 18:45:50Z / 18:49:50Z), b252d8996050… (cid 34 → 51
        // at 18:45:56Z / 18:49:56Z), and 6a650c470be6… (cid 37 → 69 at 18:46:01Z /
        // 18:47:01Z) pairs, and the gru peer of sfo 58dda0785551… (cid 40 → 72) at the same
        // wall-clock :07 steps as fra-controller 88eec19ebb94… and sfo-platform
        // ef71b6e32493…: health probes present operator-read every cycle while bare
        // RestartAsync of NATS reloads the same expired PEM and re-emits the server-side
        // handshake error on the next reconnect. Recovery must match every occurrence, skip
        // startup grace for cert failures, and force remint from invalid on-disk probe
        // leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:07.924484 [ERR] 127.0.0.1:48998 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:07.647308 [ERR] 127.0.0.1:42902 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact gru-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 9dd8feb97fa2…): same 4e40db2b… operator-read leaf and gru control
        // issuer as c6627a56bf45… / c48cbf142a9a… / f4f92376efda… / b252d8996050… /
        // 6a650c470be6… / 5c56829c01e4…, observed twice after control-NATS recycle
        // (cid 43 → 75 at 18:46:13Z on 127.0.0.1:49032 and 18:47:13Z on 127.0.0.1:42960,
        // NotAfter still 18:45:24Z). This is a fifth sparse two-occurrence post-bare-
        // restart reconnect twin of the denser c6627a56… / c48cbf142a9a… storms and of the
        // earlier f4f92376efda… (cid 31 → 46 at 18:45:50Z / 18:49:50Z), b252d8996050…
        // (cid 34 → 51 at 18:45:56Z / 18:49:56Z), 6a650c470be6… (cid 37 → 69 at 18:46:01Z /
        // 18:47:01Z), and 5c56829c01e4… (cid 40 → 72 at 18:46:07Z / 18:47:07Z) pairs, and
        // the gru operator-read peer of sfo-platform e583d837318a… and fra-platform
        // d86f81358e32… at the same wall-clock :13 steps: health probes present
        // operator-read every cycle while bare RestartAsync of NATS reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        // Recovery must match every occurrence, skip startup grace for cert failures, and
        // force remint from invalid on-disk probe leaves so the recycle loop cannot
        // continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:46:13.978351 [ERR] 127.0.0.1:49032 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[gru-control-nats-1] [1] 2026/07/21 18:47:13.815465 [ERR] 127.0.0.1:42960 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 4e40db2bc8dcc6bcc5e19bc59b25e86ef0b630d4480fbe1a107ba79eb8ad3bf0; " +
                "CN=TerraScale gru control issuer SHA-256: da96b024f2849ad2ba051fa8cd80c26867c9d14cdd548e403cacb771b8d52a84)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read multi-occurrence shape (fingerprint
        // e517701a2468…): same NotAfter (18:45:24Z) and cid recycle pattern as the gru
        // twin (29237 → 62 → 69 at 18:45:34Z / 18:48:34Z / 18:50:34Z), but against the
        // sfo control issuer and the aa00c1c3… operator-read leaf. Recovery must match
        // every occurrence and force remint from invalid on-disk probe leaves so bare
        // RestartAsync cannot keep re-presenting operator-read after each NATS recycle.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:34.132987 [ERR] 127.0.0.1:45742 - cid:29237 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:34.475856 [ERR] 127.0.0.1:51918 - cid:62 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:34.257477 [ERR] 127.0.0.1:55498 - cid:69 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read multi-occurrence shape (fingerprint
        // f08d1c577176…): same aa00c1c3… operator-read leaf and sfo control issuer as
        // e517701a2468…, with a denser cid recycle (29239 → 33 → 65 → 72 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z). This is the sfo twin of gru c48cbf142a9a…:
        // health probes present operator-read every cycle; bare RestartAsync of NATS while
        // that PEM stays expired re-emits every reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:40.091257 [ERR] 127.0.0.1:55352 - cid:29239 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:40.071359 [ERR] 127.0.0.1:34600 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:48:40.409379 [ERR] 127.0.0.1:51940 - cid:65 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:50:40.268987 [ERR] 127.0.0.1:41716 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 62860f83eeb6…): same aa00c1c3… operator-read leaf and sfo control
        // issuer as e517701a2468… / f08d1c577176…, observed twice after control-NATS recycle
        // (cid 30 → 46 at 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070,
        // NotAfter still 18:45:24Z). This is the sparse two-occurrence post-bare-restart
        // reconnect twin of the denser e517701a… / f08d1c577176… storms: health probes
        // present operator-read every cycle while bare RestartAsync of NATS reloads the
        // same expired PEM and re-emits the server-side handshake error on the next
        // reconnect. Recovery must match every occurrence, skip startup grace for cert
        // failures, and force remint from invalid on-disk probe leaves so the recycle
        // loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:50.105982 [ERR] 127.0.0.1:50596 - cid:30 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:50.277370 [ERR] 127.0.0.1:34070 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 97d33257778a…): same aa00c1c3… operator-read leaf and sfo control
        // issuer as e517701a2468… / f08d1c577176… / 62860f83eeb6…, observed twice after
        // control-NATS recycle (cid 33 → 50 at 18:45:56Z on 127.0.0.1:52196 and 18:49:56Z
        // on 127.0.0.1:36654, NotAfter still 18:45:24Z). This is a second sparse two-
        // occurrence post-bare-restart reconnect twin of the denser e517701a… /
        // f08d1c577176… storms and of the earlier 62860f83eeb6… pair (cid 30 → 46 at
        // 18:45:50Z / 18:49:50Z): health probes present operator-read every cycle while
        // bare RestartAsync of NATS reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:45:56.051643 [ERR] 127.0.0.1:52196 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:49:56.236863 [ERR] 127.0.0.1:36654 - cid:50 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint d80a6067f126…): same aa00c1c3… operator-read leaf and sfo control
        // issuer as e517701a2468… / f08d1c577176… / 62860f83eeb6… / 97d33257778a…, observed
        // twice after control-NATS recycle (cid 37 → 68 at 18:46:01Z on 127.0.0.1:52246 and
        // 18:47:01Z on 127.0.0.1:34762, NotAfter still 18:45:24Z). This is a third sparse
        // two-occurrence post-bare-restart reconnect twin of the denser e517701a… /
        // f08d1c577176… storms and of the earlier 62860f83eeb6… (cid 30 → 46 at 18:45:50Z /
        // 18:49:50Z) and 97d33257778a… (cid 33 → 50 at 18:45:56Z / 18:49:56Z) pairs: health
        // probes present operator-read every cycle while bare RestartAsync of NATS reloads
        // the same expired PEM and re-emits the server-side handshake error on the next
        // reconnect. Recovery must match every occurrence, skip startup grace for cert
        // failures, and force remint from invalid on-disk probe leaves so the recycle loop
        // cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:01.969997 [ERR] 127.0.0.1:52246 - cid:37 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:01.736126 [ERR] 127.0.0.1:34762 - cid:68 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 58dda0785551…): same aa00c1c3… operator-read leaf and sfo control
        // issuer as e517701a2468… / f08d1c577176… / 62860f83eeb6… / 97d33257778a… /
        // d80a6067f126…, observed twice after control-NATS recycle (cid 40 → 72 at
        // 18:46:07Z on 127.0.0.1:49186 and 18:47:07Z on 127.0.0.1:53880, NotAfter still
        // 18:45:24Z). This is a fourth sparse two-occurrence post-bare-restart reconnect
        // twin of the denser e517701a… / f08d1c577176… storms and of the earlier
        // 62860f83eeb6… (cid 30 → 46 at 18:45:50Z / 18:49:50Z), 97d33257778a… (cid 33 → 50
        // at 18:45:56Z / 18:49:56Z), and d80a6067f126… (cid 37 → 68 at 18:46:01Z /
        // 18:47:01Z) pairs, at the same wall-clock :07 steps as fra-controller
        // 88eec19ebb94… and sfo-platform ef71b6e32493…: health probes present operator-read
        // every cycle while bare RestartAsync of NATS reloads the same expired PEM and
        // re-emits the server-side handshake error on the next reconnect. Recovery must
        // match every occurrence, skip startup grace for cert failures, and force remint
        // from invalid on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:07.924395 [ERR] 127.0.0.1:49186 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:07.647771 [ERR] 127.0.0.1:53880 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact sfo-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 69541ea34d1d…): same aa00c1c3… operator-read leaf and sfo control
        // issuer as e517701a2468… / f08d1c577176… / 62860f83eeb6… / 97d33257778a… /
        // d80a6067f126… / 58dda0785551…, observed twice after control-NATS recycle
        // (cid 43 → 75 at 18:46:13Z on 127.0.0.1:49240 and 18:47:13Z on 127.0.0.1:53920,
        // NotAfter still 18:45:24Z). This is a fifth sparse two-occurrence post-bare-
        // restart reconnect twin of the denser e517701a… / f08d1c577176… storms and of the
        // earlier 62860f83eeb6… (cid 30 → 46 at 18:45:50Z / 18:49:50Z), 97d33257778a…
        // (cid 33 → 50 at 18:45:56Z / 18:49:56Z), d80a6067f126… (cid 37 → 68 at 18:46:01Z /
        // 18:47:01Z), and 58dda0785551… (cid 40 → 72 at 18:46:07Z / 18:47:07Z) pairs, and
        // the sfo operator-read peer of gru 9dd8feb97fa2… (cid 43 → 75) / fra 424b0b6af457…
        // (cid 43 → 75) / sfo-platform e583d837318a… / fra-platform d86f81358e32… at the
        // same wall-clock :13 steps: health probes present operator-read every cycle while
        // bare RestartAsync of NATS reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:46:13.980547 [ERR] 127.0.0.1:49240 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[sfo-control-nats-1] [1] 2026/07/21 18:47:13.815724 [ERR] 127.0.0.1:53920 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: aa00c1c3fca01567ad5069d92edb201d2a0a8d1d5a51fa62d587a8df264668fc; " +
                "CN=TerraScale sfo control issuer SHA-256: 5e42a605731e1af1a8eb24192a5357ad022c1a8916d0e58950bc5568bfa90ec1)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read multi-occurrence shape (fingerprint
        // 9a811bb8b959…): same NotAfter (18:45:24Z) as the gru/sfo operator-read twins,
        // with a distinct cid recycle (29237 → 63 → 68 at 18:45:34Z / 18:48:34Z /
        // 18:50:34Z) against the fra control issuer and the 6477b788… operator-read leaf.
        // Health probes present operator-read every cycle; bare RestartAsync of NATS while
        // that PEM stays expired re-emits every reconnect. Recovery must match every
        // occurrence and force remint from invalid on-disk probe leaves for every cell,
        // not only gru/sfo.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:34.134763 [ERR] 127.0.0.1:55294 - cid:29237 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:34.475736 [ERR] 127.0.0.1:40558 - cid:63 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:34.256251 [ERR] 127.0.0.1:51904 - cid:68 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:34Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read multi-occurrence shape (fingerprint
        // f95adc65…): same 6477b788… operator-read leaf and fra control issuer as
        // 9a811bb8b959…, with a denser cid recycle (29239 → 33 → 65 → 72 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z). This is the fra twin of gru c48cbf142a9a…
        // and sfo f08d1c577176…: health probes present operator-read every cycle; bare
        // RestartAsync of NATS while that PEM stays expired re-emits every reconnect.
        // Recovery must match every occurrence, skip startup grace for cert failures,
        // and force remint from invalid on-disk probe leaves so the recycle loop cannot
        // continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:40.091588 [ERR] 127.0.0.1:41300 - cid:29239 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:40.072201 [ERR] 127.0.0.1:53168 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:48:40.410351 [ERR] 127.0.0.1:40596 - cid:65 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:48:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:50:40.269547 [ERR] 127.0.0.1:59604 - cid:72 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:50:40Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 7421834a4183…): same 6477b788… operator-read leaf and fra control
        // issuer as 9a811bb8b959… / f95adc65…, observed twice after control-NATS recycle
        // (cid 30 → 46 at 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762,
        // NotAfter still 18:45:24Z). This is the sparse two-occurrence post-bare-restart
        // reconnect twin of the denser 9a811bb8… / f95adc65… storms and the fra twin of
        // gru f4f92376efda… / sfo 62860f83eeb6…: health probes present operator-read every
        // cycle while bare RestartAsync of NATS reloads the same expired PEM and re-emits
        // the server-side handshake error on the next reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:50.107659 [ERR] 127.0.0.1:34654 - cid:30 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:50.278716 [ERR] 127.0.0.1:33762 - cid:46 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:50Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint c74671d2c0e4…): same 6477b788… operator-read leaf and fra control
        // issuer as 9a811bb8b959… / f95adc65… / 7421834a4183…, observed twice after
        // control-NATS recycle (cid 33 → 49 at 18:45:56Z on 127.0.0.1:43890 and 18:49:56Z
        // on 127.0.0.1:37146, NotAfter still 18:45:24Z). This is a second sparse two-
        // occurrence post-bare-restart reconnect twin of the denser 9a811bb8… /
        // f95adc65… storms and of the earlier 7421834a4183… pair (cid 30 → 46 at
        // 18:45:50Z / 18:49:50Z), and the fra twin of gru b252d8996050… / sfo
        // 97d33257778a… at the same wall-clock :56 steps: health probes present
        // operator-read every cycle while bare RestartAsync of NATS reloads the same
        // expired PEM and re-emits the server-side handshake error on the next reconnect.
        // Recovery must match every occurrence, skip startup grace for cert failures, and
        // force remint from invalid on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:45:56.052194 [ERR] 127.0.0.1:43890 - cid:33 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:45:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:49:56.248657 [ERR] 127.0.0.1:37146 - cid:49 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:49:56Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint b2dec42a6166…): same 6477b788… operator-read leaf and fra control
        // issuer as 9a811bb8b959… / f95adc65… / 7421834a4183… / c74671d2c0e4…, observed
        // twice after control-NATS recycle (cid 36 → 68 at 18:46:01Z on 127.0.0.1:43922 and
        // 18:47:01Z on 127.0.0.1:42774, NotAfter still 18:45:24Z). This is a third sparse
        // two-occurrence post-bare-restart reconnect twin of the denser 9a811bb8… /
        // f95adc65… storms and of the earlier 7421834a4183… (cid 30 → 46 at 18:45:50Z /
        // 18:49:50Z) and c74671d2c0e4… (cid 33 → 49 at 18:45:56Z / 18:49:56Z) pairs, and the
        // fra peer of gru 6a650c470be6… (cid 37 → 69) / sfo d80a6067f126… (cid 37 → 68) at
        // the same wall-clock :01 steps: health probes present operator-read every cycle
        // while bare RestartAsync of NATS reloads the same expired PEM and re-emits the
        // server-side handshake error on the next reconnect. Recovery must match every
        // occurrence, skip startup grace for cert failures, and force remint from invalid
        // on-disk probe leaves so the recycle loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:01.977899 [ERR] 127.0.0.1:43922 - cid:36 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:01.737094 [ERR] 127.0.0.1:42774 - cid:68 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:01Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint d26af782af24…): same 6477b788… operator-read leaf and fra control
        // issuer as 9a811bb8b959… / f95adc65… / 7421834a4183… / c74671d2c0e4… /
        // b2dec42a6166…, observed twice after control-NATS recycle (cid 40 → 71 at
        // 18:46:07Z on 127.0.0.1:48686 and 18:47:07Z on 127.0.0.1:46486, NotAfter still
        // 18:45:24Z). This is a fourth sparse two-occurrence post-bare-restart reconnect
        // twin of the denser 9a811bb8… / f95adc65… storms and of the earlier
        // 7421834a4183… (cid 30 → 46 at 18:45:50Z / 18:49:50Z), c74671d2c0e4… (cid 33 → 49
        // at 18:45:56Z / 18:49:56Z), and b2dec42a6166… (cid 36 → 68 at 18:46:01Z /
        // 18:47:01Z) pairs, and the fra peer of gru 5c56829c01e4… (cid 40 → 72) / sfo
        // 58dda0785551… (cid 40 → 72) at the same wall-clock :07 steps as fra-controller
        // 88eec19ebb94… / sfo-platform ef71b6e32493… / gru-platform 0401b56675fd…: health
        // probes present operator-read every cycle while bare RestartAsync of NATS reloads
        // the same expired PEM and re-emits the server-side handshake error on the next
        // reconnect. Recovery must match every occurrence, skip startup grace for cert
        // failures, and force remint from invalid on-disk probe leaves so the recycle loop
        // cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:07.924716 [ERR] 127.0.0.1:48686 - cid:40 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:07.648094 [ERR] 127.0.0.1:46486 - cid:71 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:07Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Exact fra-control-nats / CN=operator-read two-occurrence post-recycle shape
        // (fingerprint 424b0b6af457…): same 6477b788… operator-read leaf and fra control
        // issuer as 9a811bb8b959… / f95adc65… / 7421834a4183… / c74671d2c0e4… /
        // b2dec42a6166… / d26af782af24…, observed twice after control-NATS recycle
        // (cid 43 → 75 at 18:46:13Z on 127.0.0.1:48710 and 18:47:13Z on 127.0.0.1:46544,
        // NotAfter still 18:45:24Z). This is a fifth sparse two-occurrence post-bare-
        // restart reconnect twin of the denser 9a811bb8… / f95adc65… storms and of the
        // earlier 7421834a4183… (cid 30 → 46 at 18:45:50Z / 18:49:50Z), c74671d2c0e4…
        // (cid 33 → 49 at 18:45:56Z / 18:49:56Z), b2dec42a6166… (cid 36 → 68 at 18:46:01Z /
        // 18:47:01Z), and d26af782af24… (cid 40 → 71 at 18:46:07Z / 18:47:07Z) pairs, and
        // the fra operator-read peer of gru 9dd8feb97fa2… (cid 43 → 75) / sfo-platform
        // e583d837318a… / fra-platform d86f81358e32… at the same wall-clock :13 steps:
        // health probes present operator-read every cycle while bare RestartAsync of NATS
        // reloads the same expired PEM and re-emits the server-side handshake error on the
        // next reconnect. Recovery must match every occurrence, skip startup grace for
        // cert failures, and force remint from invalid on-disk probe leaves so the recycle
        // loop cannot continue.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:46:13.979902 [ERR] 127.0.0.1:48710 - cid:43 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:46:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "[fra-control-nats-1] [1] 2026/07/21 18:47:13.816176 [ERR] 127.0.0.1:46544 - cid:75 - " +
                "TLS handshake error: tls: failed to verify certificate: x509: certificate has expired " +
                "or is not yet valid: current time 2026-07-21T18:47:13Z is after 2026-07-21T18:45:24Z " +
                "(CN=operator-read SHA-256: 6477b78851b42f39bb319fafc6ef3863ae4bd0223446f9b76eb026f1e3e802af; " +
                "CN=TerraScale fra control issuer SHA-256: 0233c03792ae90553dbf3e7592420fa92fabf09fdc84f2224b6f743e66d0e742)"))
            .IsTrue();
        // Pre-connect leaf refusal must still feed force-remint (same recovery path as
        // post-connect FormatProbeFailure annotations).
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: certificate has expired: current time 2026-07-21T18:45:28.0000000Z " +
                "is after 2026-07-21T18:45:24.0000000Z"))
            .IsTrue();
        // Fingerprint c05d3fee208c… (and control-NATS / product-NATS / controller twins
        // including b0ca5ad6b00f…, 1e57af750edb…, 2c66150c157c…, 666f072201a5…,
        // 6da1925a9038…, 7bead2653aa7…, bfa083ed37ee…, and e1c5c64cbb9d…): orchestrator
        // logged "Restarted unhealthy development resource gru-control-nats-1: Health
        // probe failed: can not start to connect nats server: nats://127.0.0.1:18600"
        // three times between 18:45:41Z and 18:49:11Z. The outer NATS.Net text alone is
        // intentionally not a certificate-shaped match — remint must still win via
        // RequiresForceRemintOnPersistentUnhealth so bare RestartAsync cannot thrash NATS.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18600"))
            .IsFalse();
        // Exact sfo control-plane twin (fingerprint b0ca5ad6b00f…): same outer text on
        // sfo-control-nats-1 :18800 three bare restarts between 18:45:42Z and 18:49:12Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800"))
            .IsFalse();
        // Exact fra control-plane twin (fingerprint 1e57af750edb…): same outer text on
        // fra-control-nats-1 :19000 three bare restarts between 18:45:44Z and 18:49:13Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000"))
            .IsFalse();
        // Exact product-plane twin (fingerprint 2c66150c157c…): same outer text on
        // gru-product-nats-1 :18620 three bare restarts between 18:45:42Z and 18:49:12Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18620"))
            .IsFalse();
        // Exact sfo product-plane twin (fingerprint 666f072201a5…): same outer text on
        // sfo-product-nats-1 :18820 three bare restarts between 18:45:43Z and 18:49:13Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18820"))
            .IsFalse();
        // Exact fra product-plane twin (fingerprint 6da1925a9038…): same outer text on
        // fra-product-nats-1 :19020 three bare restarts between 18:45:44Z and 18:49:14Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19020"))
            .IsFalse();
        // Exact gru controller twin (fingerprint 7bead2653aa7…): same outer text on
        // gru-controller-1 probing :18600 three bare restarts between 18:45:42Z and
        // 18:49:12Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18600"))
            .IsFalse();
        // Exact sfo controller twin (fingerprint bfa083ed37ee…): same outer text on
        // sfo-controller-1 probing :18800 three bare restarts between 18:45:44Z and
        // 18:49:13Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800"))
            .IsFalse();
        // Exact fra controller twin (fingerprint e1c5c64cbb9d…): same outer text on
        // fra-controller-1 probing :19000 three bare restarts between 18:45:45Z and
        // 18:49:20Z.
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000"))
            .IsFalse();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: Connection refused"))
            .IsFalse();
    }

    [Test]
    public async Task PlainNatsConnectFailuresForceRemintInsteadOfBareRestartOnControlPlane()
    {
        // Fingerprint c05d3fee208c…: three bare restarts of gru-control-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18600".
        // Fingerprint b0ca5ad6b00f…: three bare restarts of sfo-control-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18800"
        // between 18:45:42Z and 18:49:12Z (sfo twin of c05d3fee208c…).
        // Fingerprint 1e57af750edb…: three bare restarts of fra-control-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:19000"
        // between 18:45:44Z and 18:49:13Z (fra twin of c05d3fee208c… / b0ca5ad6b00f…).
        // LooksLikeCertificateFailure is false for that text; recovery must still classify
        // control/product NATS and controllers as force-remint so the consecutive-unhealthy
        // path never logs "Restarted unhealthy development resource *-control-nats-1: …".
        var topology = DevelopmentTopology.CreateThreeCellLean();
        foreach (var cell in new[] { "gru", "sfo", "fra" })
        {
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-control-nats-1"))
                .IsTrue();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-product-nats-1"))
                .IsTrue();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-controller-1"))
                .IsTrue();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-platform"))
                .IsFalse();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-authentication"))
                .IsFalse();
        }

        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "email-emulator"))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "missing-resource"))
            .IsFalse();

        // Exact orchestrator restart log detail that DevHost scrapes for c05d3fee208c… —
        // not certificate-shaped, but control-NATS must still force remint.
        const string gruControlConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18600";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(gruControlConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "gru-control-nats-1"))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for b0ca5ad6b00f… —
        // not certificate-shaped, but sfo control-NATS must still force remint.
        const string sfoControlConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoControlConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "sfo-control-nats-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for b0ca5ad6b00f… (resource + detail).
        const string sfoControlRestartLog =
            "Restarted unhealthy development resource sfo-control-nats-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoControlRestartLog))
            .IsFalse();
        await Assert.That(sfoControlRestartLog.Contains(
                "Restarted unhealthy development resource sfo-control-nats-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for 1e57af750edb… —
        // not certificate-shaped, but fra control-NATS must still force remint.
        const string fraControlConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraControlConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "fra-control-nats-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for 1e57af750edb… (resource + detail).
        const string fraControlRestartLog =
            "Restarted unhealthy development resource fra-control-nats-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraControlRestartLog))
            .IsFalse();
        await Assert.That(fraControlRestartLog.Contains(
                "Restarted unhealthy development resource fra-control-nats-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Sibling control endpoints that share the same bare-restart normalized shape.
        foreach (var endpoint in new[]
                 {
                     ("gru-control-nats-1", "nats://127.0.0.1:18600"),
                     ("sfo-control-nats-1", "nats://127.0.0.1:18800")
                 })
        {
            var detail = $"Health probe failed: can not start to connect nats server: {endpoint.Item2}";
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(detail)).IsFalse();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, endpoint.Item1))
                .IsTrue();
        }
    }

    [Test]
    public async Task PlainNatsConnectFailuresForceRemintInsteadOfBareRestartOnProductPlane()
    {
        // Fingerprint 2c66150c157c…: three bare restarts of gru-product-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18620"
        // between 18:45:42Z and 18:49:12Z. Product-plane twin of c05d3fee208c… (control
        // :18600): LooksLikeCertificateFailure is intentionally false for that outer text,
        // so recovery must still force remint via RequiresForceRemintOnPersistentUnhealth
        // and never log "Restarted unhealthy development resource gru-product-nats-1: …".
        // Fingerprint 666f072201a5…: three bare restarts of sfo-product-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18820"
        // between 18:45:43Z and 18:49:13Z (sfo product twin of 2c66150c157c…).
        // Fingerprint 6da1925a9038…: three bare restarts of fra-product-nats-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:19020"
        // between 18:45:44Z and 18:49:14Z (fra product twin of 2c66150c157c… / 666f072201a5…).
        var topology = DevelopmentTopology.CreateThreeCellLean();
        foreach (var cell in new[] { "gru", "sfo", "fra" })
        {
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-product-nats-1"))
                .IsTrue();
        }

        // Exact orchestrator restart log detail that DevHost scrapes for 2c66150c157c… —
        // not certificate-shaped, but product-NATS must still force remint.
        const string gruProductConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18620";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(gruProductConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "gru-product-nats-1"))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for 666f072201a5… —
        // not certificate-shaped, but sfo product-NATS must still force remint.
        const string sfoProductConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18820";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoProductConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "sfo-product-nats-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for 666f072201a5… (resource + detail).
        const string sfoProductRestartLog =
            "Restarted unhealthy development resource sfo-product-nats-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18820";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoProductRestartLog))
            .IsFalse();
        await Assert.That(sfoProductRestartLog.Contains(
                "Restarted unhealthy development resource sfo-product-nats-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for 6da1925a9038… —
        // not certificate-shaped, but fra product-NATS must still force remint.
        const string fraProductConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19020";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraProductConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "fra-product-nats-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for 6da1925a9038… (resource + detail).
        const string fraProductRestartLog =
            "Restarted unhealthy development resource fra-product-nats-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19020";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraProductRestartLog))
            .IsFalse();
        await Assert.That(fraProductRestartLog.Contains(
                "Restarted unhealthy development resource fra-product-nats-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Sibling product endpoints that share the same bare-restart normalized shape.
        foreach (var endpoint in new[]
                 {
                     ("gru-product-nats-1", "nats://127.0.0.1:18620"),
                     ("sfo-product-nats-1", "nats://127.0.0.1:18820")
                 })
        {
            var detail = $"Health probe failed: can not start to connect nats server: {endpoint.Item2}";
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(detail)).IsFalse();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, endpoint.Item1))
                .IsTrue();
        }
    }

    [Test]
    public async Task PlainNatsConnectFailuresForceRemintInsteadOfBareRestartOnControllers()
    {
        // Fingerprint 7bead2653aa7…: three bare restarts of gru-controller-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18600"
        // between 18:45:42Z and 18:49:12Z (same window as product-NATS 2c66150c157c… and
        // control-NATS c05d3fee208c…). Controller-health twin of those NATS thrash paths:
        // LooksLikeCertificateFailure is intentionally false for that outer text, so
        // recovery must still force remint via RequiresForceRemintOnPersistentUnhealth and
        // never log "Restarted unhealthy development resource gru-controller-1: …".
        // Fingerprint bfa083ed37ee…: three bare restarts of sfo-controller-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:18800"
        // between 18:45:44Z and 18:49:13Z (sfo controller twin of 7bead2653aa7…).
        // Fingerprint e1c5c64cbb9d…: three bare restarts of fra-controller-1 with only the
        // outer probe detail "can not start to connect nats server: nats://127.0.0.1:19000"
        // between 18:45:45Z and 18:49:20Z (fra controller twin of 7bead2653aa7… /
        // bfa083ed37ee…).
        var topology = DevelopmentTopology.CreateThreeCellLean();
        foreach (var cell in new[] { "gru", "sfo", "fra" })
        {
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, $"{cell}-controller-1"))
                .IsTrue();
        }

        // Exact orchestrator restart log detail that DevHost scrapes for 7bead2653aa7… —
        // not certificate-shaped, but controllers must still force remint.
        const string gruControllerConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18600";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(gruControllerConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "gru-controller-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for 7bead2653aa7… (resource + detail).
        const string gruControllerRestartLog =
            "Restarted unhealthy development resource gru-controller-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18600";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(gruControllerRestartLog))
            .IsFalse();
        await Assert.That(gruControllerRestartLog.Contains(
                "Restarted unhealthy development resource gru-controller-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for bfa083ed37ee… —
        // not certificate-shaped, but sfo controller must still force remint.
        const string sfoControllerConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoControllerConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "sfo-controller-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for bfa083ed37ee… (resource + detail).
        const string sfoControllerRestartLog =
            "Restarted unhealthy development resource sfo-controller-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:18800";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(sfoControllerRestartLog))
            .IsFalse();
        await Assert.That(sfoControllerRestartLog.Contains(
                "Restarted unhealthy development resource sfo-controller-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Exact orchestrator restart log detail that DevHost scrapes for e1c5c64cbb9d… —
        // not certificate-shaped, but fra controller must still force remint.
        const string fraControllerConnectFailure =
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraControllerConnectFailure))
            .IsFalse();
        await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                topology, "fra-controller-1"))
            .IsTrue();

        // Full restart-log shape DevHost normalizes for e1c5c64cbb9d… (resource + detail).
        const string fraControllerRestartLog =
            "Restarted unhealthy development resource fra-controller-1: " +
            "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000";
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(fraControllerRestartLog))
            .IsFalse();
        await Assert.That(fraControllerRestartLog.Contains(
                "Restarted unhealthy development resource fra-controller-1:",
                StringComparison.Ordinal))
            .IsTrue();

        // Sibling controller endpoints that share the same bare-restart normalized shape.
        foreach (var endpoint in new[]
                 {
                     ("gru-controller-1", "nats://127.0.0.1:18600"),
                     ("sfo-controller-1", "nats://127.0.0.1:18800")
                 })
        {
            var detail = $"Health probe failed: can not start to connect nats server: {endpoint.Item2}";
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(detail)).IsFalse();
            await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                    topology, endpoint.Item1))
                .IsTrue();
        }
    }

    [Test]
    public async Task InvalidControlNatsServerLeafForcesRemintBeforeBareRestart()
    {
        // Server-facing PEMs are not presented by health probes (operator-read is), so an
        // expired server leaf alone used to fall through to bare RestartAsync and the
        // c05d3fee208c… / b0ca5ad6b00f… / 1e57af750edb… "can not start to connect" thrash.
        // EnumerateReconnectTlsIdentities must include the NATS server Client/Route leaves
        // for every control cell (gru :18600, sfo :18800, fra :19000).
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-server-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            foreach (var cell in new[] { "gru", "sfo", "fra" })
            {
                var resourceName = $"{cell}-control-nats-1";
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, resourceName))
                    .IsFalse();

                var serverTls = security.Cell(cell).Tls.Control.Servers[resourceName].Client;
                using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                           System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
                {
                    var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                        $"CN={resourceName}",
                        ecdsa,
                        System.Security.Cryptography.HashAlgorithmName.SHA256);
                    var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                    var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                    using var expired = request.CreateSelfSigned(notBefore, notAfter);
                    File.WriteAllText(serverTls.CertificateFile, expired.ExportCertificatePem());
                }

                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, resourceName))
                    .IsTrue();
                // Operator-read probe leaf remains valid; remint is driven by the server PEM.
                await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(
                        security.Cell(cell).Tls.Control.Clients["operator-read"].CertificateFile))
                    .IsNull();
                await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                        topology, resourceName))
                    .IsTrue();
            }
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
    public async Task InvalidProductNatsServerLeafForcesRemintBeforeBareRestart()
    {
        // Product-plane twin of InvalidControlNatsServerLeafForcesRemintBeforeBareRestart
        // (fingerprint 2c66150c157c… / 666f072201a5… / 6da1925a9038…): health probes present
        // the platform leaf, not the product NATS server Client/Route PEMs. An expired server
        // leaf alone used to fall through to bare RestartAsync and the "can not start to
        // connect nats server: nats://127.0.0.1:18620" / ":18820" / ":19020" thrash.
        // EnumerateReconnectTlsIdentities must include product server Client/Route leaves for
        // every product cell (gru :18620, sfo :18820, fra :19020).
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-product-server-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            foreach (var cell in new[] { "gru", "sfo", "fra" })
            {
                var resourceName = $"{cell}-product-nats-1";
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, resourceName))
                    .IsFalse();

                var serverTls = security.Cell(cell).Tls.Product.Servers[resourceName].Client;
                using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                           System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
                {
                    var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                        $"CN={resourceName}",
                        ecdsa,
                        System.Security.Cryptography.HashAlgorithmName.SHA256);
                    var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                    var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                    using var expired = request.CreateSelfSigned(notBefore, notAfter);
                    File.WriteAllText(serverTls.CertificateFile, expired.ExportCertificatePem());
                }

                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, resourceName))
                    .IsTrue();
                // Platform probe leaf remains valid; remint is driven by the server PEM.
                await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(
                        security.Cell(cell).Tls.Product.Clients[$"{cell}-platform"].CertificateFile))
                    .IsNull();
                await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                        topology, resourceName))
                    .IsTrue();
            }
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
    public async Task InvalidControlNatsServerLeafForcesControllerRemintBeforeBareRestart()
    {
        // Fingerprint 7bead2653aa7… / bfa083ed37ee… / e1c5c64cbb9d…: controller health
        // probes ConnectAsync to control NATS and present the controller leaf, not the
        // control-NATS server Client/Route PEMs. An expired server leaf alone used to leave
        // ResourceHasInvalidTlsLeaf(controller) false while the probe only reported
        // "can not start to connect nats server: nats://127.0.0.1:18600" / ":18800" /
        // ":19000", so the consecutive-unhealthy path bare-RestartAsync'd gru-controller-1 /
        // sfo-controller-1 / fra-controller-1 three times. EnumerateReconnectTlsIdentities
        // for controllers must include control server Client/Route leaves for every control
        // cell (gru :18600, sfo :18800, fra :19000).
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-controller-server-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            foreach (var cell in new[] { "gru", "sfo", "fra" })
            {
                var controllerName = $"{cell}-controller-1";
                var controlNatsName = $"{cell}-control-nats-1";
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, controllerName))
                    .IsFalse();

                // Controller leaf remains valid; only the server PEM is expired.
                await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(
                        security.Cell(cell).Tls.Control.Clients[controllerName].CertificateFile))
                    .IsNull();

                var serverTls = security.Cell(cell).Tls.Control.Servers[controlNatsName].Client;
                using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                           System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
                {
                    var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                        $"CN={controlNatsName}",
                        ecdsa,
                        System.Security.Cryptography.HashAlgorithmName.SHA256);
                    var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                    var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                    using var expired = request.CreateSelfSigned(notBefore, notAfter);
                    File.WriteAllText(serverTls.CertificateFile, expired.ExportCertificatePem());
                }

                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, controllerName))
                    .IsTrue();
                await Assert.That(DevelopmentLab.RequiresForceRemintOnPersistentUnhealth(
                        topology, controllerName))
                    .IsTrue();
            }
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
    public async Task InvalidOperatorReadLeafIsDetectedForSfoControlNatsBeforeBareRestart()
    {
        // Fingerprints e517701a2468…, f08d1c577176…, 62860f83eeb6…, 97d33257778a…,
        // d80a6067f126…, 58dda0785551…, and 69541ea34d1d…: sfo-control-nats health probes
        // present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // gru twin (cid 29237 → 62 → 69 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin
        // cid 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against
        // the same aa00c1c3… leaf; two-occurrence post-recycle twin cid 30 → 46 at
        // 18:45:50Z on 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070 for 62860f83eeb6…;
        // second two-occurrence post-recycle twin cid 33 → 50 at 18:45:56Z on
        // 127.0.0.1:52196 and 18:49:56Z on 127.0.0.1:36654 for 97d33257778a…; third
        // two-occurrence post-recycle twin cid 37 → 68 at 18:46:01Z on 127.0.0.1:52246 and
        // 18:47:01Z on 127.0.0.1:34762 for d80a6067f126…; fourth two-occurrence post-recycle
        // twin cid 40 → 72 at 18:46:07Z on 127.0.0.1:49186 and 18:47:07Z on 127.0.0.1:53880
        // for 58dda0785551…; fifth two-occurrence post-recycle twin cid 43 → 75 at
        // 18:46:13Z on 127.0.0.1:49240 and 18:47:13Z on 127.0.0.1:53920 for 69541ea34d1d…,
        // sfo peer of gru 9dd8feb97fa2… / fra 424b0b6af457… / sfo-platform e583d837318a… /
        // fra-platform d86f81358e32… at the same wall-clock :13 steps). When only the sfo
        // operator-read PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true
        // for sfo-control-nats-1 so force-remint runs instead of bare RestartAsync.
        await AssertInvalidOperatorReadLeafForcesRemintForCellAsync("sfo");
    }

    [Test]
    public async Task InvalidOperatorReadLeafIsDetectedForGruControlNatsBeforeBareRestart()
    {
        // Fingerprints c6627a56bf45…, c48cbf142a9a…, f4f92376efda…, b252d8996050…,
        // 6a650c470be6…, 5c56829c01e4…, and 9dd8feb97fa2…: gru-control-nats health probes
        // present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // sfo twin (cid 29237 → 62 → 69 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin
        // cid 29239 → 34 → 66 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against
        // the same 4e40db2b… leaf; two-occurrence post-recycle twin cid 31 → 46 at
        // 18:45:50Z on 127.0.0.1:56170 and 18:49:50Z on 127.0.0.1:45996 for f4f92376efda…;
        // second two-occurrence post-recycle twin cid 34 → 51 at 18:45:56Z on
        // 127.0.0.1:54410 and 18:49:56Z on 127.0.0.1:35762 for b252d8996050…; third
        // two-occurrence post-recycle twin cid 37 → 69 at 18:46:01Z on 127.0.0.1:54470 and
        // 18:47:01Z on 127.0.0.1:57302 for 6a650c470be6…, gru peer of sfo d80a6067f126…;
        // fourth two-occurrence post-recycle twin cid 40 → 72 at 18:46:07Z on
        // 127.0.0.1:48998 and 18:47:07Z on 127.0.0.1:42902 for 5c56829c01e4…, gru peer of
        // sfo 58dda0785551…; fifth two-occurrence post-recycle twin cid 43 → 75 at
        // 18:46:13Z on 127.0.0.1:49032 and 18:47:13Z on 127.0.0.1:42960 for 9dd8feb97fa2…,
        // gru peer of sfo-platform e583d837318a… / fra-platform d86f81358e32… at the same
        // wall-clock :13 steps). When only the gru operator-read PEM is past NotAfter,
        // ResourceHasInvalidTlsLeaf must still be true for gru-control-nats-1 so force-
        // remint runs instead of bare RestartAsync.
        await AssertInvalidOperatorReadLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidOperatorReadLeafIsDetectedForFraControlNatsBeforeBareRestart()
    {
        // Fingerprints 9a811bb8b959…, f95adc65…, 7421834a4183…, c74671d2c0e4…,
        // b2dec42a6166…, d26af782af24…, and 424b0b6af457…: fra-control-nats health probes
        // present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // gru/sfo twins (cid 29237 → 63 → 68 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser
        // twin cid 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z
        // against the same 6477b788… leaf; two-occurrence post-recycle twin cid 30 → 46 at
        // 18:45:50Z on 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762 for 7421834a4183…;
        // second two-occurrence post-recycle twin cid 33 → 49 at 18:45:56Z on
        // 127.0.0.1:43890 and 18:49:56Z on 127.0.0.1:37146 for c74671d2c0e4…; third
        // two-occurrence post-recycle twin cid 36 → 68 at 18:46:01Z on 127.0.0.1:43922 and
        // 18:47:01Z on 127.0.0.1:42774 for b2dec42a6166…, fra peer of gru 6a650c470be6… /
        // sfo d80a6067f126…; fourth two-occurrence post-recycle twin cid 40 → 71 at
        // 18:46:07Z on 127.0.0.1:48686 and 18:47:07Z on 127.0.0.1:46486 for d26af782af24…,
        // fra peer of gru 5c56829c01e4… / sfo 58dda0785551…; fifth two-occurrence
        // post-recycle twin cid 43 → 75 at 18:46:13Z on 127.0.0.1:48710 and 18:47:13Z on
        // 127.0.0.1:46544 for 424b0b6af457…, fra peer of gru 9dd8feb97fa2… / sfo-platform
        // e583d837318a… / fra-platform d86f81358e32… at the same wall-clock :13 steps).
        // When only the fra operator-read PEM is past NotAfter, ResourceHasInvalidTlsLeaf
        // must still be true for fra-control-nats-1 so force-remint runs instead of bare
        // RestartAsync.
        await AssertInvalidOperatorReadLeafForcesRemintForCellAsync("fra");
    }

    private static async Task AssertInvalidOperatorReadLeafForcesRemintForCellAsync(string cell)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var controlNatsName = $"{cell}-control-nats-1";
        var platformName = $"{cell}-platform";
        var otherCells = new[] { "gru", "sfo", "fra" }
            .Where(candidate => !string.Equals(candidate, cell, StringComparison.Ordinal))
            .ToArray();
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-{cell}-operator-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);

            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsFalse();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsFalse();
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, controlNatsName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/operator/operator-read");
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, platformName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/workload/{platformName}");
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, "email-emulator"))
                .IsNull();

            var operatorTls = security.Cell(cell).Tls.Control.Clients["operator-read"];
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

            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsTrue();
            // Other cells still have valid operator-read leaves; AnyProbe must still trip
            // because this cell's probe identity is invalid.
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
            foreach (var other in otherCells)
            {
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, $"{other}-control-nats-1"))
                    .IsFalse();
            }

            // A single deleted probe leaf must also force remint even when the NotAfter
            // survey of remaining siblings would still look healthy.
            File.Delete(operatorTls.CertificateFile);
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsTrue();
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
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
    public async Task InvalidControllerLeafIsDetectedForSfoControlNatsBeforeBareRestart()
    {
        // Fingerprints f490b625…, 9815ef5a…, 4eeeee0520a1…, e8e55fe0bef9…, 412baaa56842…,
        // 71cf8514f4d6…, ce40d219dc90…, fc867739e2e2…, 3db5efff618c…, c9f4a06686ba…,
        // a5ee4c55235d…, 914b99d5fbc6…, 53b4362b4444…, and bbdb6e0d6006…: sfo-controller-1
        // (not operator-read) presents the control leaf. When only that PEM is past NotAfter,
        // ResourceHasInvalidTlsLeaf must still be true for sfo-control-nats-1 so the
        // consecutive-unhealthy path force-remints instead of bare RestartAsync (cid recycle
        // 29238 → 63 → 70 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin cid 29240 → 34 →
        // 35 → 66 → 73 at 18:45:40Z / 18:47:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the
        // same f56fe7a4… leaf, dual reconnect at 18:47:40Z; two-occurrence post-recycle twin
        // cid 28 → 36 at 18:45:45Z on 127.0.0.1:50552 and 18:47:45Z on 127.0.0.1:37302 for
        // 4eeeee0520a1…; second two-occurrence post-recycle twin cid 29 → 61 at 18:45:47Z on
        // 127.0.0.1:50560 and 18:46:47Z on 127.0.0.1:55476 for e8e55fe0bef9…; three-occurrence
        // post-recycle twin cid 31 → 39 → 47 at 18:45:50Z on 127.0.0.1:50606, 18:47:50Z on
        // 127.0.0.1:37360, and 18:49:50Z on 127.0.0.1:34092 for 412baaa56842…; four-occurrence
        // post-recycle twin cid 32 → 41 → 71 → 48 at 18:45:51Z on 127.0.0.1:50616, 18:47:51Z
        // on 127.0.0.1:37414, 18:48:51Z on 127.0.0.1:58882, and 18:49:51Z on 127.0.0.1:34106
        // for 71cf8514f4d6…; second four-occurrence post-recycle twin cid 64 → 73 → 78 → 80 at
        // 18:46:52Z on 127.0.0.1:55524, 18:48:52Z on 127.0.0.1:58922, and 18:50:52Z on
        // 127.0.0.1:52222 / 127.0.0.1:52258 dual for ce40d219dc90…; five-occurrence
        // post-recycle twin cid 34 → 35 → 74 → 49 → 51 at 18:45:56Z on 127.0.0.1:52202 /
        // 127.0.0.1:52218 dual, 18:48:56Z on 127.0.0.1:51334, and 18:49:56Z on 127.0.0.1:36626
        // / 127.0.0.1:36656 dual for fc867739e2e2…; second five-occurrence post-recycle twin
        // cid 36 → 38 → 69 → 77 → 52 at 18:46:01Z on 127.0.0.1:52226 / 127.0.0.1:52264 dual,
        // 18:47:01Z on 127.0.0.1:34778, 18:49:01Z on 127.0.0.1:51374, and 18:50:01Z on
        // 127.0.0.1:36672 for 3db5efff618c…; three-occurrence post-recycle twin cid 39 → 80 →
        // 55 at 18:46:06Z on 127.0.0.1:49160, 18:49:06Z on 127.0.0.1:37578, and 18:50:06Z on
        // 127.0.0.1:48750 for c9f4a06686ba…; three-occurrence post-recycle twin cid 41 → 71 →
        // 73 at 18:46:07Z on 127.0.0.1:49206 and 18:47:07Z on 127.0.0.1:53864 /
        // 127.0.0.1:53886 dual for a5ee4c55235d…; three-occurrence post-recycle twin cid 42 →
        // 83 → 58 at 18:46:11Z on 127.0.0.1:49220, 18:49:11Z on 127.0.0.1:37634, and 18:50:11Z
        // on 127.0.0.1:48798 for 914b99d5fbc6…; two-occurrence post-recycle twin cid 44 → 76
        // at 18:46:13Z on 127.0.0.1:49260 and 18:47:13Z on 127.0.0.1:53940 for 53b4362b4444…;
        // three-occurrence post-recycle twin cid 45 → 29 → 61 at 18:46:16Z on
        // 127.0.0.1:40982, 18:49:16Z on 127.0.0.1:35628, and 18:50:16Z on 127.0.0.1:52900 for
        // bbdb6e0d6006… — three seconds after 53b4362b4444… and sfo peer of gru d00ef05a1026…
        // at the adjacent wall-clock :15/:16 steps).
        // Control-NATS probes present only operator-read, so recovery must survey controller
        // leaves on the NATS resource independently of the probe leaf.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("sfo");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForGruControlNatsBeforeBareRestart()
    {
        // Fingerprints c2bf6b539a62…, 782d6308…, 003657d51ecd…, b9dc4dd1a8ef…, 7b6a047263d8…,
        // 87f7f1566c88…, a9bf884a363b…, 25b92b919c66…, 34c89dedb769…, 024cbd22bdf4…,
        // e7ad7a71e395…, 96fe8dda09bb…, d2538c612184…, and d00ef05a1026…: gru-controller-1
        // (not operator-read) presents the control leaf. Same NotAfter window and bare-NATS-
        // recycle storm as the sfo twin (cid 29238 → 32 → 63 → 70 at 18:45:34Z / 18:47:34Z /
        // 18:48:34Z / 18:50:34Z; denser twin cid 29240 → 58 → 35 → 65 → 67 → 42 → 73 at
        // 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:48:40Z / 18:49:40Z / 18:50:40Z
        // against the same d467c210… leaf; two-occurrence post-recycle twin cid 28 → 60 at
        // 18:45:43Z on 127.0.0.1:49796 and 18:46:43Z on 127.0.0.1:60312 for 003657d51ecd…;
        // four-occurrence post-recycle twin cid 29 → 61 → 68 → 45 at 18:45:45Z on
        // 127.0.0.1:56146, 18:46:45Z on 127.0.0.1:57182, 18:48:45Z on 127.0.0.1:55606, and
        // 18:49:45Z on 127.0.0.1:45982 for b9dc4dd1a8ef…; six-occurrence post-recycle twin
        // cid 30 → 32 → 64 → 71 → 47 → 48 at 18:45:50Z on 127.0.0.1:56154 / 127.0.0.1:56178
        // dual, 18:46:50Z on 127.0.0.1:57224, 18:48:50Z on 127.0.0.1:55652, and 18:49:50Z on
        // 127.0.0.1:46006 / 127.0.0.1:46018 dual for 7b6a047263d8…; five-occurrence post-
        // recycle twin cid 33 → 67 → 65 → 74 → 49 at 18:45:55Z on 127.0.0.1:54390, 18:46:55Z
        // on 127.0.0.1:57284 / 127.0.0.1:57238 dual, 18:48:55Z on 127.0.0.1:46006, and
        // 18:49:55Z on 127.0.0.1:35748 for 87f7f1566c88…; three-occurrence post-recycle twin
        // cid 35 → 50 → 81 at 18:45:56Z on 127.0.0.1:54434, 18:49:56Z on 127.0.0.1:35776, and
        // 18:50:56Z on 127.0.0.1:34540 for a9bf884a363b…; four-occurrence post-recycle twin
        // cid 36 → 68 → 77 → 52 at 18:46:00Z on 127.0.0.1:54442, 18:47:00Z on 127.0.0.1:57286,
        // 18:49:00Z on 127.0.0.1:46044, and 18:50:00Z on 127.0.0.1:35784 for 25b92b919c66…;
        // two-occurrence post-recycle twin cid 38 → 70 at 18:46:01Z on 127.0.0.1:54492 and
        // 18:47:01Z on 127.0.0.1:57318 for 34c89dedb769…; four-occurrence post-recycle twin
        // cid 39 → 71 → 80 → 55 at 18:46:05Z on 127.0.0.1:48986, 18:47:05Z on 127.0.0.1:42886,
        // 18:49:05Z on 127.0.0.1:51702, and 18:50:05Z on 127.0.0.1:35504 for 024cbd22bdf4…;
        // two-occurrence post-recycle twin cid 41 → 73 at 18:46:07Z on 127.0.0.1:49008 and
        // 18:47:07Z on 127.0.0.1:42932 for e7ad7a71e395…; seven-occurrence post-recycle twin
        // cid 42 → 74 → 50 → 51 → 81 → 83 → 58 at 18:46:10Z on 127.0.0.1:49018, 18:47:10Z on
        // 127.0.0.1:42948, 18:48:10Z on 127.0.0.1:40182 / 127.0.0.1:40194 dual, 18:49:10Z on
        // 127.0.0.1:51716 / 127.0.0.1:51744 dual, and 18:50:10Z on 127.0.0.1:35554 for
        // 96fe8dda09bb…; three-occurrence post-recycle twin cid 44 → 76 → 28 at 18:46:13Z on
        // 127.0.0.1:49052, 18:47:13Z on 127.0.0.1:42988, and 18:49:13Z on 127.0.0.1:51756 for
        // d2538c612184… — three-seconds-later sparse twin of 96fe8dda09bb… on adjacent ports,
        // control-plane peer of fra-controller 7063631384a4… and product-plane peer of
        // gru-platform 88ff8c404d3b… at the same wall-clock :13 steps; seven-occurrence
        // post-recycle twin cid 45 → 77 → 52 → 54 → 29 → 60 → 61 at 18:46:15Z on
        // 127.0.0.1:37246, 18:47:15Z on 127.0.0.1:34118, 18:48:15Z on 127.0.0.1:52154 /
        // 127.0.0.1:52194 dual, 18:49:15Z on 127.0.0.1:45258, and 18:50:15Z on
        // 127.0.0.1:57522 / 127.0.0.1:57524 dual for d00ef05a1026… — two-seconds-later denser
        // twin of d2538c612184… and denser seven-occurrence peer of 96fe8dda09bb… at the
        // adjacent wall-clock :15 steps). When only the gru-controller-1 PEM is past
        // NotAfter, ResourceHasInvalidTlsLeaf must still be true for gru-control-nats-1 so
        // force-remint runs instead of bare RestartAsync. Probes alone would miss this
        // because control-NATS probes present operator-read.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForFraControlNatsBeforeBareRestart()
    {
        // Fingerprints 91b5b852…, ffcef075c58c…, bca21682b315…, 23eafce842f6…, 4046b92fa615…,
        // 87c737a0ed10…, 5e5b835252fe…, 6e08a77cd4b6…, 876de6711801…, 52a227218acf…,
        // 88eec19ebb94…, 49ec50da2e2a…, 7063631384a4…, and d7de94966c92…: fra-controller-1
        // (not operator-read) presents the control leaf. Same NotAfter window and bare-NATS-
        // recycle storm as the sfo/gru twins (cid 29238 → 62 → 69 → 70 at 18:45:34Z /
        // 18:48:34Z / 18:50:34Z; denser twin cid 29240 → 34 → 66 → 73 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 8f6e801c… leaf; four-occurrence
        // post-recycle twin cid 28 → 37 → 69 → 76 at 18:45:46Z on 127.0.0.1:34624, 18:47:46Z
        // on 127.0.0.1:60304, 18:48:46Z on 127.0.0.1:50796, and 18:50:46Z on 127.0.0.1:54352
        // for bca21682b315…; single post-recycle twin cid:29 at 18:45:48Z on 127.0.0.1:34626
        // for 23eafce842f6…; two-occurrence post-recycle twin cid 31 → 47 at 18:45:50Z on
        // 127.0.0.1:34668 and 18:49:50Z on 127.0.0.1:33784 for 4046b92fa615…; seven-occurrence
        // post-recycle twin cid 32 → 64 → 41 → 72 → 73 → 48 → 79 at 18:45:52Z on
        // 127.0.0.1:34674, 18:46:52Z on 127.0.0.1:53654, 18:47:52Z on 127.0.0.1:60380,
        // 18:48:52Z on 127.0.0.1:50844 / 50858 dual, 18:49:52Z on 127.0.0.1:33786, and
        // 18:50:52Z on 127.0.0.1:54412 for 87c737a0ed10…; second two-occurrence post-recycle
        // twin cid 34 → 50 at 18:45:56Z on 127.0.0.1:43900 and 18:49:56Z on 127.0.0.1:37150
        // for 5e5b835252fe…; four-occurrence post-recycle twin cid 35 → 42 → 44 → 51 at
        // 18:45:57Z on 127.0.0.1:43906, 18:47:57Z on 127.0.0.1:44698 / 127.0.0.1:44730 dual,
        // and 18:49:57Z on 127.0.0.1:37152 for 6e08a77cd4b6…; two-occurrence post-recycle twin
        // cid 37 → 69 at 18:46:01Z on 127.0.0.1:43944 and 18:47:01Z on 127.0.0.1:42784 for
        // 876de6711801…; three-occurrence post-recycle twin cid 38 → 45 → 52 at 18:46:02Z on
        // 127.0.0.1:43948, 18:48:02Z on 127.0.0.1:44744, and 18:50:02Z on 127.0.0.1:37162 for
        // 52a227218acf…; five-occurrence post-recycle twin cid 39 → 41 → 72 → 48 → 55 at
        // 18:46:07Z on 127.0.0.1:48674 / 127.0.0.1:48694 dual, 18:47:07Z on 127.0.0.1:46502,
        // 18:48:07Z on 127.0.0.1:55402, and 18:50:07Z on 127.0.0.1:60620 for 88eec19ebb94… —
        // fra peer of gru 024cbd22bdf4… at adjacent :07 steps; three-occurrence post-recycle
        // twin cid 42 → 51 → 58 at 18:46:12Z on 127.0.0.1:48696, 18:48:12Z on 127.0.0.1:55440,
        // and 18:50:12Z on 127.0.0.1:60662 for 49ec50da2e2a… — sparse five-seconds-later twin
        // of 88eec19ebb94… on adjacent ports and fra peer of sfo 914b99d5fbc6… /
        // gru 96fe8dda09bb… at adjacent :10/:11/:12 steps; four-occurrence post-recycle twin
        // cid 44 → 74 → 76 → 83 at 18:46:13Z on 127.0.0.1:48726, 18:47:13Z on 127.0.0.1:46524 /
        // 127.0.0.1:46564 dual, and 18:49:13Z on 127.0.0.1:52176 for 7063631384a4… —
        // one-second-later twin of 49ec50da2e2a… on adjacent port 48696 → 48726 with denser
        // mid-window dual reconnect, control-plane peer of gru-platform 88ff8c404d3b… at the
        // same wall-clock :13 steps; three-occurrence post-recycle twin cid 45 → 54 → 61 at
        // 18:46:17Z on 127.0.0.1:45396, 18:48:17Z on 127.0.0.1:33434, and 18:50:17Z on
        // 127.0.0.1:58410 for d7de94966c92… — four seconds after 7063631384a4…, fra peer of
        // sfo bbdb6e0d6006… / gru d00ef05a1026… at the adjacent wall-clock :15/:16 steps, and
        // product-plane peer of fra-platform ec156a1db321… at the same wall-clock :17 steps).
        // When only the fra-controller-1 PEM is past NotAfter, ResourceHasInvalidTlsLeaf must
        // still be true for fra-control-nats-1 so force-remint runs instead of bare
        // RestartAsync. Probes alone would miss this because control-NATS probes present
        // operator-read.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("fra");
    }

    private static async Task AssertInvalidControllerLeafForcesRemintForCellAsync(string cell)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var controllerName = $"{cell}-controller-1";
        var controlNatsName = $"{cell}-control-nats-1";
        var otherCells = new[] { "gru", "sfo", "fra" }
            .Where(candidate => !string.Equals(candidate, cell, StringComparison.Ordinal))
            .ToArray();
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-{cell}-controller-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);

            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsFalse();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controllerName))
                .IsFalse();
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, controllerName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/controller/{controllerName}");
            var reconnectLeaves = DevelopmentLab.EnumerateReconnectTlsIdentities(
                    topology, security, controlNatsName)
                .Select(identity => identity.SpiffeId)
                .ToArray();
            await Assert.That(reconnectLeaves)
                .Contains($"spiffe://terrascale.tech/cell/{cell}/operator/operator-read");
            await Assert.That(reconnectLeaves)
                .Contains($"spiffe://terrascale.tech/cell/{cell}/controller/{controllerName}");

            var controllerTls = security.Cell(cell).Tls.Control.Clients[controllerName];
            var operatorTls = security.Cell(cell).Tls.Control.Clients["operator-read"];
            using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                       System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
            {
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    $"CN={controllerName}",
                    ecdsa,
                    System.Security.Cryptography.HashAlgorithmName.SHA256);
                var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                using var expired = request.CreateSelfSigned(notBefore, notAfter);
                File.WriteAllText(controllerTls.CertificateFile, expired.ExportCertificatePem());
            }

            // operator-read remains valid — the probe path alone would not force remint.
            await Assert.That(DevelopmentHealthProbe.DescribeLeafValidity(operatorTls.CertificateFile))
                .IsNull();
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, controlNatsName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/operator/operator-read");
            // Control NATS must still see the expired controller client leaf.
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controllerName))
                .IsTrue();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsTrue();
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
            // Other cells' control NATS stay clean when only this cell's controller is expired.
            foreach (var other in otherCells)
            {
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, $"{other}-control-nats-1"))
                    .IsFalse();
            }

            File.Delete(controllerTls.CertificateFile);
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, controlNatsName))
                .IsTrue();
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
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
    public async Task InvalidPlatformLeafIsDetectedForFraProductNatsBeforeBareRestart()
    {
        // Also fingerprint ec156a1db321…: two-occurrence post-recycle twin of
        // bf210e609e7f… / d86f81358e32… / a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… /
        // b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… /
        // 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
        // f106e39e815f… cid 52 → 91 / gru d0feba5039c6… cid:53 / gru 88ff8c404d3b… cid 51 →
        // 90 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru
        // 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid
        // 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 /
        // sfo e583d837318a… dual cid 49+50 → 88+89 / sfo 02525de8dfa3… cid 47 → 86 → 39 / sfo
        // ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
        // 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:46:17Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
        // 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
        // 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z /
        // 18:50:15Z steps) with cid 52 → 91 at 18:46:17Z on 127.0.0.1:47542 and
        // 18:47:17Z on 127.0.0.1:48210 against the same 7ef9d0a4… leaf — still requires
        // force-remint from invalid fra product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint bf210e609e7f…: four-occurrence sparse post-recycle twin of
        // d86f81358e32… / a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… /
        // 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru f106e39e815f… cid 52 → 91 /
        // gru 88ff8c404d3b… cid 51 → 90 / gru 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da…
        // cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 →
        // 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru
        // 5990e53d2fde… cid 44 → 83 / sfo e583d837318a… dual cid 49+50 → 88+89 / sfo
        // 02525de8dfa3… cid 47 → 86 → 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo
        // b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the adjacent
        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
        // 18:46:15Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z /
        // 18:47:14Z / 18:47:15Z / 18:48:10Z / 18:48:15Z / 18:49:10Z / 18:50:09Z /
        // 18:50:15Z steps) with cid 51 → 90 → 47 → 40 at 18:46:15Z on 127.0.0.1:47532,
        // 18:47:15Z on 127.0.0.1:48208, 18:48:15Z on 127.0.0.1:42916, and 18:50:15Z on
        // 127.0.0.1:56668 against the same 7ef9d0a4… leaf — still requires force-remint
        // from invalid fra product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint d86f81358e32…: four-occurrence dual-cid post-recycle twin of
        // a87539b37de1… / a66e03d58e6a… / aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… /
        // 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
        // dacc95d0e7ba… / 1e8b88f75d43… (and gru 897b9ff7b37e… cid 50 → 89 / gru
        // 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru
        // 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo 02525de8dfa3… cid 47 → 86 →
        // 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:46:12Z / 18:46:13Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:48:10Z /
        // 18:49:10Z / 18:50:09Z steps) with cid 49 → 50 → 88 → 89 at 18:46:13Z on
        // 127.0.0.1:38852 / 127.0.0.1:38860 (dual cid 49+50) and 18:47:13Z on
        // 127.0.0.1:40222 / 127.0.0.1:40240 (dual cid 88+89) against the same 7ef9d0a4… leaf —
        // still requires force-remint from invalid fra product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint a87539b37de1…: two-occurrence post-recycle twin of a66e03d58e6a… /
        // aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
        // 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
        // gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / gru 6be7ec00050d… cid 48 → 87 / gru
        // 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo 02525de8dfa3… cid 47 → 86 →
        // 39 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:47:11Z / 18:50:09Z steps) with cid 48 → 87 at 18:46:11Z on
        // 127.0.0.1:38842 and 18:47:11Z on 127.0.0.1:40216 against the same 7ef9d0a4… leaf —
        // still requires force-remint from invalid fra product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint a66e03d58e6a…: three-occurrence sparse post-recycle twin of
        // aae9c8a6b484… / b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… /
        // 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
        // gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508…
        // cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 →
        // 83 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / sfo
        // c907c56a7c0c… cid 43 → 82 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:50:09Z steps) with
        // cid 47 → 86 → 39 at 18:46:09Z on 127.0.0.1:38828, 18:47:09Z on 127.0.0.1:40210, and
        // 18:50:09Z on 127.0.0.1:48084 against the same 7ef9d0a4… leaf — still requires
        // force-remint from invalid fra product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint aae9c8a6b484…: four-occurrence dual-cid post-recycle twin of
        // b8e719ba13ca… / 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… /
        // 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru e962f4a49508…
        // cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 →
        // 83 / sfo b439248687d8… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the
        // adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z /
        // 18:46:07Z / 18:47:02Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) with cid 45 → 46 →
        // 84 → 85 at 18:46:07Z on 127.0.0.1:38812 / 127.0.0.1:38824 (dual cid 45+46) and
        // 18:47:07Z on 127.0.0.1:40184 / 127.0.0.1:40196 (dual cid 84+85) against the same
        // 7ef9d0a4… leaf — still requires force-remint from invalid fra product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint b8e719ba13ca…: single-occurrence post-recycle twin of
        // 67d134aeab25… / 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… /
        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 3f4dc73e62f2… cid 45 → 84 →
        // 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / sfo c907c56a7c0c… cid 43 → 82 → 38 at the
        // adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z steps) with
        // cid:44 at 18:46:05Z on 127.0.0.1:38810 against the same 7ef9d0a4… leaf — still
        // requires force-remint from invalid fra product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint 67d134aeab25…: two-occurrence sparse post-recycle twin of
        // 669e26dad203… / eebfa17cec6b… / 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… /
        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
        // dacc95d0e7ba… / 1e8b88f75d43… (and gru 6d84bda1e560… cid 43 → 82 / gru
        // 764b28c3439a… cid 42 → 81 / sfo eacb3282ca0c… dual cid 41+42 → 80+81 at the
        // adjacent wall-clock 18:46:01Z / 18:47:01Z steps) with cid 43 → 38 at 18:46:03Z on
        // 127.0.0.1:51072 and 18:50:03Z on 127.0.0.1:52810 against the same 7ef9d0a4… leaf —
        // still requires force-remint from invalid fra product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint 669e26dad203…: two-occurrence post-recycle twin of eebfa17cec6b… /
        // 639501fa4228… / 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… /
        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
        // gru 6d84bda1e560… cid 43 → 82 / gru 764b28c3439a… cid 42 → 81 / sfo eacb3282ca0c…
        // dual cid 41+42 → 80+81 at the same wall-clock 18:46:01Z / 18:47:01Z steps) with
        // cid 42 → 81 at 18:46:01Z on 127.0.0.1:51068 and 18:47:01Z on 127.0.0.1:38828 against
        // the same 7ef9d0a4… leaf — still requires force-remint from invalid fra product-
        // plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint eebfa17cec6b…: two-occurrence post-recycle twin of 639501fa4228… /
        // 5d30a28d7f44… / 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… /
        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru
        // 764b28c3439a… / gru a2e01c16a27c… / sfo 9b960cc93f83… / gru operator-read
        // b252d8996050… / gru-controller a9bf884a363b… / 25b92b919c66… / sfo operator-read
        // 97d33257778a… / fra operator-read c74671d2c0e4… at the same wall-clock 18:46:00Z /
        // 18:47:00Z steps) with cid 41 → 80 at 18:46:00Z on 127.0.0.1:51046 and 18:47:00Z on
        // 127.0.0.1:38810 against the same 7ef9d0a4… leaf — still requires force-remint from
        // invalid fra product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 639501fa4228…: three-occurrence post-recycle twin of 5d30a28d7f44… /
        // 5804cb3aaf61… / 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… /
        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru a2e01c16a27c… / sfo
        // 9b960cc93f83… / gru operator-read b252d8996050… / gru-controller a9bf884a363b… /
        // sfo operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent
        // wall-clock :56/:57/:58 steps) with cid 40 → 79 → 54 at 18:45:58Z on
        // 127.0.0.1:51030, 18:46:58Z on 127.0.0.1:38798, and 18:48:58Z on 127.0.0.1:38302
        // against the same 7ef9d0a4… leaf — still requires force-remint from invalid fra
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 5d30a28d7f44…: four-occurrence post-recycle twin of 5804cb3aaf61… /
        // 7904dd055f87… / 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… /
        // dacc95d0e7ba… / 1e8b88f75d43… (and gru be7bee33b946… / sfo 26b95f54769c… / gru
        // operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
        // 97d33257778a… / fra operator-read c74671d2c0e4… / fra-controller 5e5b835252fe… at
        // the same wall-clock :56 steps) with cid 38 → 39 → 78 → 37 at 18:45:56Z on
        // 127.0.0.1:51008 / 127.0.0.1:51016 (dual cid 38+39), 18:46:56Z on 127.0.0.1:38782,
        // and 18:49:56Z on 127.0.0.1:52794 against the same 7ef9d0a4… leaf — still requires
        // force-remint from invalid fra product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 5804cb3aaf61…: two-occurrence post-recycle twin of 7904dd055f87… /
        // 92ed0baffd5b… / fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… /
        // 1e8b88f75d43… (and gru 9371738eec92… / b22018f7aa7b… / sfo e33d87402e17… /
        // operator-read twins at adjacent wall-clock :52/:53/:54 steps) with cid 37 → 76 at
        // 18:45:54Z on 127.0.0.1:50978 and 18:46:54Z on 127.0.0.1:38754 against the same
        // 7ef9d0a4… leaf — still requires force-remint from invalid fra product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 7904dd055f87…: four-occurrence post-recycle twin of 92ed0baffd5b… /
        // fc4e0317d2a1… / 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and
        // gru b22018f7aa7b… at the same wall-clock :52 steps) with cid 36 → 75 → 53 → 46 at
        // 18:45:52Z on 127.0.0.1:34510, 18:46:52Z on 127.0.0.1:45778, 18:48:52Z on
        // 127.0.0.1:44268, and 18:50:52Z on 127.0.0.1:58444 against the same 7ef9d0a4… leaf —
        // still requires force-remint from invalid fra product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint 92ed0baffd5b…: four-occurrence post-recycle twin of fc4e0317d2a1… /
        // 30e9c320e15b… / 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru ed3f4504d5e1… /
        // sfo 146c64f3fc52… / operator-read twins f4f92376efda… / 62860f83eeb6… / 7421834a4183…
        // at the same wall-clock pair) with cid 34 → 35 → 74 → 36 at 18:45:50Z on
        // 127.0.0.1:34504 / 34506 (dual), 18:46:50Z on 127.0.0.1:45768, and 18:49:50Z on
        // 127.0.0.1:59726 against the same 7ef9d0a4… leaf — still requires force-remint from
        // invalid fra product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint fc4e0317d2a1…: two-occurrence post-recycle twin of 30e9c320e15b… /
        // 25ef0004168c… / dacc95d0e7ba… / 1e8b88f75d43… (and gru 6a1c43a93378…) with cid 33 →
        // 72 at 18:45:48Z on 127.0.0.1:34476 and 18:46:48Z on 127.0.0.1:45738 against the same
        // 7ef9d0a4… leaf — still requires force-remint from invalid fra product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 30e9c320e15b…: six-occurrence post-recycle twin of 25ef0004168c… /
        // dacc95d0e7ba… / 1e8b88f75d43… (and gru 0cbc78bc3a3a…) with cid 32 → 71 → 41 → 42 →
        // 52 → 45 at 18:45:46Z on 127.0.0.1:34468, 18:46:46Z on 127.0.0.1:45732, 18:47:46Z on
        // 127.0.0.1:49922 / 49934 (dual cid 41+42), 18:48:46Z on 127.0.0.1:44248, and
        // 18:50:46Z on 127.0.0.1:58440 against the same 7ef9d0a4… leaf — still requires
        // force-remint from invalid fra product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 1e8b88f75d43…: single post-recycle reconnect twin of 25ef0004168c… /
        // dacc95d0e7ba… (and gru 0b23b4fb5a75… / sfo d739f8d83bed…) with cid:31 at 18:45:45Z on
        // 127.0.0.1:34466 against the same 7ef9d0a4… leaf — still requires force-remint from
        // invalid fra product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint dacc95d0e7ba…: denser five-occurrence twin of 25ef0004168c… with
        // cid 14635 → 67 → 38 → 51 → 44 at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z /
        // 18:50:40Z against the same 7ef9d0a4… leaf — still requires force-remint from
        // invalid fra product-plane leaves before bare product-NATS RestartAsync.
        // Fingerprint 25ef0004168c…: fra-platform presents the product leaf. When only that
        // PEM is past NotAfter, ResourceHasInvalidTlsLeaf must be true for both fra-platform
        // and fra-product-nats-1 so force-remint runs instead of bare product-NATS RestartAsync
        // (cid 14634 → 63 → 50 → 43 at 18:45:34Z / 18:46:34Z / 18:48:34Z / 18:50:34Z).
        // Platform HTTP /health/ready can stay green; product-plane recovery must not rely on
        // that path alone.
        await AssertInvalidPlatformLeafForcesRemintForCellAsync("fra");
    }

    [Test]
    public async Task InvalidPlatformLeafIsDetectedForGruProductNatsBeforeBareRestart()
    {
        // Also fingerprint d0feba5039c6…: single post-recycle twin of f106e39e815f… /
        // 88ff8c404d3b… / 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… /
        // e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
        // 54fea6c92b78… / 57ae70882ed5… (and sfo e583d837318a… dual cid 49+50 → 88+89 / fra
        // d86f81358e32… dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid 45+46 → 84+85 /
        // fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 /
        // fra a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra
        // b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25…
        // cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:17Z /
        // 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z /
        // 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z /
        // 18:48:10Z / 18:49:10Z steps) with cid:53 at 18:46:17Z on 127.0.0.1:38752 against
        // the same 6b500765… leaf — still requires force-remint from invalid gru
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint f106e39e815f…: two-occurrence post-recycle twin of 88ff8c404d3b… /
        // 897b9ff7b37e… / 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… /
        // 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
        // 57ae70882ed5… (and sfo e583d837318a… dual cid 49+50 → 88+89 / fra d86f81358e32…
        // dual cid 49+50 → 88+89 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
        // aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra
        // a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra
        // b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25…
        // cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z /
        // 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:48:10Z /
        // 18:49:10Z steps) with cid 52 → 91 at 18:46:14Z on 127.0.0.1:38738 and 18:47:14Z
        // on 127.0.0.1:47750 against the same 6b500765… leaf — still requires force-remint
        // from invalid gru product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 88ff8c404d3b…: two-occurrence post-recycle twin of 897b9ff7b37e… /
        // 8a0aaf8cb1da… / 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… /
        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
        // sfo e583d837318a… dual cid 49+50 → 88+89 / fra d86f81358e32… dual cid 49+50 →
        // 88+89 / sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid
        // 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 →
        // 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo
        // c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra
        // a87539b37de1… cid 48 → 87 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z /
        // 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
        // 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z /
        // 18:47:12Z / 18:47:13Z / 18:48:10Z / 18:49:10Z steps) with cid 51 → 90 at
        // 18:46:13Z on 127.0.0.1:44104 and 18:47:13Z on 127.0.0.1:48274 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 897b9ff7b37e…: two-occurrence post-recycle twin of 8a0aaf8cb1da… /
        // 6be7ec00050d… / 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… /
        // 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493…
        // dual cid 45+46 → 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo
        // 02525de8dfa3… cid 47 → 86 → 39 / fra a66e03d58e6a… cid 47 → 86 → 39 / sfo
        // b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
        // 82 → 38 / fra 67d134aeab25… cid 43 → 38 / fra a87539b37de1… cid 48 → 87 at the
        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:48:10Z / 18:49:10Z steps) with cid 50 → 89
        // at 18:46:12Z on 127.0.0.1:44082 and 18:47:12Z on 127.0.0.1:48252 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 8a0aaf8cb1da…: four-occurrence post-recycle twin of 6be7ec00050d… /
        // 0401b56675fd… / e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… /
        // 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 →
        // 84+85 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / sfo 02525de8dfa3… cid 47 → 86 →
        // 39 / fra a66e03d58e6a… cid 47 → 86 → 39 / sfo b439248687d8… cid 44 → 83 / fra
        // b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25…
        // cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z /
        // 18:47:10Z / 18:48:10Z / 18:49:10Z steps) with cid 49 → 88 → 45 → 55 at 18:46:10Z
        // on 127.0.0.1:44074, 18:47:10Z on 127.0.0.1:48238, 18:48:10Z on 127.0.0.1:52880,
        // and 18:49:10Z on 127.0.0.1:48166 against the same 6b500765… leaf — still requires
        // force-remint from invalid gru product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 6be7ec00050d…: two-occurrence post-recycle twin of 0401b56675fd… /
        // e962f4a49508… / 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… /
        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
        // 54fea6c92b78… / 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra
        // aae9c8a6b484… dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / fra
        // b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25…
        // cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z /
        // 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
        // 18:47:07Z / 18:47:08Z steps) with cid 48 → 87 at 18:46:08Z on 127.0.0.1:44070 and
        // 18:47:08Z on 127.0.0.1:48226 against the same 6b500765… leaf — still requires
        // force-remint from invalid gru product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 0401b56675fd…: two-occurrence post-recycle twin of e962f4a49508… /
        // 3f4dc73e62f2… / 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… /
        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
        // 57ae70882ed5… (and sfo ef71b6e32493… dual cid 45+46 → 84+85 / fra aae9c8a6b484…
        // dual cid 45+46 → 84+85 / sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 /
        // sfo c907c56a7c0c… cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent
        // wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:47:03Z /
        // 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z steps) with cid 47 → 86 at 18:46:07Z
        // on 127.0.0.1:44066 and 18:47:07Z on 127.0.0.1:48220 against the same 6b500765… leaf
        // — still requires force-remint from invalid gru product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint e962f4a49508…: two-occurrence post-recycle twin of 3f4dc73e62f2… /
        // 5990e53d2fde… / 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… /
        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
        // sfo b439248687d8… cid 44 → 83 / fra b8e719ba13ca… cid:44 / sfo c907c56a7c0c… cid 43 →
        // 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z /
        // 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z
        // steps) with cid 46 → 85 at 18:46:06Z on 127.0.0.1:44054 and 18:47:06Z on
        // 127.0.0.1:48204 against the same 6b500765… leaf — still requires force-remint from
        // invalid gru product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 3f4dc73e62f2…: four-occurrence post-recycle twin of 5990e53d2fde… /
        // 6d84bda1e560… / 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… /
        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo c907c56a7c0c…
        // cid 43 → 82 → 38 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
        // 18:46:03Z / 18:47:03Z / 18:50:03Z steps) with cid 45 → 84 → 44 → 54 at 18:46:04Z on
        // 127.0.0.1:44042, 18:47:04Z on 127.0.0.1:48200, 18:48:04Z on 127.0.0.1:42712, and
        // 18:49:04Z on 127.0.0.1:48152 against the same 6b500765… leaf — still requires
        // force-remint from invalid gru product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 5990e53d2fde…: two-occurrence post-recycle twin of 6d84bda1e560… /
        // 764b28c3439a… / a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… /
        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 →
        // 80+81 / fra eebfa17cec6b… cid 41 → 80 / fra 669e26dad203… cid 42 → 81 at the adjacent
        // wall-clock 18:46:01Z / 18:47:01Z steps) with cid 44 → 83 at 18:46:02Z on
        // 127.0.0.1:35234 and 18:47:02Z on 127.0.0.1:53260 against the same 6b500765… leaf —
        // still requires force-remint from invalid gru product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint 6d84bda1e560…: two-occurrence post-recycle twin of 764b28c3439a… /
        // a2e01c16a27c… / be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… /
        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
        // 54fea6c92b78… / 57ae70882ed5… (and sfo eacb3282ca0c… dual cid 41+42 → 80+81 / fra
        // eebfa17cec6b… cid 41 → 80 at the same wall-clock 18:46:01Z / 18:47:01Z steps) with
        // cid 43 → 82 at 18:46:01Z on 127.0.0.1:35228 and 18:47:01Z on 127.0.0.1:53246 against
        // the same 6b500765… leaf — still requires force-remint from invalid gru product-
        // plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 764b28c3439a…: two-occurrence post-recycle twin of a2e01c16a27c… /
        // be7bee33b946… / 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… /
        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
        // 57ae70882ed5… (and gru controller 25b92b919c66… at the same wall-clock 18:46:00Z /
        // 18:47:00Z steps) with cid 42 → 81 at 18:46:00Z on 127.0.0.1:35222 and 18:47:00Z on
        // 127.0.0.1:53234 against the same 6b500765… leaf — still requires force-remint from
        // invalid gru product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint a2e01c16a27c…: three-occurrence post-recycle twin of be7bee33b946… /
        // 02a670a12fe6… / 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… /
        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
        // sfo 9b960cc93f83… / fra 5d30a28d7f44… / gru operator-read b252d8996050… /
        // gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… / fra operator-read
        // c74671d2c0e4… at adjacent wall-clock :56/:57/:58 steps) with cid 41 → 80 → 53 at
        // 18:45:58Z on 127.0.0.1:35206, 18:46:58Z on 127.0.0.1:53226, and 18:48:58Z on
        // 127.0.0.1:54632 against the same 6b500765… leaf — still requires force-remint from
        // invalid gru product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint be7bee33b946…: four-occurrence post-recycle twin of 02a670a12fe6… /
        // 9371738eec92… / b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… /
        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and gru operator-read
        // b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read 97d33257778a… /
        // fra operator-read c74671d2c0e4… at the same wall-clock :56 steps) with cid 39 → 40 →
        // 79 → 37 at 18:45:56Z on 127.0.0.1:35188 / 127.0.0.1:35204 (dual cid 39+40),
        // 18:46:56Z on 127.0.0.1:53210, and 18:49:56Z on 127.0.0.1:49142 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 02a670a12fe6…: single post-recycle twin of 9371738eec92… /
        // b22018f7aa7b… / ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… /
        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… with cid:78 at 18:46:55Z on
        // 127.0.0.1:53194 against the same 6b500765… leaf — still requires force-remint from
        // invalid gru product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 9371738eec92…: two-occurrence post-recycle twin of b22018f7aa7b… /
        // ed3f4504d5e1… / 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… /
        // 54fea6c92b78… / 57ae70882ed5… (and sfo e33d87402e17… / fra 7904dd055f87… /
        // operator-read twins at adjacent wall-clock :52/:53/:54 steps) with cid 38 → 77 at
        // 18:45:54Z on 127.0.0.1:48886 and 18:46:54Z on 127.0.0.1:60264 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint b22018f7aa7b…: four-occurrence post-recycle twin of ed3f4504d5e1… /
        // 6a1c43a93378… / 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… /
        // 57ae70882ed5… (and sfo eaa27086a65c… / fra 92ed0baffd5b… / operator-read twins at
        // adjacent wall-clock :50/:51/:52 steps) with cid 37 → 76 → 52 → 46 at 18:45:52Z on
        // 127.0.0.1:48880, 18:46:52Z on 127.0.0.1:60260, 18:48:52Z on 127.0.0.1:39364, and
        // 18:50:52Z on 127.0.0.1:48432 against the same 6b500765… leaf — still requires
        // force-remint from invalid gru product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint ed3f4504d5e1…: four-occurrence post-recycle twin of 6a1c43a93378… /
        // 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… (and
        // sfo 146c64f3fc52… / operator-read twins f4f92376efda… / 62860f83eeb6… at the same
        // wall-clock pair) with cid 35 → 36 → 75 → 36 at 18:45:50Z on 127.0.0.1:48870 /
        // 48878 (dual), 18:46:50Z on 127.0.0.1:60244, and 18:49:50Z on 127.0.0.1:41546
        // against the same 6b500765… leaf — still requires force-remint from invalid gru
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 6a1c43a93378…: two-occurrence post-recycle twin of 0cbc78bc3a3a… /
        // 1364f1b0cdbc… / 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… with cid 34 → 73 at
        // 18:45:48Z on 127.0.0.1:48846 and 18:46:48Z on 127.0.0.1:60214 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 0cbc78bc3a3a…: five-occurrence post-recycle twin of 1364f1b0cdbc… /
        // 0b23b4fb5a75… / 54fea6c92b78… / 57ae70882ed5… with cid 33 → 72 → 41 → 51 → 45 at
        // 18:45:46Z on 127.0.0.1:48834, 18:46:46Z on 127.0.0.1:60204, 18:47:46Z on
        // 127.0.0.1:56364, 18:48:46Z on 127.0.0.1:39346, and 18:50:46Z on 127.0.0.1:48414
        // against the same 6b500765… leaf — still requires force-remint from invalid gru
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 1364f1b0cdbc…: four-occurrence post-recycle twin of 0b23b4fb5a75…
        // with cid 32 → 70 → 71 → 40 at 18:45:43Z on 127.0.0.1:39470, 18:46:43Z on
        // 127.0.0.1:47014 / 47034 (dual), and 18:47:43Z on 127.0.0.1:38360 against the same
        // 6b500765… leaf — still requires force-remint from invalid gru product-plane leaves
        // before bare product-NATS RestartAsync.
        // Fingerprints 57ae70882ed5…, 54fea6c92b78…, and 0b23b4fb5a75…: gru-platform presents
        // the product leaf. Same NotAfter window and bare product-NATS recycle storm as the
        // fra twin (cid 14634 at 18:45:34Z; denser twin cid 14635 → 38 → 50 → 44 at 18:45:40Z /
        // 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 6b500765… leaf; single
        // post-recycle reconnect cid:31 at 18:45:42Z on 127.0.0.1:39462 for 0b23b4fb5a75…).
        // When only that PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true
        // for both gru-platform and gru-product-nats-1 so force-remint runs instead of bare
        // product-NATS RestartAsync. Platform HTTP /health/ready can stay green;
        // product-plane recovery must not rely on that path alone.
        await AssertInvalidPlatformLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidPlatformLeafIsDetectedForSfoProductNatsBeforeBareRestart()
    {
        // Also fingerprint e7adbe3390eb…: two-occurrence post-recycle twin of
        // e7810573222a… / e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… /
        // b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… /
        // 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
        // fra ec156a1db321… cid 52 → 91 / gru d0feba5039c6… cid:53 / fra bf210e609e7f… cid
        // 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 → 91 / gru 88ff8c404d3b… cid 51 → 90 /
        // fra d86f81358e32… cid 49 → 50 → 88 → 89 / gru 897b9ff7b37e… cid 50 → 89 / gru
        // 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a87539b37de1… cid 48 → 87 / fra
        // a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd…
        // cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 →
        // 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra
        // b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock
        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z /
        // 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:46:12Z / 18:46:13Z / 18:46:14Z /
        // 18:46:15Z / 18:46:17Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z /
        // 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z /
        // 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:47:17Z / 18:48:10Z / 18:48:15Z /
        // 18:49:10Z / 18:50:09Z / 18:50:15Z steps) with cid 52 → 91 at 18:46:17Z on
        // 127.0.0.1:59852 and 18:47:17Z on 127.0.0.1:55584 against the same a914ebca… leaf —
        // still requires force-remint from invalid sfo product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint e7810573222a…: four-occurrence sparse post-recycle twin of
        // e583d837318a… / 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… / b439248687d8… /
        // c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… /
        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra
        // bf210e609e7f… cid 51 → 90 → 47 → 40 / gru f106e39e815f… cid 52 → 91 / gru
        // 88ff8c404d3b… cid 51 → 90 / fra d86f81358e32… cid 49 → 50 → 88 → 89 / gru
        // 897b9ff7b37e… cid 50 → 89 / gru 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra
        // a87539b37de1… cid 48 → 87 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d…
        // cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru
        // 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra
        // aae9c8a6b484… dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:46:12Z / 18:46:13Z / 18:46:14Z / 18:46:15Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z /
        // 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:47:14Z / 18:47:15Z / 18:48:10Z /
        // 18:48:15Z / 18:49:10Z / 18:50:09Z / 18:50:15Z steps) with cid 51 → 90 → 46 → 40 at
        // 18:46:15Z on 127.0.0.1:59838, 18:47:15Z on 127.0.0.1:55568, 18:48:15Z on
        // 127.0.0.1:35124, and 18:50:15Z on 127.0.0.1:42264 against the same a914ebca… leaf —
        // still requires force-remint from invalid sfo product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint e583d837318a…: four-occurrence dual-cid post-recycle twin of
        // 67300e8b3fe0… / 02525de8dfa3… / ef71b6e32493… / b439248687d8… / c907c56a7c0c… /
        // eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and fra d86f81358e32… cid 49 → 50 →
        // 88 → 89 / fra a87539b37de1… cid 48 → 87 / gru 897b9ff7b37e… cid 50 → 89 / gru
        // 8a0aaf8cb1da… cid 49 → 88 → 45 → 55 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru
        // 6be7ec00050d… cid 48 → 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid
        // 46 → 85 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 /
        // fra aae9c8a6b484… dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z /
        // 18:46:12Z / 18:46:13Z / 18:47:03Z / 18:47:04Z / 18:47:05Z / 18:47:06Z / 18:47:07Z /
        // 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:47:12Z / 18:47:13Z / 18:50:09Z
        // steps) with cid 49 → 50 → 88 → 89 at 18:46:13Z on 127.0.0.1:36302 /
        // 127.0.0.1:36324 (dual cid 49+50) and 18:47:13Z on 127.0.0.1:46602 /
        // 127.0.0.1:46614 (dual cid 88+89) against the same a914ebca… leaf — still requires
        // force-remint from invalid sfo product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint 67300e8b3fe0…: two-occurrence post-recycle twin of 02525de8dfa3… /
        // ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
        // 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
        // 77220dace263… (and fra a87539b37de1… cid 48 → 87 / gru 8a0aaf8cb1da… cid 49 → 88 →
        // 45 → 55 / fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 → 87 / gru
        // 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru 3f4dc73e62f2… cid
        // 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra aae9c8a6b484… dual cid
        // 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra 67d134aeab25… cid 43 → 38 at the
        // adjacent wall-clock 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:46:06Z / 18:46:07Z /
        // 18:46:08Z / 18:46:09Z / 18:46:10Z / 18:46:11Z / 18:47:03Z / 18:47:04Z / 18:47:05Z /
        // 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:47:10Z / 18:47:11Z / 18:50:09Z
        // steps) with cid 48 → 87 at 18:46:11Z on 127.0.0.1:36290 and 18:47:11Z on
        // 127.0.0.1:46596 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 02525de8dfa3…: three-occurrence sparse post-recycle twin of
        // ef71b6e32493… / b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… /
        // 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… /
        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
        // 77220dace263… (and fra a66e03d58e6a… cid 47 → 86 → 39 / gru 6be7ec00050d… cid 48 →
        // 87 / gru 0401b56675fd… cid 47 → 86 / gru e962f4a49508… cid 46 → 85 / gru
        // 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra
        // aae9c8a6b484… dual cid 45+46 → 84+85 / fra b8e719ba13ca… cid:44 / fra
        // 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:03Z / 18:46:04Z /
        // 18:46:05Z / 18:46:06Z / 18:46:07Z / 18:46:08Z / 18:46:09Z / 18:47:03Z / 18:47:04Z /
        // 18:47:05Z / 18:47:06Z / 18:47:07Z / 18:47:08Z / 18:47:09Z / 18:50:09Z steps) with
        // cid 47 → 86 → 39 at 18:46:09Z on 127.0.0.1:36278, 18:47:09Z on 127.0.0.1:46582, and
        // 18:50:09Z on 127.0.0.1:45784 against the same a914ebca… leaf — still requires
        // force-remint from invalid sfo product-plane leaves before bare product-NATS
        // RestartAsync.
        // Also fingerprint ef71b6e32493…: four-occurrence dual-cid post-recycle twin of
        // b439248687d8… / c907c56a7c0c… / eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… /
        // 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
        // fra aae9c8a6b484… cid 45 → 46 → 84 → 85 / gru e962f4a49508… cid 46 → 85 / gru
        // 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 5990e53d2fde… cid 44 → 83 / fra
        // b8e719ba13ca… cid:44 / gru 6d84bda1e560… cid 43 → 82 / fra 67d134aeab25… cid 43 →
        // 38 at the adjacent wall-clock 18:46:02Z / 18:46:03Z / 18:46:04Z / 18:46:05Z /
        // 18:46:06Z / 18:46:07Z / 18:47:02Z / 18:47:03Z / 18:47:05Z / 18:47:06Z / 18:47:07Z
        // steps) with cid 45 → 46 → 84 → 85 at 18:46:07Z on 127.0.0.1:36252 / 127.0.0.1:36270
        // (dual cid 45+46) and 18:47:07Z on 127.0.0.1:46566 / 127.0.0.1:46574 (dual cid 84+85)
        // against the same a914ebca… leaf — still requires force-remint from invalid sfo
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint b439248687d8…: two-occurrence post-recycle twin of c907c56a7c0c… /
        // eacb3282ca0c… / bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… /
        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru 5990e53d2fde… cid 44 → 83 /
        // fra b8e719ba13ca… cid:44 / gru 3f4dc73e62f2… cid 45 → 84 → 44 → 54 / gru 6d84bda1e560…
        // cid 43 → 82 / fra 67d134aeab25… cid 43 → 38 at the adjacent wall-clock 18:46:02Z /
        // 18:46:03Z / 18:46:04Z / 18:46:05Z / 18:47:02Z / 18:47:03Z / 18:47:05Z steps) with
        // cid 44 → 83 at 18:46:05Z on 127.0.0.1:36238 and 18:47:05Z on 127.0.0.1:46560 against
        // the same a914ebca… leaf — still requires force-remint from invalid sfo product-plane
        // leaves before bare product-NATS RestartAsync.
        // Also fingerprint c907c56a7c0c…: three-occurrence post-recycle twin of eacb3282ca0c… /
        // bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
        // b1723b879b59… / 77220dace263… (and fra 67d134aeab25… cid 43 → 38 / gru 6d84bda1e560…
        // cid 43 → 82 / gru 5990e53d2fde… cid 44 → 83 / gru 764b28c3439a… cid 42 → 81 / fra
        // 669e26dad203… cid 42 → 81 at the adjacent wall-clock 18:46:01Z / 18:46:02Z /
        // 18:46:03Z / 18:47:01Z / 18:47:02Z / 18:47:03Z / 18:50:03Z steps) with cid 43 → 82 →
        // 38 at 18:46:03Z on 127.0.0.1:45990, 18:47:03Z on 127.0.0.1:39600, and 18:50:03Z on
        // 127.0.0.1:41872 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint eacb3282ca0c…: four-occurrence dual-reconnect post-recycle twin of
        // bf521ed338de… / 9b960cc93f83… / 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… /
        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
        // b1723b879b59… / 77220dace263… (and fra eebfa17cec6b… cid 41 → 80 / gru 764b28c3439a…
        // cid 42 → 81 / gru a2e01c16a27c… / fra 639501fa4228… / gru be7bee33b946… / fra
        // 5d30a28d7f44… / gru operator-read b252d8996050… / gru-controller a9bf884a363b… /
        // 25b92b919c66… / sfo operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at
        // the same wall-clock 18:46:01Z / 18:47:01Z steps) with cid 41 → 42 → 80 → 81 at
        // 18:46:01Z on 127.0.0.1:45962 / 127.0.0.1:45986 and 18:47:01Z on 127.0.0.1:39584 /
        // 127.0.0.1:39598 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint bf521ed338de…: two-occurrence post-recycle twin of 9b960cc93f83… /
        // 26b95f54769c… / 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… /
        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
        // gru a2e01c16a27c… / fra 639501fa4228… / gru be7bee33b946… / fra 5d30a28d7f44… / gru
        // operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
        // 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent wall-clock :57/:58/:59
        // steps) with cid 40 → 79 at 18:45:59Z on 127.0.0.1:45954 and 18:46:59Z on
        // 127.0.0.1:39572 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 9b960cc93f83…: three-occurrence post-recycle twin of 26b95f54769c… /
        // 16f64e5cf6e5… / e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… /
        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru be7bee33b946…
        // / fra 5d30a28d7f44… / gru operator-read b252d8996050… / gru-controller a9bf884a363b…
        // / sfo operator-read 97d33257778a… / fra operator-read c74671d2c0e4… at adjacent
        // wall-clock :56/:57 steps) with cid 39 → 78 → 43 at 18:45:57Z on 127.0.0.1:45942,
        // 18:46:57Z on 127.0.0.1:39560, and 18:47:57Z on 127.0.0.1:52548 against the same
        // a914ebca… leaf — still requires force-remint from invalid sfo product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 26b95f54769c…: two-occurrence post-recycle twin of 16f64e5cf6e5… /
        // e33d87402e17… / eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… /
        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru be7bee33b946… / gru
        // operator-read b252d8996050… / gru-controller a9bf884a363b… / sfo operator-read
        // 97d33257778a… / fra operator-read c74671d2c0e4… at the same wall-clock :56 steps)
        // with cid 38 → 37 at 18:45:56Z on 127.0.0.1:45940 and 18:49:56Z on 127.0.0.1:41844
        // against the same a914ebca… leaf — still requires force-remint from invalid sfo
        // product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 16f64e5cf6e5…: three-occurrence post-recycle twin of e33d87402e17… /
        // eaa27086a65c… / 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… /
        // b1723b879b59… / 77220dace263… (and fra 5804cb3aaf61… / gru 9371738eec92… at adjacent
        // wall-clock :54/:55 steps) with cid 37 → 76 → 77 at 18:45:55Z on 127.0.0.1:45918 and
        // 18:46:55Z on 127.0.0.1:39530 / 127.0.0.1:39552 (dual cid 76+77) against the same
        // a914ebca… leaf — still requires force-remint from invalid sfo product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint e33d87402e17…: two-occurrence post-recycle twin of eaa27086a65c… /
        // 146c64f3fc52… / 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… /
        // 77220dace263… (and fra 7904dd055f87… / gru b22018f7aa7b… at adjacent wall-clock
        // :52/:53 steps) with cid 36 → 75 at 18:45:53Z on 127.0.0.1:39168 and 18:46:53Z on
        // 127.0.0.1:59854 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint eaa27086a65c…: three-occurrence post-recycle twin of 146c64f3fc52… /
        // 9f8f5f2cd955… / a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and
        // gru ed3f4504d5e1… / fra 92ed0baffd5b… / operator-read twins f4f92376efda… /
        // 62860f83eeb6… at adjacent wall-clock :50/:51 steps) with cid 35 → 74 → 42 at
        // 18:45:51Z on 127.0.0.1:39154, 18:46:51Z on 127.0.0.1:59850, and 18:47:51Z on
        // 127.0.0.1:47938 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint 146c64f3fc52…: two-occurrence post-recycle twin of 9f8f5f2cd955… /
        // a42bd88ac488… / d739f8d83bed… / b1723b879b59… / 77220dace263… (and operator-read
        // twins f4f92376efda… / 62860f83eeb6… at the same wall-clock pair) with cid 34 → 36
        // at 18:45:50Z on 127.0.0.1:39142 and 18:49:50Z on 127.0.0.1:57178 against the same
        // a914ebca… leaf — still requires force-remint from invalid sfo product-plane leaves
        // before bare product-NATS RestartAsync.
        // Also fingerprint 9f8f5f2cd955…: two-occurrence post-recycle twin of a42bd88ac488… /
        // d739f8d83bed… / b1723b879b59… / 77220dace263… (and gru 6a1c43a93378…, fra
        // fc4e0317d2a1…) with cid 33 → 72 at 18:45:48Z on 127.0.0.1:39126 and 18:46:48Z on
        // 127.0.0.1:59822 against the same a914ebca… leaf — still requires force-remint from
        // invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Also fingerprint a42bd88ac488…: five-occurrence post-recycle twin of d739f8d83bed… /
        // b1723b879b59… / 77220dace263… (and gru 0cbc78bc3a3a… / 1364f1b0cdbc… / 0b23b4fb5a75…,
        // fra 30e9c320e15b…) with cid 32 → 71 → 41 → 51 → 45 at 18:45:46Z on 127.0.0.1:39118,
        // 18:46:46Z on 127.0.0.1:59808, 18:47:46Z on 127.0.0.1:47908, 18:48:46Z on
        // 127.0.0.1:54714, and 18:50:46Z on 127.0.0.1:60650 against the same a914ebca… leaf —
        // still requires force-remint from invalid sfo product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint d739f8d83bed…: four-occurrence post-recycle twin of b1723b879b59… /
        // 77220dace263… (and gru 1364f1b0cdbc… / 0b23b4fb5a75…) with cid 31 → 70 → 40 → 35 at
        // 18:45:44Z on 127.0.0.1:39116, 18:46:44Z on 127.0.0.1:59792, 18:47:44Z on
        // 127.0.0.1:47888, and 18:49:44Z on 127.0.0.1:42228 against the same a914ebca… leaf —
        // still requires force-remint from invalid sfo product-plane leaves before bare
        // product-NATS RestartAsync.
        // Also fingerprint 77220dace263…: denser six-occurrence twin of b1723b879b59… with
        // cid 14635 → 67 → 37 → 38 → 50 → 44 at 18:45:40Z / 18:46:40Z / 18:47:40Z (dual) /
        // 18:48:40Z / 18:50:40Z against the same a914ebca… leaf — still requires force-remint
        // from invalid sfo product-plane leaves before bare product-NATS RestartAsync.
        // Fingerprint b1723b879b59…: sfo-platform presents the product leaf. Same NotAfter
        // (18:45:24Z) as the fra twin (25ef0004168c…), with cid recycle 14634 → 63 → 34 → 49 →
        // 43 at 18:45:34Z / 18:46:34Z / 18:47:34Z / 18:48:34Z / 18:50:34Z against the a914ebca…
        // leaf. When only that PEM is past NotAfter, ResourceHasInvalidTlsLeaf must be true for
        // both sfo-platform and sfo-product-nats-1 so force-remint runs instead of bare
        // product-NATS RestartAsync. Platform HTTP /health/ready can stay green; product-plane
        // recovery must not rely on that path alone.
        await AssertInvalidPlatformLeafForcesRemintForCellAsync("sfo");
    }

    private static async Task AssertInvalidPlatformLeafForcesRemintForCellAsync(string cell)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var platformName = $"{cell}-platform";
        var productNatsName = $"{cell}-product-nats-1";
        var otherCells = new[] { "gru", "sfo", "fra" }
            .Where(candidate => !string.Equals(candidate, cell, StringComparison.Ordinal))
            .ToArray();
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-{cell}-platform-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);

            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, productNatsName))
                .IsFalse();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, platformName))
                .IsFalse();
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, platformName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/workload/{platformName}");
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, productNatsName)!.SpiffeId)
                .IsEqualTo($"spiffe://terrascale.tech/cell/{cell}/workload/{platformName}");
            var reconnectLeaves = DevelopmentLab.EnumerateReconnectTlsIdentities(
                    topology, security, productNatsName)
                .Select(identity => identity.SpiffeId)
                .ToArray();
            await Assert.That(reconnectLeaves)
                .Contains($"spiffe://terrascale.tech/cell/{cell}/workload/{platformName}");

            var platformTls = security.Cell(cell).Tls.Product.Clients[platformName];
            using (var ecdsa = System.Security.Cryptography.ECDsa.Create(
                       System.Security.Cryptography.ECCurve.NamedCurves.nistP256))
            {
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    $"CN={platformName}",
                    ecdsa,
                    System.Security.Cryptography.HashAlgorithmName.SHA256);
                var notBefore = DateTimeOffset.UtcNow.AddDays(-2);
                var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
                using var expired = request.CreateSelfSigned(notBefore, notAfter);
                File.WriteAllText(platformTls.CertificateFile, expired.ExportCertificatePem());
            }

            // Platform resource and product NATS must both see the expired product client leaf.
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, platformName))
                .IsTrue();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, productNatsName))
                .IsTrue();
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
            var platformRefusal = DevelopmentHealthProbe.TryInvalidLeafProbeFailure(platformTls);
            await Assert.That(platformRefusal).IsNotNull();
            await Assert.That(platformRefusal!.Healthy).IsFalse();
            await Assert.That(platformRefusal.Detail).Contains("certificate has expired");
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(platformRefusal.Detail))
                .IsTrue();
            // Other cells' product NATS stay clean when only this cell's platform is expired.
            foreach (var other in otherCells)
            {
                await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                        topology, security, $"{other}-product-nats-1"))
                    .IsFalse();
            }

            File.Delete(platformTls.CertificateFile);
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, productNatsName))
                .IsTrue();
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
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
    public async Task PkiRemintStopsNatsBeforeClientsAndCoversAllCells()
    {
        // Remint must stop control/product NATS first (cut server-side expiry logs),
        // then every non-NATS mTLS client, before Create rewrites PEMs. Controllers
        // (control plane) and platforms (product plane) both present leaves; leaving
        // NATS up while either reconnects logs certificate-expired handshakes
        // (CN=*-controller-1 / CN=*-platform / CN=operator-read).
        var topology = DevelopmentTopology.CreateThreeCellLean();
        var nats = DevelopmentLab.NatsResourceNames(topology);
        var clients = DevelopmentLab.TlsClientResourceNames(topology);

        await Assert.That(nats).Contains("sfo-control-nats-1");
        await Assert.That(nats).Contains("sfo-product-nats-1");
        await Assert.That(nats).Contains("fra-control-nats-1");
        await Assert.That(nats).Contains("gru-control-nats-1");
        await Assert.That(nats).Contains("gru-product-nats-1");
        await Assert.That(nats).Contains("fra-product-nats-1");
        await Assert.That(nats.Any(name => name.Contains("controller", StringComparison.Ordinal)))
            .IsFalse();
        await Assert.That(nats.Any(name => name.Contains("platform", StringComparison.Ordinal)))
            .IsFalse();

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
        // Controllers and platforms are both first-class remint clients (cell order).
        var fraController = clients.ToList().IndexOf("fra-controller-1");
        var fraPlatform = clients.ToList().IndexOf("fra-platform");
        var gruPlatform = clients.ToList().IndexOf("gru-platform");
        var sfoController = clients.ToList().IndexOf("sfo-controller-1");
        await Assert.That(fraController).IsGreaterThanOrEqualTo(0);
        await Assert.That(fraPlatform).IsGreaterThanOrEqualTo(0);
        await Assert.That(gruPlatform).IsGreaterThanOrEqualTo(0);
        await Assert.That(sfoController).IsGreaterThanOrEqualTo(0);
        // NATS and client sets must be disjoint so StopMany cannot double-stop.
        await Assert.That(nats.Intersect(clients, StringComparer.Ordinal).Any()).IsFalse();
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
            await Assert.That(DevelopmentHealthProbe.TryInvalidLeafProbeFailure(operatorTls))
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
            var missingRefusal = DevelopmentHealthProbe.TryInvalidLeafProbeFailure(operatorTls);
            await Assert.That(missingRefusal).IsNotNull();
            await Assert.That(missingRefusal!.Healthy).IsFalse();
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(missingRefusal.Detail)).IsTrue();

            // An on-disk leaf that is already past NotAfter must annotate explicitly even when
            // the outer NATS exception text is generic — and pre-connect refusal must surface
            // the same recovery trigger without calling ConnectAsync (no CN=operator-read
            // server log from the probe itself).
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
            var expiredRefusal = DevelopmentHealthProbe.TryInvalidLeafProbeFailure(operatorTls);
            await Assert.That(expiredRefusal).IsNotNull();
            await Assert.That(expiredRefusal!.Healthy).IsFalse();
            await Assert.That(expiredRefusal.Detail).Contains("Health probe failed:");
            await Assert.That(expiredRefusal.Detail).Contains("certificate has expired");
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(expiredRefusal.Detail)).IsTrue();

            // Product-plane twin: an expired gru-platform leaf must refuse the same way so
            // platform health (not only product-NATS ConnectAsync) can force-remint and stop
            // CN=gru-platform handshake spam on gru-product-nats.
            var platformTls = security.Cell("gru").Tls.Product.Clients["gru-platform"];
            File.WriteAllText(platformTls.CertificateFile, File.ReadAllText(operatorTls.CertificateFile));
            var platformRefusal = DevelopmentHealthProbe.TryInvalidLeafProbeFailure(platformTls);
            await Assert.That(platformRefusal).IsNotNull();
            await Assert.That(platformRefusal!.Healthy).IsFalse();
            await Assert.That(platformRefusal.Detail).Contains("certificate has expired");
            await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(platformRefusal.Detail)).IsTrue();
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
