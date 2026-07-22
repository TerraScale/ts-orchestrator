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
        // Fingerprints e517701a2468…, f08d1c577176…, and 62860f83eeb6…: sfo-control-nats health
        // probes present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // gru twin (cid 29237 → 62 → 69 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin cid
        // 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same
        // aa00c1c3… leaf; two-occurrence post-recycle twin cid 30 → 46 at 18:45:50Z on
        // 127.0.0.1:50596 and 18:49:50Z on 127.0.0.1:34070 for 62860f83eeb6…). When only the sfo
        // operator-read PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true for
        // sfo-control-nats-1 so force-remint runs instead of bare RestartAsync.
        await AssertInvalidOperatorReadLeafForcesRemintForCellAsync("sfo");
    }

    [Test]
    public async Task InvalidOperatorReadLeafIsDetectedForGruControlNatsBeforeBareRestart()
    {
        // Fingerprints c6627a56bf45…, c48cbf142a9a…, and f4f92376efda…: gru-control-nats health
        // probes present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // sfo twin (cid 29237 → 62 → 69 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin cid
        // 29239 → 34 → 66 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same
        // 4e40db2b… leaf; two-occurrence post-recycle twin cid 31 → 46 at 18:45:50Z on
        // 127.0.0.1:56170 and 18:49:50Z on 127.0.0.1:45996 for f4f92376efda…). When only the gru
        // operator-read PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true for
        // gru-control-nats-1 so force-remint runs instead of bare RestartAsync.
        await AssertInvalidOperatorReadLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidOperatorReadLeafIsDetectedForFraControlNatsBeforeBareRestart()
    {
        // Fingerprints 9a811bb8b959…, f95adc65…, and 7421834a4183…: fra-control-nats health
        // probes present operator-read. Same NotAfter window and bare-NATS-recycle storm as the
        // gru/sfo twins (cid 29237 → 63 → 68 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin
        // cid 29239 → 33 → 65 → 72 at 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the
        // same 6477b788… leaf; two-occurrence post-recycle twin cid 30 → 46 at 18:45:50Z on
        // 127.0.0.1:34654 and 18:49:50Z on 127.0.0.1:33762 for 7421834a4183…). When only the
        // fra operator-read PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true
        // for fra-control-nats-1 so force-remint runs instead of bare RestartAsync.
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
        // Fingerprints f490b625…, 9815ef5a…, 4eeeee0520a1…, e8e55fe0bef9…, 412baaa56842…, and
        // 71cf8514f4d6…: sfo-controller-1 (not operator-read) presents the control leaf. When
        // only that PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true for
        // sfo-control-nats-1 so the consecutive-unhealthy path force-remints instead of bare
        // RestartAsync (cid recycle 29238 → 63 → 70 at 18:45:34Z / 18:48:34Z / 18:50:34Z;
        // denser twin cid 29240 → 34 → 35 → 66 → 73 at 18:45:40Z / 18:47:40Z / 18:47:40Z /
        // 18:48:40Z / 18:50:40Z against the same f56fe7a4… leaf, dual reconnect at 18:47:40Z;
        // two-occurrence post-recycle twin cid 28 → 36 at 18:45:45Z on 127.0.0.1:50552 and
        // 18:47:45Z on 127.0.0.1:37302 for 4eeeee0520a1…; second two-occurrence post-recycle
        // twin cid 29 → 61 at 18:45:47Z on 127.0.0.1:50560 and 18:46:47Z on 127.0.0.1:55476
        // for e8e55fe0bef9…; three-occurrence post-recycle twin cid 31 → 39 → 47 at 18:45:50Z
        // on 127.0.0.1:50606, 18:47:50Z on 127.0.0.1:37360, and 18:49:50Z on 127.0.0.1:34092
        // for 412baaa56842…; four-occurrence post-recycle twin cid 32 → 41 → 71 → 48 at
        // 18:45:51Z on 127.0.0.1:50616, 18:47:51Z on 127.0.0.1:37414, 18:48:51Z on
        // 127.0.0.1:58882, and 18:49:51Z on 127.0.0.1:34106 for 71cf8514f4d6…). Control-NATS
        // probes present only operator-read, so recovery must survey controller leaves on the
        // NATS resource independently of the probe leaf.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("sfo");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForGruControlNatsBeforeBareRestart()
    {
        // Fingerprints c2bf6b539a62…, 782d6308…, 003657d51ecd…, b9dc4dd1a8ef…, and
        // 7b6a047263d8…: gru-controller-1 (not operator-read) presents the control leaf. Same
        // NotAfter window and bare-NATS-recycle storm as the sfo twin (cid 29238 → 32 → 63 → 70
        // at 18:45:34Z / 18:47:34Z / 18:48:34Z / 18:50:34Z; denser twin cid 29240 → 58 → 35 →
        // 65 → 67 → 42 → 73 at 18:45:40Z / 18:46:40Z / 18:47:40Z / 18:48:40Z / 18:48:40Z /
        // 18:49:40Z / 18:50:40Z against the same d467c210… leaf; two-occurrence post-recycle
        // twin cid 28 → 60 at 18:45:43Z on 127.0.0.1:49796 and 18:46:43Z on 127.0.0.1:60312 for
        // 003657d51ecd…; four-occurrence post-recycle twin cid 29 → 61 → 68 → 45 at 18:45:45Z
        // on 127.0.0.1:56146, 18:46:45Z on 127.0.0.1:57182, 18:48:45Z on 127.0.0.1:55606, and
        // 18:49:45Z on 127.0.0.1:45982 for b9dc4dd1a8ef…; six-occurrence post-recycle twin cid
        // 30 → 32 → 64 → 71 → 47 → 48 at 18:45:50Z on 127.0.0.1:56154 / 127.0.0.1:56178 dual,
        // 18:46:50Z on 127.0.0.1:57224, 18:48:50Z on 127.0.0.1:55652, and 18:49:50Z on
        // 127.0.0.1:46006 / 127.0.0.1:46018 dual for 7b6a047263d8…). When only the
        // gru-controller-1 PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true
        // for gru-control-nats-1 so force-remint runs instead of bare RestartAsync. Probes alone
        // would miss this because control-NATS probes present operator-read.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForFraControlNatsBeforeBareRestart()
    {
        // Fingerprints 91b5b852…, ffcef075c58c…, bca21682b315…, 23eafce842f6…, and
        // 4046b92fa615…: fra-controller-1 (not operator-read) presents the control leaf. Same
        // NotAfter window and bare-NATS-recycle storm as the sfo/gru twins (cid 29238 → 62 →
        // 69 → 70 at 18:45:34Z / 18:48:34Z / 18:50:34Z; denser twin cid 29240 → 34 → 66 → 73 at
        // 18:45:40Z / 18:47:40Z / 18:48:40Z / 18:50:40Z against the same 8f6e801c… leaf; four-
        // occurrence post-recycle twin cid 28 → 37 → 69 → 76 at 18:45:46Z on 127.0.0.1:34624,
        // 18:47:46Z on 127.0.0.1:60304, 18:48:46Z on 127.0.0.1:50796, and 18:50:46Z on
        // 127.0.0.1:54352 for bca21682b315…; single post-recycle twin cid:29 at 18:45:48Z on
        // 127.0.0.1:34626 for 23eafce842f6…; two-occurrence post-recycle twin cid 31 → 47 at
        // 18:45:50Z on 127.0.0.1:34668 and 18:49:50Z on 127.0.0.1:33784 for 4046b92fa615…).
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
