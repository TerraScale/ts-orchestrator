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
        // Pre-connect leaf refusal must still feed force-remint (same recovery path as
        // post-connect FormatProbeFailure annotations).
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: certificate has expired: current time 2026-07-21T18:45:28.0000000Z " +
                "is after 2026-07-21T18:45:24.0000000Z"))
            .IsTrue();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: can not start to connect nats server: nats://127.0.0.1:19000"))
            .IsFalse();
        await Assert.That(DevelopmentLab.LooksLikeCertificateFailure(
                "Health probe failed: Connection refused"))
            .IsFalse();
    }

    [Test]
    public async Task InvalidOperatorReadLeafIsDetectedForSfoControlNatsBeforeBareRestart()
    {
        // Fingerprint e517701a2468…: sfo-control-nats health probes present operator-read.
        // When that leaf is already past NotAfter, ResourceHasInvalidTlsLeaf must be true
        // for sfo-control-nats-1 so the consecutive-unhealthy path force-remints instead of
        // bare RestartAsync (cid recycle 29237 → 62 → 69).
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-sfo-operator-leaf-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateThreeCellLean();
            var security = DevelopmentNatsSecurity.Create(topology, directory);

            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsFalse();
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, "sfo-control-nats-1"))
                .IsFalse();
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, "sfo-control-nats-1")!.SpiffeId)
                .IsEqualTo("spiffe://terrascale.tech/cell/sfo/operator/operator-read");
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, "sfo-platform")!.SpiffeId)
                .IsEqualTo("spiffe://terrascale.tech/cell/sfo/workload/sfo-platform");
            await Assert.That(DevelopmentLab.TryGetProbeTlsIdentity(
                    topology, security, "email-emulator"))
                .IsNull();

            var operatorTls = security.Cell("sfo").Tls.Control.Clients["operator-read"];
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
                    topology, security, "sfo-control-nats-1"))
                .IsTrue();
            // Other cells still have valid operator-read leaves; AnyProbe must still trip
            // because sfo's probe identity is invalid.
            await Assert.That(DevelopmentLab.AnyProbeTlsLeafInvalid(topology, security)).IsTrue();
            // A single deleted probe leaf must also force remint even when the NotAfter
            // survey of remaining siblings would still look healthy.
            File.Delete(operatorTls.CertificateFile);
            await Assert.That(DevelopmentLab.ResourceHasInvalidTlsLeaf(
                    topology, security, "sfo-control-nats-1"))
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
        // Fingerprint f490b625…: sfo-controller-1 (not operator-read) presents the control
        // leaf. When only that PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be
        // true for sfo-control-nats-1 so the consecutive-unhealthy path force-remints instead
        // of bare RestartAsync (cid recycle 29238 → 63 → 70). Health probes alone would miss
        // this because control-NATS probes present operator-read.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("sfo");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForGruControlNatsBeforeBareRestart()
    {
        // Fingerprint c2bf6b539a62…: gru-controller-1 (not operator-read) presents the control
        // leaf. Same NotAfter window and bare-NATS-recycle storm as the sfo twin (cid 29238 →
        // 32 → 63 → 70 at 18:45:34Z / 18:47:34Z / 18:48:34Z / 18:50:34Z). When only the
        // gru-controller-1 PEM is past NotAfter, ResourceHasInvalidTlsLeaf must still be true
        // for gru-control-nats-1 so force-remint runs instead of bare RestartAsync. Health
        // probes alone would miss this because control-NATS probes present operator-read.
        await AssertInvalidControllerLeafForcesRemintForCellAsync("gru");
    }

    [Test]
    public async Task InvalidControllerLeafIsDetectedForFraControlNatsBeforeBareRestart()
    {
        // fra twin of f490b625… / c2bf6b539a62…: controller-only expiry on fra-control-nats-1
        // must force remint cell-locally without relying on operator-read probe health.
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
