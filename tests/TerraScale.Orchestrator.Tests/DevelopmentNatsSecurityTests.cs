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
                .IsNotEqualTo(File.ReadAllText(gru.Tls.Product.Clients["gru-api"].CaFile));

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
                .IsEqualTo(gru.Tls.Product.Clients["gru-api"].CertificateFile);
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
