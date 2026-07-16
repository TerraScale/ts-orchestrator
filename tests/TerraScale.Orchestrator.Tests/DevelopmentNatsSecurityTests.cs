using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentNatsSecurityTests
{
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
            var topology = DevelopmentTopology.CreateThreeCellR3();
            var security = DevelopmentNatsSecurity.Create(topology, directory);
            var gru = security.Cell("gru");
            var sfo = security.Cell("sfo");

            await Assert.That(gru.Controllers.Count).IsEqualTo(3);
            await Assert.That(gru.Controllers.Values.Select(value => value.PublicKey).Distinct().Count())
                .IsEqualTo(3);
            await Assert.That(gru.Operator.PublicKey).IsNotEqualTo(gru.Controllers[1].PublicKey);
            await Assert.That(gru.Product.Password).IsNotEqualTo(sfo.Product.Password);

            foreach (var identity in gru.Controllers.Values.Append(gru.Operator))
            {
                await Assert.That(File.GetUnixFileMode(identity.SeedFile))
                    .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var authorization = NatsDevelopmentCluster.ControlAuthorization(
                topology.Cells.Single(cell => cell.Cell == "gru"),
                gru);
            await Assert.That(authorization).Contains(gru.Operator.PublicKey);
            await Assert.That(authorization).Contains(gru.Controllers[1].PublicKey);
            await Assert.That(authorization).DoesNotContain(File.ReadAllText(gru.Operator.SeedFile).Trim());
            await Assert.That(authorization).DoesNotContain(gru.Product.Password);
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
