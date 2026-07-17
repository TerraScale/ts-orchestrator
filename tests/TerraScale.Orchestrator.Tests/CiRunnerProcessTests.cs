using System.Runtime.Versioning;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerProcessTests
{
    [Test]
    public async Task RunnerUsesItsScopedJwtCredentialInsteadOfAControllerNKey()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"ci-runner-nats-{Guid.NewGuid():N}");
        try
        {
            var security = DevelopmentNatsSecurity.Create(DevelopmentTopology.CreateThreeCellLean(), root);
            var tls = security.Cell("gru").Tls.Control.Clients["operator-read"];
            var credentials = Path.Combine(root, "runner.creds");
            await File.WriteAllTextAsync(credentials, "bounded-supported-client-credential");
            File.SetUnixFileMode(credentials, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var configuration = CiRunnerNatsConfiguration.Resolve(
                "tls://global-control.internal:4222",
                credentials,
                tls.CaFile,
                tls.CertificateFile,
                tls.KeyFile);
            var options = CiRunnerNatsRuntime.Options(configuration);

            await Assert.That(options.AuthOpts.CredsFile).IsEqualTo(credentials);
            await Assert.That(options.AuthOpts.NKeyFile).IsNull();
            await Assert.That(options.TlsOpts.Mode).IsEqualTo(NATS.Client.Core.TlsMode.Require);
            File.SetUnixFileMode(credentials, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => CiRunnerNatsConfiguration.Resolve(
                    "tls://global-control.internal:4222",
                    credentials,
                    tls.CaFile,
                    tls.CertificateFile,
                    tls.KeyFile))
                .Throws<ArgumentException>();
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task RuntimeProfileReconstructsOnlyTheSignedRunnerIsolation()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var command = accepted.Command;
        var expected = CiRunnerExecutionPlannerTests.Isolation(command);

        await Assert.That(CiRunnerProcess.ExecutionLeaseId(accepted)).IsEqualTo(command.Operation);
        var evidence = CiRunnerProcessConfiguration.CreateIsolationEvidence(
            accepted,
            command.Runner,
            command.AllowedZones.Single(),
            command.RunnerSequence,
            command.RequiredCapabilities,
            expected.CpuMilliCores,
            expected.MemoryBytes,
            expected.EphemeralDiskBytes,
            expected.Pids,
            expected.MaximumLogBytes);

        await Assert.That(evidence).IsEqualTo(expected);
        await Assert.That(() => CiRunnerProcessConfiguration.CreateIsolationEvidence(
                accepted,
                command.Runner,
                command.AllowedZones.Single(),
                command.RunnerSequence,
                command.RequiredCapabilities,
                expected.CpuMilliCores,
                expected.MemoryBytes + 1,
                expected.EphemeralDiskBytes,
                expected.Pids,
                expected.MaximumLogBytes))
            .Throws<InvalidDataException>();
        await Assert.That(() => CiRunnerProcessConfiguration.CreateRunnerEvidence(
                accepted,
                "runner-other",
                TrustZone.UntrustedProduct,
                command.RunnerSequence,
                command.RequiredCapabilities))
            .Throws<InvalidDataException>();
    }
}
