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
            var security = DevelopmentNatsSecurity.Create(DevelopmentTopology.CreateRegional(), root);
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
        var observation = Observation(expected);

        await Assert.That(CiRunnerProcess.ExecutionLeaseId(accepted)).IsEqualTo(command.Operation);
        var evidence = CiRunnerProcessConfiguration.CreateIsolationEvidence(
            accepted,
            command.Runner,
            command.AllowedZones.Single(),
            command.RunnerSequence,
            command.RequiredCapabilities,
            observation,
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
                observation with { MemoryLimitBytes = expected.MemoryBytes + 2 },
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

    [Test]
    public async Task LinuxProbeRequiresObservedKernelControlsAndResourceCeilings()
    {
        var observation = CiRunnerLinuxIsolationProbe.Parse(
            "Name:\trunner\nNoNewPrivs:\t1\nSeccomp:\t2\n",
            "0::/system.slice/terrascale-ci-runner.service\n",
            "36 25 0:32 / / ro,relatime - ext4 /dev/root ro\n",
            (2L * 1024 * 1024 * 1024).ToString(),
            "512",
            "200000 100000",
            hostDockerSocketMounted: false,
            20L * 1024 * 1024 * 1024,
            rootlessBuildKit: true,
            userNamespace: true);

        CiRunnerLinuxIsolationProbe.Require(
            observation,
            2_000,
            2L * 1024 * 1024 * 1024,
            20L * 1024 * 1024 * 1024,
            512);
        var invalid = new[]
        {
            observation with { ReadOnlyRootFilesystem = false },
            observation with { HostDockerSocketMounted = true },
            observation with { NoNewPrivileges = false },
            observation with { UserNamespace = false },
            observation with { CpuLimitMilliCores = 2_001 },
            observation with { PidsLimit = 513 },
        };
        foreach (var value in invalid)
            await Assert.That(() => CiRunnerLinuxIsolationProbe.Require(
                    value,
                    2_000,
                    2L * 1024 * 1024 * 1024,
                    20L * 1024 * 1024 * 1024,
                    512))
                .Throws<InvalidDataException>();
        await Assert.That(() => CiRunnerLinuxIsolationProbe.Parse(
                "NoNewPrivs:\t1\nSeccomp:\t2\n",
                "0::/runner\n",
                "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n",
                "max",
                "max",
                "max 100000",
                false,
                1,
                true,
                true))
            .Throws<InvalidDataException>();
    }

    private static CiRunnerLinuxIsolationObservation Observation(CiRunnerIsolationEvidence expected) => new(
        expected.ReadOnlyRootFilesystem,
        expected.RootlessBuildKit,
        expected.HostDockerSocketMounted,
        expected.NoNewPrivileges,
        expected.UserNamespace,
        expected.Seccomp,
        expected.CgroupV2,
        expected.CpuMilliCores,
        expected.MemoryBytes,
        expected.EphemeralDiskBytes,
        expected.Pids);
}
