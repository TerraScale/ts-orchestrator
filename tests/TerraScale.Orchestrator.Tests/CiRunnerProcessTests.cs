using System.Runtime.Versioning;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerProcessTests
{
    // TODO(rehome-agent): RunnerUsesItsScopedJwtCredentialInsteadOfAControllerNKey was removed
    // with the production Development/ lab fixtures; rehome it onto a test-owned NATS TLS
    // fixture so CiRunnerNatsConfiguration.Resolve keeps its credential-preference coverage.

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
