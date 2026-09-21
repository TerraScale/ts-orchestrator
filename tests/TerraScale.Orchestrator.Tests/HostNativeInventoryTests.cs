using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostNativeInventoryTests
{
    [Test]
    public async Task Discovery_uses_fixed_native_names_for_every_catalog_allocation_and_both_drivers()
    {
        await using var files = new HostInventoryFixture();
        var member = files.Plan();
        var auth = files.Plan(AdmittedRole.Authentication);
        var runner = new Commands(member);
        var containers = new Containers(auth);
        var probe = new HostNativeInventoryProbe(containers, runner, new HostProbe());
        var found = await probe.ReadAsync(files.Identity, CancellationToken.None);
        await Assert.That(found.Drivers).IsEquivalentTo(new[] { RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer });
        await Assert.That(found.Allocations.Count).IsEqualTo(2);
        await Assert.That(found.Allocations.Single(value => value.Driver == RuntimeDriver.OciContainer).Matches(auth)).IsTrue();
        await Assert.That(found.Allocations.Single(value => value.Driver == RuntimeDriver.NativeSystemd).Matches(member)).IsTrue();
        await Assert.That(containers.Ids).Contains(auth.Oci!.ContainerId);
        await Assert.That(containers.Ids.Distinct().Count()).IsEqualTo(containers.Ids.Count);
        await Assert.That(runner.Ids.Count).IsEqualTo(AdmittedRoleCatalog.All.Where(role => role.AllowedDrivers.Contains(RuntimeDriver.NativeSystemd))
            .Select(role => role.ArtifactKey).Distinct().Count());
    }

    [Test]
    [Arguments("foreign-description")]
    [Arguments("invalid-pid")]
    [Arguments("invalid-control")]
    [Arguments("missing-job")]
    [Arguments("unknown-state")]
    [Arguments("wrong-container")]
    [Arguments("missing-fingerprint")]
    public async Task Discovery_rejects_ambiguous_native_evidence(string fault)
    {
        await using var files = new HostInventoryFixture();
        var probe = new HostNativeInventoryProbe(new Containers(files.Plan(AdmittedRole.Authentication), fault),
            new Commands(files.Plan(), fault), new HostProbe());
        await Assert.That(async () => { await probe.ReadAsync(files.Identity, CancellationToken.None); }).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("queued-start")]
    [Arguments("control-process")]
    public async Task Recovery_inventory_does_not_report_queued_or_control_work_as_stopped(string fault)
    {
        await using var files = new HostInventoryFixture();
        var probe = new HostNativeInventoryProbe(new Containers(files.Plan(AdmittedRole.Authentication)),
            new Commands(files.Plan(), fault), new HostProbe());
        var found = await probe.ReadAsync(files.Identity, CancellationToken.None);
        var allocation = found.Allocations.Single(value => value.Driver == RuntimeDriver.NativeSystemd);
        await Assert.That(allocation.MainProcessId).IsNull();
        await Assert.That(allocation.State).IsEqualTo(fault == "queued-start" ? SystemdAllocationState.Starting : SystemdAllocationState.Stopping);
    }

    private sealed class HostProbe : ISystemdHostProbe
    {
        public SystemdHostProbeResult Probe() => new(true, true, true, true, true);
    }
    private sealed class Commands(HostRuntimePlan member, string? fault = null) : IHostCommandRunner
    {
        internal List<string> Ids { get; } = [];
        public Task<HostCommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            if (executable != "/usr/bin/systemctl" || arguments[0] != "show") throw new InvalidOperationException("Unexpected discovery command.");
            Ids.Add(arguments[1]);
            if (arguments[1] != member.Systemd!.UnitName) return Task.FromResult(new HostCommandResult(1, "LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nJob=\n", ""));
            var description = fault == "foreign-description" ? "unowned" : $"TerraScale allocation {member.AllocationId} plan {CanonicalPlanFingerprint.Compute(member)}";
            var pid = fault == "invalid-pid" ? "invalid" : fault is "queued-start" or "control-process" ? "0" : "123";
            var state = fault == "unknown-state" ? "unknown" : fault is "queued-start" or "control-process" ? "inactive" : "active";
            var job = fault == "missing-job" ? "" : fault == "queued-start" ? "Job=41\n" : "Job=\n";
            var control = fault == "invalid-control" ? "invalid" : fault == "control-process" ? "72" : "0";
            return Task.FromResult(new HostCommandResult(0, $"LoadState=loaded\nActiveState={state}\nMainPID={pid}\nControlPID={control}\n{job}Description={description}\n", ""));
        }
    }
    private sealed class Containers(HostRuntimePlan auth, string? fault = null) : IContainerdClient
    {
        internal List<string> Ids { get; } = [];
        public Task<ContainerdAllocationObservation> ObserveAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            if (@namespace != "terrascale" || !containerId.StartsWith("terrascale-", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected discovery address.");
            Ids.Add(containerId);
            return Task.FromResult(containerId == auth.Oci!.ContainerId
                ? new ContainerdAllocationObservation(fault == "wrong-container" ? "wrong" : containerId, ContainerdAllocationState.Running,
                    auth.Oci.ImageReference, auth.Oci.Platform, fault == "missing-fingerprint" ? null : CanonicalPlanFingerprint.Compute(auth), 123, "test")
                : new(containerId, ContainerdAllocationState.Absent, null, null, null, null, "absent"));
        }
        public Task<string> PullAsync(string @namespace, string imageReference, string platform, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task CreateAsync(ContainerdCreateRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task StartAsync(string @namespace, string containerId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task StopAsync(string @namespace, string containerId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task DeleteAsync(string @namespace, string containerId, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
