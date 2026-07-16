using TerraScale.Orchestrator.Lab.SmolVm;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SmolVmTopologyTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task RegionsProfileIsExactlyThreeSeedMachinesPerCell()
    {
        var topology = Create();

        await Assert.That(topology.Machines).Count().IsEqualTo(9);
        await Assert.That(topology.Machines.GroupBy(machine => machine.Cell)
            .ToDictionary(group => group.Key, group => group.Count()))
            .IsEquivalentTo(new Dictionary<string, int> { ["gru"] = 3, ["sfo"] = 3, ["fra"] = 3 });
        await Assert.That(topology.Machines.Select(machine => machine.Name).Distinct()).Count().IsEqualTo(9);
        await Assert.That(topology.Machines.SelectMany(machine => machine.Ports)
            .Select(port => port.HostPort).Distinct()).Count().IsEqualTo(90);
    }

    [Test]
    public async Task NamespaceSeparatesParallelNineMachineRuns()
    {
        var first = Create("run-a", 24_000);
        var second = Create("run-b", 26_000);

        await Assert.That(first.Machines.Select(machine => machine.Name)
            .Intersect(second.Machines.Select(machine => machine.Name))).IsEmpty();
        await Assert.That(first.Machines.SelectMany(machine => machine.Ports).Select(port => port.HostPort)
            .Intersect(second.Machines.SelectMany(machine => machine.Ports).Select(port => port.HostPort))).IsEmpty();
    }

    [Test]
    public async Task ElasticNamesAreAllowedOnlyAsExplicitTemporaryMembers()
    {
        var topology = Create();

        await Assert.That(SmolVmRegionsTopology.IsElasticMachineName(
            topology.NamespacePrefix,
            $"{topology.NamespacePrefix}-sfo-elastic-1")).IsTrue();
        await Assert.That(SmolVmRegionsTopology.IsElasticMachineName(
            topology.NamespacePrefix,
            $"foreign-sfo-elastic-1")).IsFalse();
        await Assert.That(topology.Machines.Any(machine =>
            SmolVmRegionsTopology.IsElasticMachineName(topology.NamespacePrefix, machine.Name))).IsFalse();
    }

    [Test]
    public async Task InvalidOrNonAbsoluteInputsFailBeforeAnyVmOperation()
    {
        await Assert.That(() => SmolVmRegionsTopology.Create(
                "INVALID",
                "relative.smolmachine",
                new ArtifactDigest(Digest),
                new(2, 2048, 20, 4),
                []))
            .Throws<ArgumentException>();
    }

    private static SmolVmRegionsTopology Create(string runId = "acceptance", ushort port = 24_000) =>
        SmolVmRegionsTopology.Create(
            runId,
            "/opt/terrascale/testlab/base.smolmachine",
            new ArtifactDigest(Digest),
            new(2, 2048, 20, 4),
            ["10.0.0.0/8"],
            port);
}
