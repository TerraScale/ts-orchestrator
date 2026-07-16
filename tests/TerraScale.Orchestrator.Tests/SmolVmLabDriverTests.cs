using System.Net;
using System.Security.Cryptography;
using TerraScale.Orchestrator.Lab.SmolVm;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SmolVmLabDriverTests
{
    [Test]
    public async Task ConvergeCleansOwnedOrphansAndStartsExactlyNineSeedMachines()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var existingPlan = fixture.Topology.Machines[0];
            var client = new RecordingSmolVmClient(
            [
                Info(existingPlan, "stopped"),
                Info(existingPlan with { Name = $"{fixture.Topology.NamespacePrefix}-sfo-elastic-1" }, "running"),
                Info(existingPlan with { Name = "foreign-run-gru-seed-1" }, "running")
            ]);

            var result = await new SmolVmLabDriver(client)
                .ConvergeRegionsAsync(fixture.Topology, CancellationToken.None);

            await Assert.That(result).Count().IsEqualTo(9);
            await Assert.That(result.All(machine => machine.State == "running")).IsTrue();
            await Assert.That(client.Created).Count().IsEqualTo(8);
            await Assert.That(client.Started).Count().IsEqualTo(9);
            await Assert.That(client.Executed).Count().IsEqualTo(9);
            await Assert.That(client.Stopped).IsEquivalentTo([$"{fixture.Topology.NamespacePrefix}-sfo-elastic-1"]);
            await Assert.That(client.Deleted).IsEquivalentTo([$"{fixture.Topology.NamespacePrefix}-sfo-elastic-1"]);
            await Assert.That(client.Deleted).DoesNotContain("foreign-run-gru-seed-1");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task UnreachableMachineIsRestartedBeforeReadinessIsAccepted()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var plan = fixture.Topology.Machines[0];
            var client = new RecordingSmolVmClient([Info(plan, "unreachable")]);

            var result = await new SmolVmLabDriver(client)
                .ConvergeRegionsAsync(fixture.Topology, CancellationToken.None);

            await Assert.That(client.Started).Contains(plan.Name);
            await Assert.That(client.Executed).Contains(plan.Name);
            await Assert.That(result).Count().IsEqualTo(9);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task FailedInGuestReadinessProbePreventsAcceptance()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var client = new RecordingSmolVmClient([]) { ExecExitCode = 17 };

            await Assert.That(async () => await new SmolVmLabDriver(client)
                    .ConvergeRegionsAsync(fixture.Topology, CancellationToken.None))
                .Throws<InvalidOperationException>();
            await Assert.That(client.Executed).Count().IsEqualTo(1);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task ExistingDriftedMachineIsFencedInsteadOfResizedOrRecreated()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var plan = fixture.Topology.Machines[0];
            var drifted = Info(plan, "running") with { MemoryMiB = plan.Resources.MemoryMiB + 1 };
            var client = new RecordingSmolVmClient([drifted]);

            await Assert.That(async () => await new SmolVmLabDriver(client)
                    .ConvergeRegionsAsync(fixture.Topology, CancellationToken.None))
                .Throws<InvalidOperationException>();
            await Assert.That(client.Created).IsEmpty();
            await Assert.That(client.Deleted).IsEmpty();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task ArtifactMismatchStopsBeforeAnyApiMutation()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            await File.AppendAllTextAsync(fixture.ArtifactPath, "tampered");
            var client = new RecordingSmolVmClient([]);

            await Assert.That(async () => await new SmolVmLabDriver(client)
                    .ConvergeRegionsAsync(fixture.Topology, CancellationToken.None))
                .Throws<InvalidOperationException>();
            await Assert.That(client.ListCount).IsEqualTo(0);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static SmolVmMachineInfo Info(SmolVmMachinePlan plan, string state) => new(
        plan.Name,
        state,
        plan.Resources.CpuCount,
        plan.Resources.MemoryMiB,
        state == "running" ? 123 : null,
        [],
        plan.Ports.Select(port => new SmolVmApiPort(port.HostPort, port.GuestPort)).ToArray(),
        true,
        "virtio-net",
        plan.AllowedEgressCidrs,
        plan.Resources.StorageGiB,
        plan.Resources.OverlayGiB,
        1);

    private sealed class RecordingSmolVmClient(IReadOnlyList<SmolVmMachineInfo> initial) : ISmolVmApiClient
    {
        private readonly List<SmolVmMachineInfo> machines = initial.ToList();
        public List<string> Created { get; } = [];
        public List<string> Started { get; } = [];
        public List<string> Stopped { get; } = [];
        public List<string> Deleted { get; } = [];
        public List<string> Executed { get; } = [];
        public int ExecExitCode { get; init; }
        public int ListCount { get; private set; }

        public Task<IReadOnlyList<SmolVmMachineInfo>> ListMachinesAsync(CancellationToken cancellationToken)
        {
            ListCount++;
            return Task.FromResult<IReadOnlyList<SmolVmMachineInfo>>(machines.ToArray());
        }

        public Task<SmolVmMachineInfo?> GetMachineAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(machines.SingleOrDefault(machine => machine.Name == name));

        public Task<SmolVmMachineInfo> CreateMachineAsync(
            SmolVmCreateMachineRequest request,
            CancellationToken cancellationToken)
        {
            Created.Add(request.Name);
            var info = new SmolVmMachineInfo(
                request.Name, "created", request.CpuCount, request.MemoryMiB, null, request.Mounts,
                request.Ports, request.Network, request.NetworkBackend, request.AllowedCidrs,
                request.StorageGiB, request.OverlayGiB, 1);
            machines.Add(info);
            return Task.FromResult(info);
        }

        public Task<SmolVmMachineInfo> StartMachineAsync(string name, CancellationToken cancellationToken)
        {
            Started.Add(name);
            var info = machines.Single(machine => machine.Name == name) with { State = "running", ProcessId = 999 };
            machines[machines.FindIndex(machine => machine.Name == name)] = info;
            return Task.FromResult(info);
        }

        public Task<SmolVmExecResponse> ExecAsync(string name, SmolVmExecRequest request, CancellationToken cancellationToken)
        {
            Executed.Add(name);
            return Task.FromResult(new SmolVmExecResponse(
                ExecExitCode,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty));
        }

        public Task<HttpResponseMessage> OpenExecStreamAsync(string name, SmolVmExecRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

        public Task<HttpResponseMessage> OpenLogsAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

        public Task<byte[]> DownloadFileAsync(string name, string guestPath, CancellationToken cancellationToken) =>
            Task.FromResult(Array.Empty<byte>());

        public Task UploadFileAsync(string name, string guestPath, Stream content, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<SmolVmMachineInfo> ResizeMachineAsync(string name, SmolVmResizeRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<SmolVmMachineInfo> StopMachineAsync(string name, CancellationToken cancellationToken)
        {
            Stopped.Add(name);
            var info = machines.Single(machine => machine.Name == name) with { State = "stopped", ProcessId = null };
            machines[machines.FindIndex(machine => machine.Name == name)] = info;
            return Task.FromResult(info);
        }

        public Task DeleteMachineAsync(string name, CancellationToken cancellationToken)
        {
            Deleted.Add(name);
            machines.RemoveAll(machine => machine.Name == name);
            return Task.CompletedTask;
        }
    }

    private sealed record Fixture(string DirectoryPath, string ArtifactPath, SmolVmRegionsTopology Topology) : IDisposable
    {
        public static async Task<Fixture> CreateAsync()
        {
            var directory = Path.Combine(Path.GetTempPath(), $"smolvm-driver-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var artifact = Path.Combine(directory, "base.smolmachine");
            await File.WriteAllTextAsync(artifact, "fixed base artifact");
            await using var stream = File.OpenRead(artifact);
            var digest = new ArtifactDigest(Convert.ToHexStringLower(await SHA256.HashDataAsync(stream)));
            return new(
                directory,
                artifact,
                SmolVmRegionsTopology.Create("driver", artifact, digest, new(2, 2048, 20, 4), ["10.0.0.0/8"]));
        }

        public void Dispose() => Directory.Delete(DirectoryPath, recursive: true);
    }
}
