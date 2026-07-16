using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed class SmolVmLabDriver(ISmolVmApiClient client)
{
    public async Task<IReadOnlyList<SmolVmMachineInfo>> ConvergeRegionsAsync(
        SmolVmRegionsTopology topology,
        CancellationToken cancellationToken)
    {
        topology.Validate();
        await VerifyBaseArtifactsAsync(topology, cancellationToken);
        var existing = await client.ListMachinesAsync(cancellationToken);
        var desiredNames = topology.Machines.Select(machine => machine.Name).ToHashSet(StringComparer.Ordinal);
        var orphans = existing
            .Where(machine => topology.OwnsMachineName(machine.Name) && !desiredNames.Contains(machine.Name))
            .OrderBy(machine => machine.Name, StringComparer.Ordinal)
            .ToArray();
        foreach (var orphan in orphans)
        {
            await StopAndDeleteAsync(orphan, cancellationToken);
        }

        var byName = existing.Except(orphans).ToDictionary(machine => machine.Name, StringComparer.Ordinal);
        var converged = new List<SmolVmMachineInfo>(topology.Machines.Count);
        foreach (var plan in topology.Machines)
        {
            if (!byName.TryGetValue(plan.Name, out var machine))
            {
                machine = await client.CreateMachineAsync(
                    SmolVmCreateMachineRequest.FromPlan(plan),
                    cancellationToken);
            }
            RequireMatchingMachine(plan, machine);
            machine = machine.State switch
            {
                "running" => machine,
                "created" or "stopped" or "failed" or "unreachable" =>
                    await client.StartMachineAsync(plan.Name, cancellationToken),
                _ => throw new InvalidOperationException(
                    $"SmolVM machine '{plan.Name}' is in unsupported state '{machine.State}'.")
            };
            if (machine.State != "running")
            {
                throw new InvalidOperationException($"SmolVM machine '{plan.Name}' did not reach running state.");
            }
            var readiness = await client.ExecAsync(
                plan.Name,
                new(["/bin/true"], [], null, 10, null),
                cancellationToken);
            if (readiness.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"SmolVM machine '{plan.Name}' failed its in-guest readiness probe with exit code {readiness.ExitCode}.");
            }
            converged.Add(machine);
        }
        return converged;
    }

    public async Task<SmolVmExecResponse> ExecAsync(
        SmolVmRegionsTopology topology,
        string machineName,
        SmolVmExecRequest request,
        CancellationToken cancellationToken)
    {
        topology.Validate();
        if (!topology.Machines.Any(machine => machine.Name == machineName))
        {
            throw new InvalidOperationException("Commands may run only inside a seed VM admitted by this lab topology.");
        }
        if (request.Command.Count == 0 || request.Command.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("The SmolVM exec request requires a non-empty argument list.", nameof(request));
        }
        return await client.ExecAsync(machineName, request, cancellationToken);
    }

    public async Task CleanupAsync(
        SmolVmRegionsTopology topology,
        CancellationToken cancellationToken)
    {
        topology.Validate();
        var failures = new List<Exception>();
        IReadOnlyList<SmolVmMachineInfo> machines;
        try
        {
            machines = await client.ListMachinesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            throw new AggregateException("SmolVM cleanup could not enumerate the private run namespace.", exception);
        }
        foreach (var machine in machines.Where(machine => topology.OwnsMachineName(machine.Name)))
        {
            try
            {
                await StopAndDeleteAsync(machine, cancellationToken);
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }
        if (failures.Count > 0)
        {
            throw new AggregateException("SmolVM cleanup failed for one or more owned machines.", failures);
        }
    }

    private async Task StopAndDeleteAsync(SmolVmMachineInfo machine, CancellationToken cancellationToken)
    {
        if (machine.State == "running")
        {
            await client.StopMachineAsync(machine.Name, cancellationToken);
        }
        await client.DeleteMachineAsync(machine.Name, cancellationToken);
    }

    private static async Task VerifyBaseArtifactsAsync(
        SmolVmRegionsTopology topology,
        CancellationToken cancellationToken)
    {
        foreach (var group in topology.Machines.GroupBy(
                     machine => (machine.BaseArtifactPath, machine.BaseArtifactDigest.Value)))
        {
            if (!File.Exists(group.Key.BaseArtifactPath))
            {
                throw new FileNotFoundException("The pinned SmolVM base artifact is unavailable.", group.Key.BaseArtifactPath);
            }
            await using var stream = new FileStream(
                group.Key.BaseArtifactPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actual = await SHA256.HashDataAsync(stream, cancellationToken);
            if (!CryptographicOperations.FixedTimeEquals(
                    actual,
                    Convert.FromHexString(group.Key.Value)))
            {
                throw new InvalidOperationException("The SmolVM base artifact does not match the topology digest.");
            }
        }
    }

    private static void RequireMatchingMachine(SmolVmMachinePlan plan, SmolVmMachineInfo actual)
    {
        var expectedPorts = plan.Ports
            .Select(port => (port.HostPort, port.GuestPort))
            .Order()
            .ToArray();
        var actualPorts = actual.Ports
            .Select(port => (port.Host, port.Guest))
            .Order()
            .ToArray();
        if (actual.Name != plan.Name ||
            actual.CpuCount != plan.Resources.CpuCount ||
            actual.MemoryMiB != plan.Resources.MemoryMiB ||
            actual.StorageGiB != plan.Resources.StorageGiB ||
            actual.OverlayGiB != plan.Resources.OverlayGiB ||
            !actual.Network ||
            actual.NetworkBackend != "virtio-net" ||
            !expectedPorts.SequenceEqual(actualPorts) ||
            !(actual.AllowedCidrs ?? []).SequenceEqual(plan.AllowedEgressCidrs))
        {
            throw new InvalidOperationException(
                $"Existing SmolVM machine '{plan.Name}' is not owned by the exact regions-smol plan.");
        }
    }
}
