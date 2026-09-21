namespace TerraScale.Orchestrator.Runtime;

internal enum SystemdAllocationState
{
    Absent,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed
}

internal sealed record SystemdAllocationObservation(
    string UnitName,
    SystemdAllocationState State,
    int? MainProcessId,
    string Result);

internal sealed class SystemdHostRuntimeAdapter(
    IHostCommandRunner commandRunner,
    bool userManager = false)
{
    private readonly IHostCommandRunner commandRunner =
        commandRunner ?? throw new ArgumentNullException(nameof(commandRunner));

    public async Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var systemd = RequireCanonicalSystemdPlan(plan);
        var observation = await ObserveAsync(plan, cancellationToken);
        if (observation.State is SystemdAllocationState.Running or SystemdAllocationState.Starting)
        {
            return;
        }
        if (observation.State != SystemdAllocationState.Absent)
        {
            var start = await commandRunner.RunAsync(
                "/usr/bin/systemctl",
                ManagerArguments("start", systemd.UnitName),
                cancellationToken);
            if (start.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"systemd could not start allocation {plan.AllocationId}; exit code {start.ExitCode}.");
            }
            return;
        }

        var arguments = new List<string>();
        if (userManager)
        {
            arguments.Add("--user");
        }
        arguments.Add("--unit");
        arguments.Add(systemd.UnitName);
        arguments.Add("--collect");
        arguments.Add("--property");
        arguments.Add($"Description={PlanDescription(plan)}");
        foreach (var property in systemd.Properties)
        {
            arguments.Add("--property");
            arguments.Add(property);
        }
        arguments.Add("--");
        arguments.Add(systemd.Executable);
        arguments.AddRange(systemd.Arguments);
        var result = await commandRunner.RunAsync("/usr/bin/systemd-run", arguments, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd refused allocation {plan.AllocationId} with exit code {result.ExitCode}.");
        }
    }

    public async Task<SystemdAllocationObservation> ObserveAsync(
        HostRuntimePlan plan,
        CancellationToken cancellationToken)
    {
        var systemd = RequireCanonicalSystemdPlan(plan);
        var (result, values) = await ShowUnitAsync(systemd, cancellationToken);
        if (values.GetValueOrDefault("LoadState") == "not-found")
        {
            RequireAbsentObservation(values);
            return new(systemd.UnitName, SystemdAllocationState.Absent, null, "not-found");
        }
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd could not inspect allocation {plan.AllocationId}; exit code {result.ExitCode}.");
        }
        if (values.GetValueOrDefault("LoadState") != "loaded" ||
            values.GetValueOrDefault("Description") != PlanDescription(plan))
        {
            throw new InvalidOperationException(
                $"Existing systemd allocation '{systemd.UnitName}' is not owned by the canonical plan.");
        }
        return MapObservation(systemd, values);
    }

    public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var systemd = RequireCanonicalSystemdPlan(plan);
        // Replacement and recovery must supply the actual previously recorded plan.
        // An allocation-name prefix cannot authorize stopping an unknown generation.
        var (result, values) = await ShowUnitAsync(systemd, cancellationToken);
        if (values.GetValueOrDefault("LoadState") == "not-found")
        {
            RequireAbsentObservation(values);
            return;
        }
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd could not inspect allocation {plan.AllocationId}; exit code {result.ExitCode}.");
        }
        var description = values.GetValueOrDefault("Description");
        if (values.GetValueOrDefault("LoadState") != "loaded" || description != PlanDescription(plan))
        {
            throw new InvalidOperationException(
                $"Existing systemd allocation '{systemd.UnitName}' is not owned by the canonical plan.");
        }
        _ = MapObservation(systemd, values);
        // Stop is idempotent for an inactive unit and cancels any queued start.
        // A zero MainPID alone cannot authorize skipping the manager operation.
        var stop = await commandRunner.RunAsync(
            "/usr/bin/systemctl",
            ManagerArguments("stop", systemd.UnitName),
            cancellationToken);
        if (stop.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd could not stop allocation {plan.AllocationId}; exit code {stop.ExitCode}.");
        }
    }

    private async Task<(HostCommandResult Result, Dictionary<string, string> Values)> ShowUnitAsync(
        SystemdExecutionPlan systemd,
        CancellationToken cancellationToken)
    {
        var arguments = ManagerArguments(
            "show",
            systemd.UnitName,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=ControlPID",
            "--property=Job",
            "--property=Result",
            "--property=Description");
        var result = await commandRunner.RunAsync("/usr/bin/systemctl", arguments, cancellationToken);
        var values = SystemdUnitActivity.Properties(result.StandardOutput);
        return (result, values);
    }

    private static SystemdAllocationObservation MapObservation(
        SystemdExecutionPlan systemd,
        Dictionary<string, string> values)
    {
        var activity = SystemdUnitActivity.Read(values);
        return new(systemd.UnitName, activity.State, activity.MainProcessId,
            values.GetValueOrDefault("Result") ?? "unknown");
    }

    internal static void RequireAbsentObservation(IReadOnlyDictionary<string, string> values)
    {
        var activity = SystemdUnitActivity.Read(values);
        if (!activity.HasNoManagerWork)
            throw new InvalidOperationException("An absent systemd allocation reports conflicting process, job or state evidence.");
    }

    private static string PlanDescription(HostRuntimePlan plan) =>
        $"TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}";

    private IReadOnlyList<string> ManagerArguments(params string[] arguments) => userManager
        ? new[] { "--user" }.Concat(arguments).ToArray()
        : arguments;

    private static SystemdExecutionPlan RequireCanonicalSystemdPlan(HostRuntimePlan plan)
        => NativeSystemdRuntimeAdmission.RequireCanonicalNativePlan(plan).Systemd!;
}
