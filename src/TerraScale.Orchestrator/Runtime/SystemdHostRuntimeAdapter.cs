using System.Diagnostics;

namespace TerraScale.Orchestrator.Runtime;

internal sealed record HostCommandResult(int ExitCode, string StandardOutput, string StandardError);

internal interface IHostCommandRunner
{
    Task<HostCommandResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken);
}

internal sealed class ProcessHostCommandRunner : IHostCommandRunner
{
    private const int MaximumCapturedCharacters = 64 * 1024;

    public async Task<HostCommandResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        var standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var standardError = process.StandardError.ReadToEndAsync(cancellationToken);
        await ProcessLifecycle.WaitForExitAsync(process, cancellationToken);
        return new(
            process.ExitCode,
            Bound(await standardOutput),
            Bound(await standardError));
    }

    private static string Bound(string value) => value.Length <= MaximumCapturedCharacters
        ? value
        : value[..MaximumCapturedCharacters];
}

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
        var arguments = ManagerArguments(
            "show",
            systemd.UnitName,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=Result",
            "--property=Description");
        var result = await commandRunner.RunAsync("/usr/bin/systemctl", arguments, cancellationToken);
        var values = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);
        if (values.GetValueOrDefault("LoadState") == "not-found")
        {
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
        var state = values.GetValueOrDefault("ActiveState") switch
        {
            "active" => SystemdAllocationState.Running,
            "activating" or "reloading" => SystemdAllocationState.Starting,
            "deactivating" => SystemdAllocationState.Stopping,
            "inactive" => SystemdAllocationState.Stopped,
            "failed" => SystemdAllocationState.Failed,
            _ => throw new InvalidOperationException(
                $"systemd returned an unknown state for allocation {plan.AllocationId}.")
        };
        int? pid = int.TryParse(values.GetValueOrDefault("MainPID"), out var parsedPid) && parsedPid > 0
            ? parsedPid
            : null;
        return new(
            systemd.UnitName,
            state,
            pid,
            values.GetValueOrDefault("Result") ?? "unknown");
    }

    public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var systemd = RequireCanonicalSystemdPlan(plan);
        var observation = await ObserveAsync(plan, cancellationToken);
        if (observation.State is SystemdAllocationState.Absent or SystemdAllocationState.Stopped or
            SystemdAllocationState.Failed or SystemdAllocationState.Stopping)
        {
            return;
        }
        var result = await commandRunner.RunAsync(
            "/usr/bin/systemctl",
            ManagerArguments("stop", systemd.UnitName),
            cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd could not stop allocation {plan.AllocationId}; exit code {result.ExitCode}.");
        }
    }

    private static string PlanDescription(HostRuntimePlan plan) =>
        $"TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}";

    private IReadOnlyList<string> ManagerArguments(params string[] arguments) => userManager
        ? new[] { "--user" }.Concat(arguments).ToArray()
        : arguments;

    private static SystemdExecutionPlan RequireCanonicalSystemdPlan(HostRuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.Driver != RuntimeDriver.NativeSystemd || plan.Systemd is null || plan.Oci is not null)
        {
            throw new ArgumentException("The systemd adapter requires a native systemd plan.", nameof(plan));
        }
        var expected = HostRuntimePlan.Create(
            plan.Role,
            plan.Driver,
            plan.AllocationId,
            plan.ArtifactDigest,
            plan.Architecture,
            plan.Resources);
        if (expected.Systemd is not { } expectedSystemd)
        {
            throw new InvalidOperationException("The systemd execution plan could not be reconstructed from the admitted role.");
        }
        var systemd = plan.Systemd;
        if (systemd.UnitName != expectedSystemd.UnitName ||
            systemd.Executable != expectedSystemd.Executable ||
            !systemd.Arguments.SequenceEqual(expectedSystemd.Arguments) ||
            !systemd.Properties.SequenceEqual(expectedSystemd.Properties) ||
            plan.Resources != expected.Resources)
        {
            throw new InvalidOperationException("The systemd execution plan is not canonical for the admitted role.");
        }
        return systemd;
    }
}

