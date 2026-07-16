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
        await process.WaitForExitAsync(cancellationToken);
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
        RequireCanonicalSystemdPlan(plan);
        var systemd = plan.Systemd!;
        var arguments = new List<string>();
        if (userManager)
        {
            arguments.Add("--user");
        }
        arguments.Add("--unit");
        arguments.Add(systemd.UnitName);
        arguments.Add("--collect");
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
        RequireCanonicalSystemdPlan(plan);
        var arguments = ManagerArguments(
            "show",
            plan.Systemd!.UnitName,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=Result");
        var result = await commandRunner.RunAsync("/usr/bin/systemctl", arguments, cancellationToken);
        if (result.ExitCode != 0)
        {
            return new(plan.Systemd.UnitName, SystemdAllocationState.Absent, null, "not-found");
        }
        var values = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);
        var state = values.GetValueOrDefault("ActiveState") switch
        {
            "active" => SystemdAllocationState.Running,
            "activating" => SystemdAllocationState.Starting,
            "deactivating" => SystemdAllocationState.Stopping,
            "failed" => SystemdAllocationState.Failed,
            _ when values.GetValueOrDefault("LoadState") == "not-found" => SystemdAllocationState.Absent,
            _ => SystemdAllocationState.Failed
        };
        int? pid = int.TryParse(values.GetValueOrDefault("MainPID"), out var parsedPid) && parsedPid > 0
            ? parsedPid
            : null;
        return new(
            plan.Systemd.UnitName,
            state,
            pid,
            values.GetValueOrDefault("Result") ?? "unknown");
    }

    public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        RequireCanonicalSystemdPlan(plan);
        var result = await commandRunner.RunAsync(
            "/usr/bin/systemctl",
            ManagerArguments("stop", plan.Systemd!.UnitName),
            cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"systemd could not stop allocation {plan.AllocationId}; exit code {result.ExitCode}.");
        }
    }

    private IReadOnlyList<string> ManagerArguments(params string[] arguments) => userManager
        ? new[] { "--user" }.Concat(arguments).ToArray()
        : arguments;

    private static void RequireCanonicalSystemdPlan(HostRuntimePlan plan)
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
            plan.Architecture);
        if (plan.Systemd.UnitName != expected.Systemd!.UnitName ||
            plan.Systemd.Executable != expected.Systemd.Executable ||
            !plan.Systemd.Arguments.SequenceEqual(expected.Systemd.Arguments) ||
            !plan.Systemd.Properties.SequenceEqual(expected.Systemd.Properties) ||
            plan.Resources != expected.Resources)
        {
            throw new InvalidOperationException("The systemd execution plan is not canonical for the admitted role.");
        }
    }
}
