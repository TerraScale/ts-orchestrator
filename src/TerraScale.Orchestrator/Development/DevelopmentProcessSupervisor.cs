using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

internal sealed class DevelopmentProcessSupervisor : IAsyncDisposable
{
    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DevelopmentProcessSpec> specifications = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> startedAt = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource stopping = new();

    public IReadOnlyDictionary<string, Process> Processes => processes;

    public Process Start(
        string name,
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        if (processes.ContainsKey(name))
        {
            throw new InvalidOperationException($"Development resource '{name}' is already running.");
        }

        var specification = new DevelopmentProcessSpec(
            name,
            executable,
            arguments.ToArray(),
            workingDirectory,
            environment?.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
        specifications.Add(name, specification);
        return StartCore(specification);
    }

    public IReadOnlyList<string> ExitedResources() => processes
        .Where(pair => pair.Value.HasExited)
        .Select(pair => pair.Key)
        .ToArray();

    public bool IsWithinStartupGrace(string name, TimeSpan grace) =>
        startedAt.TryGetValue(name, out var value) && DateTimeOffset.UtcNow - value < grace;

    public async Task<Process> RestartAsync(string name)
    {
        if (!specifications.TryGetValue(name, out var specification))
        {
            throw new InvalidOperationException($"Development resource '{name}' has no trusted process specification.");
        }
        if (processes.Remove(name, out var previous))
        {
            try
            {
                if (!previous.HasExited)
                {
                    previous.Kill(entireProcessTree: true);
                }
                await previous.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
            }
            finally
            {
                previous.Dispose();
            }
        }
        return StartCore(specification);
    }

    private Process StartCore(DevelopmentProcessSpec specification)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo(specification.Executable)
            {
                WorkingDirectory = specification.WorkingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        foreach (var argument in specification.Arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.StartInfo.Environment["DOTNET_CLI_USE_MSBUILD_SERVER"] = "0";
        process.StartInfo.Environment["MSBUILDDISABLENODEREUSE"] = "1";
        process.StartInfo.Environment["UseSharedCompilation"] = "false";
        if (specification.Environment is not null)
        {
            foreach (var (key, value) in specification.Environment)
            {
                process.StartInfo.Environment[key] = value;
            }
        }

        process.Start();
        processes.Add(specification.Name, process);
        startedAt[specification.Name] = DateTimeOffset.UtcNow;
        _ = PumpAsync(specification.Name, process.StandardOutput, Console.Out, stopping.Token);
        _ = PumpAsync(specification.Name, process.StandardError, Console.Error, stopping.Token);
        return process;
    }

    public void ThrowIfAnyExited()
    {
        var exited = processes.FirstOrDefault(pair => pair.Value.HasExited);
        if (!string.IsNullOrEmpty(exited.Key))
        {
            throw new InvalidOperationException(
                $"Development resource '{exited.Key}' exited unexpectedly with code {exited.Value.ExitCode}.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        foreach (var (_, process) in processes.Reverse())
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
            }
            catch (InvalidOperationException)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        processes.Clear();
        specifications.Clear();
        startedAt.Clear();
        stopping.Dispose();
    }

    private static async Task PumpAsync(
        string name,
        StreamReader reader,
        TextWriter writer,
        CancellationToken cancellationToken)
    {
        try
        {
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    await writer.WriteLineAsync($"[{name}] {line}");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private sealed record DevelopmentProcessSpec(
        string Name,
        string Executable,
        IReadOnlyList<string> Arguments,
        string WorkingDirectory,
        IReadOnlyDictionary<string, string?>? Environment);
}
