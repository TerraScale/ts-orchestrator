using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

internal sealed class DevelopmentProcessSupervisor : IAsyncDisposable
{
    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
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

        var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.StartInfo.Environment["DOTNET_CLI_USE_MSBUILD_SERVER"] = "0";
        process.StartInfo.Environment["MSBUILDDISABLENODEREUSE"] = "1";
        process.StartInfo.Environment["UseSharedCompilation"] = "false";
        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                process.StartInfo.Environment[key] = value;
            }
        }

        process.Start();
        processes.Add(name, process);
        _ = PumpAsync(name, process.StandardOutput, Console.Out, stopping.Token);
        _ = PumpAsync(name, process.StandardError, Console.Error, stopping.Token);
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
}
