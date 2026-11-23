using System.ComponentModel;
using System.Diagnostics;

namespace TsOrch.Cli;

internal sealed record class ProcessResult(int ExitCode, string Stdout, string Stderr);

internal sealed record class ProcessLaunchFailed(string Executable, string Detail, int? NativeErrorCode = null)
{
    public string Message => $"{Executable} could not start: {Detail}";
}

internal readonly union ProcessExecution(ProcessResult, ProcessLaunchFailed);

internal static class ExternalProcess
{
    public static Task<ProcessExecution> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        bool inheritInput,
        CancellationToken cancellationToken) =>
        RunAsync(fileName, arguments, inheritInput, null, [], cancellationToken);

    public static Task<ProcessExecution> RunWithInputAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? standardInput,
        IReadOnlyList<string> excludedEnvironment,
        CancellationToken cancellationToken) =>
        RunAsync(fileName, arguments, inheritInput: false, standardInput, excludedEnvironment, cancellationToken);

    private static async Task<ProcessExecution> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        bool inheritInput,
        string? standardInput,
        IReadOnlyList<string> excludedEnvironment,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var startInfo = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardInput = inheritInput is false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var variable in excludedEnvironment)
        {
            startInfo.Environment.Remove(variable);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Win32Exception exception)
        {
            return new ProcessLaunchFailed(fileName, exception.Message, exception.NativeErrorCode);
        }

        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            if (inheritInput is false)
            {
                using var input = process.StandardInput;
                if (standardInput is { } content)
                {
                    await input.WriteAsync(content.AsMemory(), cancellationToken);
                }
            }

            await process.WaitForExitAsync(cancellationToken);
            return new ProcessResult(process.ExitCode, await stdout, await stderr);
        }
        catch (IOException)
        {
            return new ProcessLaunchFailed(fileName, "Process I/O failed.");
        }
        finally
        {
            if (process.HasExited is false)
            {
                Stop(process);
            }
        }
    }

    private static void Stop(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
        }
        catch (Win32Exception) when (process.HasExited)
        {
        }
    }
}
