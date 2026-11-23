using System.ComponentModel;
using System.Diagnostics;

namespace TsOrch.Cli;

internal sealed record class ProcessResult(int ExitCode, string Stdout, string Stderr);

internal sealed record class ProcessLaunchFailed(string Executable, string Detail)
{
    public string Message => $"{Executable} could not start: {Detail}";
}

internal readonly union ProcessExecution(ProcessResult, ProcessLaunchFailed);

internal static class ExternalProcess
{
    public static async Task<ProcessExecution> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        bool inheritInput,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardInput = !inheritInput,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Win32Exception exception)
        {
            return new ProcessLaunchFailed(fileName, exception.Message);
        }

        if (!inheritInput)
        {
            process.StandardInput.Close();
        }

        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new ProcessResult(process.ExitCode, await stdout, await stderr);
    }
}
