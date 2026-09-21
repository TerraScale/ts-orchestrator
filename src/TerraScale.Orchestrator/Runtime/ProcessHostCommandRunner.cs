using System.Diagnostics;
using System.Text;

namespace TerraScale.Orchestrator.Runtime;

internal sealed record HostCommandResult(int ExitCode, string StandardOutput, string StandardError);

internal interface IHostCommandRunner
{
    Task<HostCommandResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken);
}

/// <summary>
/// Joins the process wait and both output readers before returning. Process-tree cleanup
/// does not prove native-manager job cancellation, cgroup emptiness or writer fencing.
/// </summary>
internal sealed class ProcessHostCommandRunner(bool rejectOutputOverflow = false) : IHostCommandRunner
{
    private const int MaximumCapturedCharacters = 64 * 1024;

    public async Task<HostCommandResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var execution = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        cancellationToken.ThrowIfCancellationRequested();
        process.Start();
        var standardOutput = ReadBoundedAsync(process.StandardOutput, execution);
        var standardError = ReadBoundedAsync(process.StandardError, execution);
        var exited = WaitForExitAsync(process, execution);
        try
        {
            // A failed reader cancels its siblings and the process wait before this join.
            // Waiting for the process first can deadlock it on a pipe nobody is draining.
            await Task.WhenAll(standardOutput, standardError, exited).ConfigureAwait(false);
        }
        catch
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Preserve the read/limit failure that initiated internal cancellation.
            if (standardOutput.IsFaulted) await standardOutput.ConfigureAwait(false);
            if (standardError.IsFaulted) await standardError.ConfigureAwait(false);
            throw;
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new(process.ExitCode, await standardOutput.ConfigureAwait(false), await standardError.ConfigureAwait(false));
    }

    private static async Task WaitForExitAsync(Process process, CancellationTokenSource execution)
    {
        try { await ProcessLifecycle.WaitForExitAsync(process, execution.Token).ConfigureAwait(false); }
        catch
        {
            await execution.CancelAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<string> ReadBoundedAsync(StreamReader reader, CancellationTokenSource execution)
    {
        var buffer = new char[4096];
        var captured = new StringBuilder(buffer.Length);
        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), execution.Token).ConfigureAwait(false);
                if (read == 0) return captured.ToString();
                var remaining = MaximumCapturedCharacters - captured.Length;
                if (rejectOutputOverflow && read > remaining)
                    throw new InvalidOperationException("The host command exceeded its output limit.");
                captured.Append(buffer, 0, Math.Min(read, remaining));
                // Truncating callers still drain both streams through EOF. Strict callers
                // abort the command immediately instead of accepting partial native evidence.
            }
        }
        catch
        {
            await execution.CancelAsync().ConfigureAwait(false);
            throw;
        }
    }
}
