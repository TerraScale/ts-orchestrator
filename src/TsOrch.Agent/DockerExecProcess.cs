using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TsOrch.Agent;

internal static class DockerExecProcess
{
    private const int PidFdOpen = 434;
    private const int PidFdSendSignal = 424;
    private const int SigKill = 9;
    private const int SigStop = 19;
    private const int NoSuchProcess = 3;

    public static bool IsSupported =>
        OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture is Architecture.Arm64 or Architecture.X64;

    public static SafeFileHandle Open(int pid) => new((nint)OpenPidFd(PidFdOpen, pid, 0), ownsHandle: true);

    public static bool IsInContainer(int pid, string containerId)
    {
        var dockerScope = $"docker-{containerId}.scope";
        var podmanScope = $"libpod-{containerId}.scope";
        foreach (var line in File.ReadLines(ProcPath(pid, "cgroup")))
        {
            var pathStart = line.LastIndexOf(':');
            if (pathStart >= 0 && line[(pathStart + 1)..].Split('/').Any(part => part == containerId || part == dockerScope || part == podmanScope))
            {
                return true;
            }
        }

        return false;
    }

    public static string? TerminateTree(SafeFileHandle process, int pid, CancellationToken cancellationToken)
    {
        var stopped = Signal(process, SigStop);
        if (stopped != 0)
        {
            return stopped == NoSuchProcess ? null : SignalError(stopped);
        }

        string? failure = null;
        try
        {
            foreach (var child in Children(pid))
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    failure ??= "Exec descendant cleanup timed out.";
                    break;
                }

                using var childProcess = Open(child);
                if (childProcess.IsInvalid || !IsChild(child, pid) || Signal(process, 0) != 0)
                {
                    continue;
                }

                var childFailure = TerminateTree(childProcess, child, cancellationToken);
                failure ??= childFailure;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            failure ??= exception.Message;
        }
        finally
        {
            var killed = Signal(process, SigKill);
            if (killed is not (0 or NoSuchProcess))
            {
                failure ??= SignalError(killed);
            }
        }

        return failure;
    }

    private static IEnumerable<int> Children(int pid)
    {
        foreach (var task in ProcessTasks(pid))
        {
            var children = ReadProcessFile(Path.Combine(task, "children"));
            foreach (var number in children.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out var child) && child > 1)
                {
                    yield return child;
                }
            }
        }
    }

    private static string[] ProcessTasks(int pid)
    {
        try
        {
            return Directory.GetDirectories(ProcPath(pid, "task"));
        }
        catch (DirectoryNotFoundException)
        {
            return [];
        }
    }

    private static bool IsChild(int pid, int parent)
    {
        var status = ReadProcessFile(ProcPath(pid, "stat"));
        var processNameEnd = status.LastIndexOf(')');
        if (processNameEnd < 0 || status.Length < processNameEnd + 5)
        {
            return false;
        }

        var fields = status.AsSpan(processNameEnd + 4);
        var separator = fields.IndexOf(' ');
        return separator > 0
            && int.TryParse(fields[..separator], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid)
            && ppid == parent;
    }

    private static string ReadProcessFile(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception exception) when (exception is DirectoryNotFoundException or FileNotFoundException)
        {
            return string.Empty;
        }
    }

    private static string ProcPath(int pid, string entry) =>
        string.Create(CultureInfo.InvariantCulture, $"/proc/{pid}/{entry}");

    private static int Signal(SafeFileHandle fd, int signal) =>
        SendPidFdSignal(PidFdSendSignal, fd, signal, 0, 0) == 0 ? 0 : Marshal.GetLastPInvokeError();

    private static string SignalError(int error) =>
        string.Create(CultureInfo.InvariantCulture, $"Signaling exec process failed (errno {error}).");

    [DllImport("libc", EntryPoint = "syscall")]
    private static extern long OpenPidFd(long number, int pid, uint flags);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long SendPidFdSignal(long number, SafeFileHandle pidFd, int signal, nint info, uint flags);
}
