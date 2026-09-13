using System.Diagnostics;

namespace TerraScale.Orchestrator.Tooling;

internal static class BoundedProcessRunner
{
    public static ObservedProcessResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string workingDirectory,
        TimeSpan timeout,
        long memoryLimitBytes,
        int processLimit)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.StartInfo.Environment["DOTNET_CLI_USE_MSBUILD_SERVER"] = "0";
        process.StartInfo.Environment["MSBUILDDISABLENODEREUSE"] = "1";
        process.StartInfo.Environment["UseSharedCompilation"] = "false";

        process.Start();
        var processId = process.Id;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var stopwatch = Stopwatch.StartNew();
        long peakMemoryBytes = 0;
        var peakProcessCount = 0;
        string? violation = null;
        while (true)
        {
            var sample = SampleTree(processId);
            peakMemoryBytes = Math.Max(peakMemoryBytes, sample.MemoryBytes);
            peakProcessCount = Math.Max(peakProcessCount, sample.ProcessCount);
            if (sample.MemoryBytes > memoryLimitBytes)
            {
                violation = $"used {sample.MemoryBytes} bytes, above the {memoryLimitBytes}-byte validation limit";
                break;
            }
            if (sample.ProcessCount > processLimit)
            {
                violation = $"used {sample.ProcessCount} processes, above the {processLimit}-process validation limit";
                break;
            }
            if (stopwatch.Elapsed > timeout)
            {
                violation = $"exceeded {timeout.TotalSeconds:0} seconds";
                break;
            }
            if (process.WaitForExit(100))
            {
                break;
            }
        }

        var finalSample = SampleTree(processId);
        peakMemoryBytes = Math.Max(peakMemoryBytes, finalSample.MemoryBytes);
        peakProcessCount = Math.Max(peakProcessCount, finalSample.ProcessCount);
        if (violation is not null)
        {
            process.Kill(entireProcessTree: true);
        }
        process.WaitForExit();
        Task.WaitAll(stdout, stderr);
        if (violation is not null)
        {
            throw new ToolValidationException([$"{fileName} {violation}"]);
        }

        return new(
            process.ExitCode,
            stdout.Result,
            stderr.Result,
            new(processId, peakMemoryBytes, Math.Max(peakProcessCount, 1), stopwatch.ElapsedMilliseconds));
    }

    private static ProcessTreeSample SampleTree(int rootProcessId)
    {
        if (!OperatingSystem.IsLinux())
        {
            try
            {
                using var process = Process.GetProcessById(rootProcessId);
                return new(process.WorkingSet64, 1);
            }
            catch (ArgumentException)
            {
                return default;
            }
        }

        var processes = new Dictionary<int, ProcessStat>();
        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(directory), out var processId) ||
                !TryReadStat(directory, out var stat))
            {
                continue;
            }
            processes[processId] = stat;
        }

        var tree = new HashSet<int> { rootProcessId };
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var (processId, stat) in processes)
            {
                if (!tree.Contains(processId) && tree.Contains(stat.ParentProcessId))
                {
                    tree.Add(processId);
                    changed = true;
                }
            }
        }
        return new(
            tree.Where(processes.ContainsKey).Sum(processId => processes[processId].ResidentBytes),
            tree.Count(processes.ContainsKey));
    }

    private static bool TryReadStat(string directory, out ProcessStat stat)
    {
        try
        {
            var value = File.ReadAllText(Path.Combine(directory, "stat"));
            var close = value.LastIndexOf(')');
            var fields = value[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            stat = new(
                int.Parse(fields[1], System.Globalization.CultureInfo.InvariantCulture),
                checked(long.Parse(fields[21], System.Globalization.CultureInfo.InvariantCulture) * Environment.SystemPageSize));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException or
                                          OverflowException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            stat = default;
            return false;
        }
    }

    private readonly record struct ProcessStat(int ParentProcessId, long ResidentBytes);
    private readonly record struct ProcessTreeSample(long MemoryBytes, int ProcessCount);
}

internal sealed record ProcessObservation(
    int ProcessId,
    long PeakMemoryBytes,
    int PeakProcessCount,
    long DurationMilliseconds);

internal sealed record ObservedProcessResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    ProcessObservation Observation);

