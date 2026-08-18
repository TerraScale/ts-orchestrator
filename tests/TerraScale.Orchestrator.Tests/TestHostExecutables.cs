using System.ComponentModel;
using System.Diagnostics;

namespace TerraScale.Orchestrator.Tests;

internal static class TestHostExecutables
{
    public static string Resolve(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (name.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException("Executable names must not contain a directory separator.", nameof(name));

        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = Path.Combine(directory, name);
            if (File.Exists(candidate)) return Path.GetFullPath(candidate);
        }

        try
        {
            using var probe = Process.Start(new ProcessStartInfo(name)
            {
                ArgumentList = { "--version" },
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (probe is not null)
            {
                probe.WaitForExit(2_000);
                if (probe.HasExited && probe.ExitCode == 0)
                    return name;
            }
        }
        catch (Win32Exception)
        {
        }

        throw new FileNotFoundException($"Required test executable '{name}' was not found on PATH.");
    }
}
