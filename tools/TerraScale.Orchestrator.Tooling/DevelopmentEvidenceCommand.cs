using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tooling;

internal static class DevelopmentEvidenceCommand
{
    internal const string DefaultProfile = "dev-containers-three-cell-lean";
    internal const int EvidenceSchemaVersion = 2;
    internal const int MaximumParallelTestModules = 1;
    internal const int MaximumParallelTests = 4;
    internal const int MaximumValidationProcesses = 512;
    internal const long AggregateMemoryLimitBytes = 16L * 1024 * 1024 * 1024;
    internal const long ExecutionMemoryLimitBytes = 14L * 1024 * 1024 * 1024;
    internal const long ReservedHeadroomBytes = AggregateMemoryLimitBytes - ExecutionMemoryLimitBytes;
    internal static readonly IReadOnlyList<TestModule> TestModules =
    [
        new("TerraScale.Orchestrator.ControlPlane.Tests", "tests/TerraScale.Orchestrator.ControlPlane.Tests"),
        new("TerraScale.Orchestrator.ModelTests", "tests/TerraScale.Orchestrator.ModelTests"),
        new("TerraScale.Orchestrator.Protocol.Tests", "tests/TerraScale.Orchestrator.Protocol.Tests"),
        new("TerraScale.Orchestrator.Scheduler.Tests", "tests/TerraScale.Orchestrator.Scheduler.Tests"),
        new("TerraScale.Orchestrator.Tests", "tests/TerraScale.Orchestrator.Tests")
    ];
    private static readonly HashSet<string> AllowedProfiles =
    [
        DefaultProfile,
        "dev-containers-control-three-cell-lean"
    ];

    public static int Run(string[] arguments)
    {
        var options = Parse(arguments);
        using var validationLease = LocalValidationLease.Acquire();
        var root = ToolingSupport.Root;
        var output = Path.GetFullPath(options.Output);
        var binary = Path.GetFullPath(options.Binary ?? Path.Combine(
            root,
            "src",
            "TerraScale.Orchestrator",
            "bin",
            "Debug",
            "net10.0",
            "linux-x64",
            "terrascale-orchestrator"));

        if (IsWithin(output, root))
        {
            throw new ToolValidationException([
                "development evidence must be written outside the Orchestrator repository"
            ]);
        }

        RequireClean(root);
        var observations = new List<(string Name, ProcessObservation Value)>();
        observations.Add(("solution-build", RunRequired(
            "dotnet",
            ["build", "TerraScale.Orchestrator.slnx", "--no-restore", "--nologo", "--maxcpucount:1", "--nodeReuse:false"],
            root,
            TimeSpan.FromMinutes(5)).Observation));
        var inventory = new JsonArray();
        foreach (var module in TestModules)
        {
            var executable = Path.Combine(root, module.RelativeDirectory, "bin", "Debug", "net10.0", "linux-x64", module.Name);
            var result = RunRequired(
                executable,
                ["--maximum-parallel-tests", MaximumParallelTests.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    "--no-ansi", "--disable-logo", "--no-progress"],
                root,
                TimeSpan.FromMinutes(5));
            var total = ParseTestTotal(module.Name, result.StandardOutput);
            observations.Add((module.Name, result.Observation));
            inventory.Add(new JsonObject
            {
                ["module"] = module.Name,
                ["tests"] = total,
                ["maximumParallelTests"] = MaximumParallelTests
            });
        }
        var toolingExecutable = Path.Combine(
            root,
            "tools",
            "TerraScale.Orchestrator.Tooling",
            "bin",
            "Debug",
            "net10.0",
            "terrascale-orchestrator-tooling");
        observations.Add(("orchestrator-policy-tooling-tests", RunRequired(
            toolingExecutable,
            ["test"],
            root,
            TimeSpan.FromMinutes(5)).Observation));
        RequireClean(root);

        if (!File.Exists(binary))
        {
            throw new ToolValidationException([$"Orchestrator binary is unavailable: {binary}"]);
        }

        var now = DateTimeOffset.UtcNow;
        var document = new JsonObject
        {
            ["schemaVersion"] = EvidenceSchemaVersion,
            ["result"] = "pass",
            ["sourceCommit"] = ToolingSupport.Git(root, "rev-parse", "HEAD").Trim(),
            ["binarySha256"] = ToolingSupport.Sha256(ResolveCodeArtifact(binary)),
            ["authorizedProfile"] = options.Profile,
            ["issuedAt"] = now,
            ["expiresAt"] = now.AddHours(options.ValidHours),
            ["checks"] = new JsonArray(
                "orchestrator-solution-build",
                "orchestrator-test-modules-sequential",
                "orchestrator-policy-tooling-tests"),
            ["resourcePolicy"] = new JsonObject
            {
                ["aggregateMemoryLimitBytes"] = AggregateMemoryLimitBytes,
                ["executionMemoryLimitBytes"] = ExecutionMemoryLimitBytes,
                ["reservedHeadroomBytes"] = ReservedHeadroomBytes,
                ["maximumParallelTestModules"] = MaximumParallelTestModules,
                ["maximumParallelTests"] = MaximumParallelTests,
                ["maximumValidationProcesses"] = MaximumValidationProcesses
            },
            ["testInventory"] = inventory,
            ["processObservations"] = new JsonArray(observations.Select(item => (JsonNode)new JsonObject
            {
                ["name"] = item.Name,
                ["processId"] = item.Value.ProcessId,
                ["peakMemoryBytes"] = item.Value.PeakMemoryBytes,
                ["peakProcessCount"] = item.Value.PeakProcessCount,
                ["durationMilliseconds"] = item.Value.DurationMilliseconds
            }).ToArray())
        };
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var temporary = $"{output}.{Environment.ProcessId}.tmp";
        File.WriteAllText(temporary, ToolingSupport.Serialize(document));
        File.Move(temporary, output, overwrite: true);
        Console.WriteLine($"authorized {options.Profile} for exact commit and binary until {now.AddHours(options.ValidHours):O}");
        Console.WriteLine(output);
        return 0;
    }

    internal static Options Parse(string[] arguments)
    {
        string? output = null;
        string? binary = null;
        var profile = DefaultProfile;
        var validHours = 8;
        for (var index = 0; index < arguments.Length; index++)
        {
            if (index + 1 >= arguments.Length)
            {
                throw Usage();
            }

            var value = arguments[++index];
            switch (arguments[index - 1])
            {
                case "--output":
                    output = value;
                    break;
                case "--binary":
                    binary = value;
                    break;
                case "--profile" when AllowedProfiles.Contains(value):
                    profile = value;
                    break;
                case "--valid-hours" when int.TryParse(value, out validHours) && validHours is >= 1 and <= 24:
                    break;
                default:
                    throw Usage();
            }
        }

        return string.IsNullOrWhiteSpace(output)
            ? throw Usage()
            : new Options(output, binary, validHours, profile);
    }

    private static void RequireClean(string root)
    {
        var status = ToolingSupport.Git(root, "status", "--porcelain", "--untracked-files=all");
        if (!string.IsNullOrWhiteSpace(status))
        {
            throw new ToolValidationException([
                "development attestation requires a clean Orchestrator worktree"
            ]);
        }
    }

    private static ObservedProcessResult RunRequired(
        string fileName,
        IEnumerable<string> arguments,
        string workingDirectory,
        TimeSpan timeout)
    {
        var result = BoundedProcessRunner.Run(
            fileName,
            arguments,
            workingDirectory,
            timeout,
            ExecutionMemoryLimitBytes,
            MaximumValidationProcesses);
        if (result.ExitCode != 0)
        {
            throw new ToolValidationException([
                $"{fileName} validation failed",
                result.StandardOutput.Trim(),
                result.StandardError.Trim()
            ]);
        }
        return result;
    }

    internal static int ParseTestTotal(string module, string output)
    {
        var match = Regex.Match(output, @"(?m)^\s*total:\s*(\d+)\s*$", RegexOptions.CultureInvariant);
        return match.Success && int.TryParse(match.Groups[1].Value, out var total) && total > 0
            ? total
            : throw new ToolValidationException([$"{module} did not report a nonzero test inventory"]);
    }

    private static bool IsWithin(string path, string directory)
    {
        var relative = Path.GetRelativePath(directory, path);
        return relative != ".." &&
            !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
            !Path.IsPathRooted(relative);
    }

    private static string ResolveCodeArtifact(string executable)
    {
        var assembly = executable + ".dll";
        return File.Exists(assembly) ? assembly : executable;
    }

    private static ToolValidationException Usage() => new([
        "development-attest requires --output <outside-repository-path> [--binary <path>] [--valid-hours 1..24] [--profile dev-containers-three-cell-lean|dev-containers-control-three-cell-lean]"
    ]);

    internal sealed record Options(string Output, string? Binary, int ValidHours, string Profile);
    internal sealed record TestModule(string Name, string RelativeDirectory);
}
