using System.Text.Json.Nodes;

namespace TerraScale.Orchestrator.Tooling;

internal static class DevelopmentEvidenceCommand
{
    private const string DefaultProfile = "dev-containers-three-cell-lean";
    private static readonly HashSet<string> AllowedProfiles =
    [
        DefaultProfile,
        "dev-containers-control-three-cell-lean"
    ];

    public static int Run(string[] arguments)
    {
        var options = Parse(arguments);
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
        RunRequired(
            "dotnet",
            ["build", "TerraScale.Orchestrator.slnx", "--no-restore", "-m:1", "-nr:false"],
            root,
            TimeSpan.FromMinutes(5));
        RunRequired(
            "dotnet",
            ["test", "TerraScale.Orchestrator.slnx", "--no-build", "--no-restore"],
            root,
            TimeSpan.FromMinutes(5));
        _ = ToolingTests.Run([]);
        RequireClean(root);

        if (!File.Exists(binary))
        {
            throw new ToolValidationException([$"Orchestrator binary is unavailable: {binary}"]);
        }

        var now = DateTimeOffset.UtcNow;
        var document = new JsonObject
        {
            ["schemaVersion"] = 1,
            ["result"] = "pass",
            ["sourceCommit"] = ToolingSupport.Git(root, "rev-parse", "HEAD").Trim(),
            ["binarySha256"] = ToolingSupport.Sha256(ResolveCodeArtifact(binary)),
            ["authorizedProfile"] = options.Profile,
            ["issuedAt"] = now,
            ["expiresAt"] = now.AddHours(options.ValidHours),
            ["checks"] = new JsonArray(
                "orchestrator-solution-tests",
                "orchestrator-policy-tooling-tests")
        };
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var temporary = $"{output}.{Environment.ProcessId}.tmp";
        File.WriteAllText(temporary, ToolingSupport.Serialize(document));
        File.Move(temporary, output, overwrite: true);
        Console.WriteLine($"authorized {options.Profile} for exact commit and binary until {now.AddHours(options.ValidHours):O}");
        Console.WriteLine(output);
        return 0;
    }

    private static Options Parse(string[] arguments)
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

    private static void RunRequired(
        string fileName,
        IEnumerable<string> arguments,
        string workingDirectory,
        TimeSpan timeout)
    {
        var result = ToolingSupport.RunProcess(
            fileName,
            arguments,
            workingDirectory,
            checked((int)timeout.TotalMilliseconds));
        if (result.ExitCode != 0)
        {
            throw new ToolValidationException([
                $"{fileName} validation failed",
                result.StandardOutput.Trim(),
                result.StandardError.Trim()
            ]);
        }
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

    private sealed record Options(string Output, string? Binary, int ValidHours, string Profile);
}
