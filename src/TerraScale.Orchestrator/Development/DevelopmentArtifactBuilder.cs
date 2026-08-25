using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentArtifactBuilder
{
    internal const string TerraBaseStudioArchiveName = "TerraBase.Studio.zip";

    public static async Task BuildAsync(
        string workspaceRoot,
        string dataDirectory,
        CancellationToken cancellationToken,
        IReadOnlySet<DevelopmentResourceKind>? affectedKinds = null)
    {
        var buildTerraBase = affectedKinds is null ||
            affectedKinds.Contains(DevelopmentResourceKind.TerraBase);
        if (buildTerraBase)
        {
            await BuildTerraBaseStudioAsync(workspaceRoot, cancellationToken);
        }

        var projects = new[]
        {
            (DevelopmentResourceKind.TerraBase,
                Path.Combine(workspaceRoot, "TerraBase", "src", "TerraBase.Server", "TerraBase.Server.csproj")),
            (DevelopmentResourceKind.Authentication,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Auth", "TerraScale.Authentication", "TerraScale.Authentication.csproj")),
            (DevelopmentResourceKind.Platform,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Platform", "TerraScale.Platform", "TerraScale.Platform.csproj"))
        };
        foreach (var (kind, project) in projects)
        {
            if (affectedKinds is not null &&
                !affectedKinds.Contains(kind))
            {
                continue;
            }
            if (!File.Exists(project))
            {
                throw new FileNotFoundException("A required development project is unavailable.", project);
            }
            await RunAsync(
                "dotnet",
                DotNetBuildArguments(project, dataDirectory),
                DevelopmentGuards.RequireDirectory(project, "Development project"),
                cancellationToken);

            if (kind == DevelopmentResourceKind.TerraBase)
            {
                BundleTerraBaseStudio(workspaceRoot, dataDirectory);
            }
        }

        if (affectedKinds is null || affectedKinds.Contains(DevelopmentResourceKind.Dashboard))
        {
            var dashboard = Path.Combine(
                workspaceRoot,
                "TerraScale.Internals",
                "src",
                "Dashboard",
                "TerraScale.Dashboard.Next");
            await RunAsync("npm", ["run", "build"], dashboard, cancellationToken);
            DevelopmentDashboardArtifact.Snapshot(dashboard, dataDirectory);
        }
    }

    internal static IReadOnlyList<string> DotNetBuildArguments(string project, string dataDirectory) =>
        ["build", project, "--configuration", "Release", "--nologo",
            "--no-incremental", "--maxcpucount:1", "--nodeReuse:false",
            "--artifacts-path", DotNetArtifactsDirectory(dataDirectory)];

    internal static string DotNetOutputDirectory(string dataDirectory, string projectName) =>
        Path.Combine(DotNetArtifactsDirectory(dataDirectory), "bin", projectName, "release");

    internal static void BundleTerraBaseStudio(string workspaceRoot, string dataDirectory)
    {
        var studioArchive = TerraBaseStudioArchive(workspaceRoot);
        if (!File.Exists(studioArchive) || new FileInfo(studioArchive).Length == 0)
        {
            throw new FileNotFoundException(
                "The TerraBase development artifact requires a non-empty Studio archive.",
                studioArchive);
        }

        var serverOutput = DotNetOutputDirectory(dataDirectory, "TerraBase.Server");
        if (!Directory.Exists(serverOutput))
        {
            throw new DirectoryNotFoundException(
                $"The TerraBase server output is unavailable: {serverOutput}");
        }

        File.Copy(
            studioArchive,
            Path.Combine(serverOutput, TerraBaseStudioArchiveName),
            overwrite: true);
    }

    private static async Task BuildTerraBaseStudioAsync(
        string workspaceRoot,
        CancellationToken cancellationToken)
    {
        var terraBaseRoot = Path.Combine(workspaceRoot, "TerraBase");
        var generatorProject = Path.Combine(
            terraBaseRoot,
            "tools",
            "TerraBase.TypingsGenerator",
            "TerraBase.TypingsGenerator.csproj");
        var studioDirectory = Path.Combine(terraBaseRoot, "src", "TerraBase.Studio");
        var packageLock = Path.Combine(studioDirectory, "package-lock.json");
        if (!File.Exists(generatorProject))
        {
            throw new FileNotFoundException("The TerraBase Studio typings generator is unavailable.", generatorProject);
        }
        if (!File.Exists(packageLock))
        {
            throw new FileNotFoundException("The TerraBase Studio lock file is unavailable.", packageLock);
        }

        await RunAsync(
            "dotnet",
            ["build", generatorProject, "--configuration", "Release", "--nologo", "--disable-build-servers"],
            terraBaseRoot,
            cancellationToken);
        await RunNpmAsync(["ci", "--no-audit", "--no-fund"], studioDirectory, cancellationToken);
        await RunNpmAsync(["run", "release"], studioDirectory, cancellationToken);

        var studioArchive = TerraBaseStudioArchive(workspaceRoot);
        if (!File.Exists(studioArchive) || new FileInfo(studioArchive).Length == 0)
        {
            throw new FileNotFoundException(
                "The TerraBase Studio build did not produce its required archive.",
                studioArchive);
        }
    }

    private static string TerraBaseStudioArchive(string workspaceRoot) => Path.Combine(
        workspaceRoot,
        "TerraBase",
        "src",
        "TerraBase.Studio",
        "wwwroot",
        "dist",
        TerraBaseStudioArchiveName);

    private static async Task RunNpmAsync(
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var command = ResolveNpmCommand();
        await RunAsync(
            command.Executable,
            command.PrefixArguments.Concat(arguments).ToArray(),
            workingDirectory,
            cancellationToken);
    }

    internal static DevelopmentNpmCommand ResolveNpmCommand(
        string? path = null,
        string? userProfile = null)
    {
        path ??= Environment.GetEnvironmentVariable("PATH");
        foreach (var directory in (path ?? string.Empty).Split(
                     Path.PathSeparator,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var executable = Path.Combine(directory, "npm");
            if (File.Exists(executable))
            {
                return new(executable, []);
            }
        }

        userProfile ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var packageManagerRoot = Path.Combine(userProfile, ".vite-plus", "package_manager", "npm");
        if (Directory.Exists(packageManagerRoot))
        {
            var npmCli = Directory.EnumerateFiles(
                    packageManagerRoot,
                    "npm-cli.js",
                    SearchOption.AllDirectories)
                .Where(static candidate => candidate.EndsWith(
                    $"{Path.DirectorySeparatorChar}npm{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}npm-cli.js",
                    StringComparison.Ordinal))
                .OrderDescending(StringComparer.Ordinal)
                .FirstOrDefault();
            if (npmCli is not null)
            {
                return new("node", [npmCli]);
            }
        }

        throw new FileNotFoundException(
            "npm is required to build TerraBase Studio and was not found on PATH or in the VitePlus package-manager cache.");
    }

    private static string DotNetArtifactsDirectory(string dataDirectory) =>
        Path.Combine(dataDirectory, "artifacts", "dotnet");

    private static async Task RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
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
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await ProcessLifecycle.WaitForExitAsync(process, cancellationToken);
        var standardError = await error;
        var standardOutput = await output;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Development artifact build failed: {Diagnostic(standardError, standardOutput)}");
        }
    }

    internal static string Diagnostic(params string[] values)
    {
        var lines = values.SelectMany(value => value.Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToArray();
        return lines.FirstOrDefault(static line =>
                   line.Contains(": error ", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("error", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("npm error", StringComparison.OrdinalIgnoreCase))
               ?? lines.LastOrDefault()
               ?? "build exited without diagnostics";
    }
}

internal sealed record DevelopmentNpmCommand(
    string Executable,
    IReadOnlyList<string> PrefixArguments);
