using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentArtifactBuilder
{
    internal const string TerraBaseStudioArchiveName = "TerraBase.Studio.zip";
    internal const string StampSchema = "terrascale.orchestrator.development.artifact-stamp/v1";

    public static async Task BuildAsync(
        string workspaceRoot,
        string dataDirectory,
        CancellationToken cancellationToken,
        IReadOnlySet<DevelopmentResourceKind>? affectedKinds = null)
    {
        var terraBaseRepository = Path.Combine(workspaceRoot, "TerraBase");
        var internalsRepository = Path.Combine(workspaceRoot, "TerraScale.Internals");
        var dashboardRepository = Path.Combine(workspaceRoot, "TerraScale.Dashboard");
        var terraBaseProject = Path.Combine(
            workspaceRoot,
            "TerraBase",
            "src",
            "TerraBase.Server",
            "TerraBase.Server.csproj");

        var buildTerraBase = affectedKinds is null ||
            affectedKinds.Contains(DevelopmentResourceKind.TerraBase);
        var skipTerraBase = buildTerraBase && TrySkip(
            dataDirectory,
            DevelopmentResourceKind.TerraBase,
            terraBaseRepository,
            terraBaseProject,
            TerraBaseOutputs(dataDirectory),
            DotNetBuilderDigest("TerraBase.Server"));
        RepositoryState? terraBaseState = null;
        if (buildTerraBase && !skipTerraBase)
        {
            terraBaseState = ReadRepositoryState(terraBaseRepository);
            await BuildTerraBaseStudioAsync(workspaceRoot, cancellationToken);
        }

        var projects = new[]
        {
            (DevelopmentResourceKind.TerraBase, terraBaseProject),
            (DevelopmentResourceKind.Authentication,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Auth", "TerraScale.Authentication", "TerraScale.Authentication.csproj"))
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
            var projectName = Path.GetFileNameWithoutExtension(project);
            var repository = kind switch
            {
                DevelopmentResourceKind.TerraBase => terraBaseRepository,
                _ => internalsRepository
            };
            // TerraBase is one unit with the studio pipeline: the top-level
            // decision already covers its full output set.
            var skip = kind == DevelopmentResourceKind.TerraBase
                ? skipTerraBase
                : TrySkip(
                    dataDirectory,
                    kind,
                    repository,
                    project,
                    [Path.Combine(DotNetOutputDirectory(dataDirectory, projectName),
                        projectName + ".dll")],
                    DotNetBuilderDigest(projectName));
            if (skip)
            {
                continue;
            }
            var state = kind == DevelopmentResourceKind.TerraBase ? terraBaseState : ReadRepositoryState(repository);
            await RunAsync(
                "dotnet",
                DotNetBuildArguments(project, dataDirectory),
                DevelopmentGuards.RequireDirectory(project, "Development project"),
                cancellationToken);

            if (kind == DevelopmentResourceKind.TerraBase)
            {
                BundleTerraBaseStudio(workspaceRoot, dataDirectory);
            }
            WriteStamp(dataDirectory, kind, repository, project, DotNetBuilderDigest(projectName), state);
        }

        // Dashboard frontend, route handlers, and backend modules are one
        // Vinext artifact. A legacy Platform impact is treated as Dashboard so
        // an in-flight DevHost request can never rebuild the removed C# API.
        if (affectedKinds is null ||
            affectedKinds.Contains(DevelopmentResourceKind.Dashboard) ||
            affectedKinds.Contains(DevelopmentResourceKind.Platform))
        {
            // The dashboard lives in its own repository; a fresh clone ships
            // without node_modules, so every rebuild installs from the lock
            // file before building through the repository's VitePlus tasks.
            var dashboardSourceRepository = dashboardRepository;
            if (!TrySkip(
                    dataDirectory,
                    DevelopmentResourceKind.Dashboard,
                    dashboardSourceRepository,
                    dashboardSourceRepository,
                    [],
                    DashboardBuilderDigest()))
            {
                var state = ReadRepositoryState(dashboardSourceRepository);
                await RunVitePlusAsync(["install", "--frozen-lockfile"], dashboardSourceRepository, cancellationToken);
                await RunVitePlusAsync(["run", "vinext:build"], dashboardSourceRepository, cancellationToken);
                DevelopmentDashboardArtifact.Snapshot(dashboardSourceRepository, dataDirectory);
                WriteStamp(
                    dataDirectory,
                    DevelopmentResourceKind.Dashboard,
                    dashboardSourceRepository,
                    dashboardSourceRepository,
                    DashboardBuilderDigest(),
                    state);
            }
        }
    }

    /// <summary>
    /// Skips one build unit when the exact source state was already built into the
    /// current outputs: the owning repository must be clean at the stamped commit,
    /// the builder recipe must be unchanged, and every required output must exist.
    /// A dirty worktree never skips, so local iteration always rebuilds.
    /// </summary>
    internal static bool TrySkip(
        string dataDirectory,
        DevelopmentResourceKind kind,
        string repository,
        string project,
        IReadOnlyList<string> requiredOutputs,
        string builderDigest)
    {
        if (!Directory.Exists(repository))
        {
            return false;
        }
        var stamp = ReadStamp(dataDirectory, kind);
        if (stamp is null ||
            !string.Equals(stamp.Repository, Path.GetFullPath(repository), StringComparison.Ordinal) ||
            !string.Equals(stamp.Project, Path.GetFullPath(project), StringComparison.Ordinal) ||
            !string.Equals(stamp.BuilderDigest, builderDigest, StringComparison.Ordinal))
        {
            return false;
        }
        if (requiredOutputs.Count == 0 && !DashboardArtifactExists(dataDirectory))
        {
            return false;
        }
        foreach (var output in requiredOutputs)
        {
            if (!File.Exists(output))
            {
                return false;
            }
        }
        var state = ReadRepositoryState(repository);
        return state is { IsClean: true } &&
            string.Equals(stamp.Commit, state.Commit, StringComparison.Ordinal);
    }

    internal static void WriteStamp(
        string dataDirectory,
        DevelopmentResourceKind kind,
        string repository,
        string project,
        string builderDigest,
        RepositoryState? state)
    {
        // Only the state captured BEFORE the build may be stamped: DevHost can
        // fast-forward the checkout mid-build, and stamping the newer commit
        // would mark a mixed build as exact for that commit.
        if (state is not { IsClean: true })
        {
            // Dirty builds are never stamped: a later clean checkout of the same
            // commit must not be treated as already built.
            return;
        }
        var stamp = new DevelopmentArtifactStamp(
            StampSchema,
            Path.GetFullPath(repository),
            state.Commit,
            Path.GetFullPath(project),
            builderDigest);
        Directory.CreateDirectory(StampDirectory(dataDirectory));
        var path = StampPath(dataDirectory, kind);
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temporary, JsonSerializer.Serialize(stamp));
        File.Move(temporary, path, overwrite: true);
    }

    internal static DevelopmentArtifactStamp? ReadStamp(string dataDirectory, DevelopmentResourceKind kind)
    {
        var path = StampPath(dataDirectory, kind);
        if (!File.Exists(path))
        {
            return null;
        }
        try
        {
            var stamp = JsonSerializer.Deserialize<DevelopmentArtifactStamp>(File.ReadAllText(path));
            return stamp is { Schema: StampSchema } ? stamp : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static IReadOnlyList<string> TerraBaseOutputs(string dataDirectory) =>
    [
        Path.Combine(DotNetOutputDirectory(dataDirectory, "TerraBase.Server"), "TerraBase.Server.dll"),
        Path.Combine(DotNetOutputDirectory(dataDirectory, "TerraBase.Server"), TerraBaseStudioArchiveName)
    ];

    internal static string StampPath(string dataDirectory, DevelopmentResourceKind kind) =>
        Path.Combine(StampDirectory(dataDirectory), kind.ToString() + ".json");

    private static string StampDirectory(string dataDirectory) =>
        Path.Combine(dataDirectory, "artifacts", "stamps");

    private static bool DashboardArtifactExists(string dataDirectory)
    {
        try
        {
            DevelopmentDashboardArtifact.Resolve(dataDirectory);
            return true;
        }
        catch (Exception exception) when (
            exception is FileNotFoundException or InvalidOperationException)
        {
            return false;
        }
    }

    internal sealed record RepositoryState(string Commit, bool IsClean);

    private static RepositoryState? ReadRepositoryState(string repository)
    {
        var commit = TryRunGit(repository, ["rev-parse", "HEAD"]);
        if (commit is null)
        {
            return null;
        }
        var status = TryRunGit(repository, ["status", "--porcelain"]);
        return status is null
            ? null
            : new RepositoryState(commit.Trim(), string.IsNullOrWhiteSpace(status));
    }

    /// <summary>
    /// Digest of the exact build recipe for one unit. Any change to the arguments,
    /// extra build steps, or the stamp schema produces a new digest and forces a
    /// rebuild even when the source commit is unchanged.
    /// </summary>
    internal static string DotNetBuilderDigest(string projectName) => Digest(
        StampSchema,
        "dotnet",
        projectName,
        string.Join('\u001f', ["build", "<project>", "--configuration", "Release", "--nologo",
            "--no-incremental", "--maxcpucount:1", "--nodeReuse:false", "--artifacts-path", "<data>"]));

    internal static string DashboardBuilderDigest() => Digest(
        StampSchema,
        "dashboard",
        "vp-install-frozen-lockfile",
        "vp-run-vinext-build",
        "snapshot-standalone");

    private static string Digest(params string[] parts) => Convert.ToHexStringLower(SHA256.HashData(
        Encoding.UTF8.GetBytes(string.Join('\u001f', parts))));

    private static string? TryRunGit(string workingDirectory, IReadOnlyList<string> arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("git")
                {
                    WorkingDirectory = workingDirectory,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                }
            };
            process.StartInfo.Environment["GIT_TERMINAL_PROMPT"] = "0";
            foreach (var argument in arguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0 ? output : null;
        }
        catch (Exception exception) when (
            exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
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

    private static async Task RunVitePlusAsync(
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var command = ResolveVitePlusCommand(workingDirectory: workingDirectory);
        await RunAsync(
            command.Executable,
            command.PrefixArguments.Concat(arguments).ToArray(),
            workingDirectory,
            cancellationToken);
    }

    internal static DevelopmentNpmCommand ResolveVitePlusCommand(
        string? path = null,
        string? userProfile = null,
        string? workingDirectory = null)
    {
        path ??= Environment.GetEnvironmentVariable("PATH");
        foreach (var directory in (path ?? string.Empty).Split(
                     Path.PathSeparator,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var executable = Path.Combine(directory, "vp");
            if (File.Exists(executable))
            {
                return new(executable, []);
            }
        }

        if (workingDirectory is not null)
        {
            var local = Path.Combine(workingDirectory, "node_modules", ".bin", "vp");
            if (File.Exists(local))
            {
                return new(local, []);
            }
        }

        userProfile ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var managed = Path.Combine(userProfile, ".vite-plus", "bin", "vp");
        if (File.Exists(managed))
        {
            return new(managed, []);
        }

        throw new FileNotFoundException(
            "VitePlus (vp) is required to build the Dashboard and was not found on PATH, in node_modules, or in the VitePlus cache.");
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

internal sealed record DevelopmentArtifactStamp(
    string Schema,
    string Repository,
    string Commit,
    string Project,
    string BuilderDigest);
