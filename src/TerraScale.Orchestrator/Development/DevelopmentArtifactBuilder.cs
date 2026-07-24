using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentArtifactBuilder
{
    public static async Task BuildAsync(
        string workspaceRoot,
        string dataDirectory,
        CancellationToken cancellationToken,
        IReadOnlySet<DevelopmentResourceKind>? affectedKinds = null)
    {
        var projects = new[]
        {
            (DevelopmentResourceKind.TerraBase,
                Path.Combine(workspaceRoot, "TerraBase", "src", "TerraBase.Server", "TerraBase.Server.csproj")),
            (DevelopmentResourceKind.EmailEmulator,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Hosting", "TerraScale.LocalEmulators", "TerraScale.LocalEmulators.csproj")),
            (DevelopmentResourceKind.Authentication,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Auth", "TerraScale.Authentication", "TerraScale.Authentication.csproj")),
            (DevelopmentResourceKind.Platform,
                Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Platform", "TerraScale.Platform", "TerraScale.Platform.csproj"))
        };
        foreach (var (kind, project) in projects)
        {
            if (affectedKinds is not null &&
                !affectedKinds.Contains(kind) &&
                !(kind == DevelopmentResourceKind.EmailEmulator &&
                  affectedKinds.Contains(DevelopmentResourceKind.StripeEmulator)))
            {
                continue;
            }
            if (!File.Exists(project))
            {
                throw new FileNotFoundException("A required development project is unavailable.", project);
            }
            await RunAsync(
                "dotnet",
                DotNetBuildArguments(project),
                Path.GetDirectoryName(project)!,
                cancellationToken);
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

    internal static IReadOnlyList<string> DotNetBuildArguments(string project) =>
        ["build", project, "--configuration", "Release", "--nologo",
            "--no-incremental", "--maxcpucount:1", "--nodeReuse:false"];

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
                $"Development artifact build failed: {FirstLine(standardError, standardOutput)}");
        }
    }

    private static string FirstLine(params string[] values) =>
        values.SelectMany(value => value.Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .FirstOrDefault() ?? "build exited without diagnostics";
}
