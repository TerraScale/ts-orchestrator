using System.Diagnostics;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentArtifactBuilder
{
    public static async Task BuildAsync(string workspaceRoot, CancellationToken cancellationToken)
    {
        var projects = new[]
        {
            Path.Combine(workspaceRoot, "TerraBase", "src", "TerraBase.Server", "TerraBase.Server.csproj"),
            Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Hosting", "TerraScale.LocalEmulators", "TerraScale.LocalEmulators.csproj"),
            Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "Auth", "TerraScale.Authentication", "TerraScale.Authentication.csproj"),
            Path.Combine(workspaceRoot, "TerraScale.Internals", "src", "API", "TerraScale.API", "TerraScale.API.csproj")
        };
        foreach (var project in projects)
        {
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

        var dashboard = Path.Combine(
            workspaceRoot,
            "TerraScale.Internals",
            "src",
            "Dashboard",
            "TerraScale.Dashboard.Next");
        await RunAsync("npm", ["run", "build"], dashboard, cancellationToken);
    }

    internal static IReadOnlyList<string> DotNetBuildArguments(string project) =>
        ["build", project, "--configuration", "Release", "--no-restore", "--nologo",
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
        _ = await output;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Development artifact build failed: {FirstLine(standardError)}");
        }
    }

    private static string FirstLine(string value) =>
        value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault() ?? "build exited without diagnostics";
}
