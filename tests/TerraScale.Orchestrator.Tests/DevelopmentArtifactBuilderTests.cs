using System.Diagnostics;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBuilderTests
{
    [Test]
    public async Task StampsSkipOnlyExactCleanUnchangedTreesWithOutputs()
    {
        var root = Path.Combine(Path.GetTempPath(), "ts-orch-stamps-" + Guid.NewGuid().ToString("N"));
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        var repository = Path.Combine(workspace, "TerraBase");
        var project = Path.Combine(repository, "src", "TerraBase.Server", "TerraBase.Server.csproj");
        try
        {
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(project, "project"));
            await File.WriteAllTextAsync(project, "<Project />");
            await RunGitAsync(repository, "init");
            await RunGitAsync(repository, "config user.email test@terrascale.tech");
            await RunGitAsync(repository, "config user.name test");
            await RunGitAsync(repository, "add src/TerraBase.Server/TerraBase.Server.csproj");
            await RunGitAsync(repository, "commit -m init");
            var commit = (await RunGitAsync(repository, "rev-parse HEAD")).Trim();
            foreach (var output in DevelopmentArtifactBuilder.TerraBaseOutputs(data))
            {
                Directory.CreateDirectory(
                    DevelopmentGuards.RequireDirectory(output, "artifact output"));
                await File.WriteAllTextAsync(output, "artifact");
            }
            var digest = DevelopmentArtifactBuilder.DotNetBuilderDigest("TerraBase.Server");

            // No stamp yet: never skip.
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    digest))
                .IsFalse();

            DevelopmentArtifactBuilder.WriteStamp(
                data,
                DevelopmentResourceKind.TerraBase,
                repository,
                project,
                digest,
                new DevelopmentArtifactBuilder.RepositoryState(commit, IsClean: true));
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    digest))
                .IsTrue();

            // A newer commit invalidates the stamp.
            await RunGitAsync(repository, "commit --allow-empty -m second");
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    digest))
                .IsFalse();

            // A dirty worktree invalidates the stamp even at the stamped commit.
            var secondCommit = (await RunGitAsync(repository, "rev-parse HEAD")).Trim();
            DevelopmentArtifactBuilder.WriteStamp(
                data,
                DevelopmentResourceKind.TerraBase,
                repository,
                project,
                digest,
                new DevelopmentArtifactBuilder.RepositoryState(secondCommit, IsClean: true));
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    digest))
                .IsFalse();
            await RunGitAsync(repository, "checkout -- src/TerraBase.Server/TerraBase.Server.csproj");

            // Missing outputs invalidate the stamp.
            File.Delete(DevelopmentArtifactBuilder.TerraBaseOutputs(data)[0]);
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    digest))
                .IsFalse();

            // A changed builder recipe invalidates the stamp.
            await File.WriteAllTextAsync(DevelopmentArtifactBuilder.TerraBaseOutputs(data)[0], "artifact");
            await Assert.That(DevelopmentArtifactBuilder.TrySkip(
                    data,
                    DevelopmentResourceKind.TerraBase,
                    repository,
                    project,
                    DevelopmentArtifactBuilder.TerraBaseOutputs(data),
                    DevelopmentArtifactBuilder.DotNetBuilderDigest("TerraBase.Server.v2")))
                .IsFalse();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task DirtyBuildsAreNeverStamped()
    {
        var root = Path.Combine(Path.GetTempPath(), "ts-orch-stamps-dirty-" + Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "data");
        var repository = Path.Combine(root, "TerraBase");
        var project = Path.Combine(repository, "src", "TerraBase.Server", "TerraBase.Server.csproj");
        try
        {
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(project, "project"));
            await File.WriteAllTextAsync(project, "<Project />");
            await RunGitAsync(repository, "init");
            await RunGitAsync(repository, "config user.email test@terrascale.tech");
            await RunGitAsync(repository, "config user.name test");
            await RunGitAsync(repository, "add src/TerraBase.Server/TerraBase.Server.csproj");
            await RunGitAsync(repository, "commit -m init");
            var commit = (await RunGitAsync(repository, "rev-parse HEAD")).Trim();
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            var digest = DevelopmentArtifactBuilder.DotNetBuilderDigest("TerraBase.Server");

            DevelopmentArtifactBuilder.WriteStamp(
                data,
                DevelopmentResourceKind.TerraBase,
                repository,
                project,
                digest,
                new DevelopmentArtifactBuilder.RepositoryState(commit, IsClean: false));

            await Assert.That(DevelopmentArtifactBuilder.ReadStamp(data, DevelopmentResourceKind.TerraBase))
                .IsNull();

            // A corrupt stamp file is ignored rather than trusted.
            Directory.CreateDirectory(
                DevelopmentGuards.RequireDirectory(
                    DevelopmentArtifactBuilder.StampPath(data, DevelopmentResourceKind.TerraBase),
                    "stamp file"));
            await File.WriteAllTextAsync(
                DevelopmentArtifactBuilder.StampPath(data, DevelopmentResourceKind.TerraBase),
                "{ not json");
            await Assert.That(DevelopmentArtifactBuilder.ReadStamp(data, DevelopmentResourceKind.TerraBase))
                .IsNull();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task<string> RunGitAsync(string workingDirectory, string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        foreach (var argument in arguments.Split(' '))
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return process.ExitCode == 0
            ? output
            : throw new InvalidOperationException($"git {arguments} failed: {error.Trim()}");
    }

    [Test]
    public async Task NpmResolutionUsesVitePlusManagedFallbackWhenPathHasNoNpm()
    {
        var root = Path.Combine(Path.GetTempPath(), "vite-plus-npm-" + Guid.NewGuid().ToString("N"));
        var npmCli = Path.Combine(
            root,
            ".vite-plus",
            "package_manager",
            "npm",
            "11.18.0",
            "npm",
            "bin",
            "npm-cli.js");
        try
        {
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(npmCli, "npm CLI"));
            await File.WriteAllTextAsync(npmCli, "// npm");

            var command = DevelopmentArtifactBuilder.ResolveNpmCommand("/missing", root);

            await Assert.That(command.Executable).IsEqualTo("node");
            await Assert.That(command.PrefixArguments).IsEquivalentTo([npmCli]);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task TerraBaseArtifactAlwaysContainsItsStudioArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "terrabase-studio-artifact-" + Guid.NewGuid().ToString("N"));
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        var studioArchive = Path.Combine(
            workspace,
            "TerraBase",
            "src",
            "TerraBase.Studio",
            "wwwroot",
            "dist",
            DevelopmentArtifactBuilder.TerraBaseStudioArchiveName);
        var serverOutput = DevelopmentArtifactBuilder.DotNetOutputDirectory(data, "TerraBase.Server");
        try
        {
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(studioArchive, "Studio archive"));
            Directory.CreateDirectory(serverOutput);
            await File.WriteAllTextAsync(studioArchive, "studio");

            DevelopmentArtifactBuilder.BundleTerraBaseStudio(workspace, data);

            await Assert.That(File.ReadAllText(Path.Combine(
                    serverOutput,
                    DevelopmentArtifactBuilder.TerraBaseStudioArchiveName)))
                .IsEqualTo("studio");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task TerraBaseArtifactRejectsAMissingStudioArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "terrabase-studio-artifact-" + Guid.NewGuid().ToString("N"));
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        try
        {
            Directory.CreateDirectory(DevelopmentArtifactBuilder.DotNetOutputDirectory(data, "TerraBase.Server"));

            await Assert.That(() => DevelopmentArtifactBuilder.BundleTerraBaseStudio(workspace, data))
                .Throws<FileNotFoundException>();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task FailureDiagnosticPrefersTheCompilerError()
    {
        var diagnostic = DevelopmentArtifactBuilder.Diagnostic(
            "",
            """
            Determining projects to restore...
            Program.cs(78,13): error CS8321: The local function is never used
            Build FAILED.
            """);

        await Assert.That(diagnostic)
            .IsEqualTo("Program.cs(78,13): error CS8321: The local function is never used");
    }
}
