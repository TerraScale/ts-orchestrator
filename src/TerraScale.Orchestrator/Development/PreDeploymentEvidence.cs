using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Development;

internal sealed record PreDeploymentEvidence(
    int SchemaVersion,
    string Result,
    string SourceCommit,
    string BinarySha256,
    string AuthorizedProfile,
    DateTimeOffset ExpiresAt,
    PreDeploymentResourcePolicy? ResourcePolicy,
    IReadOnlyList<PreDeploymentTestModule>? TestInventory,
    IReadOnlyList<PreDeploymentProcessObservation>? ProcessObservations)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static async Task RequireAsync(
        string? evidenceFile,
        string workspaceRoot,
        string profile,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(evidenceFile) || !File.Exists(evidenceFile))
        {
            throw new InvalidOperationException(
                "Lab startup requires --evidence with valid exact-tree pre-deployment evidence.");
        }

        await using var stream = File.OpenRead(evidenceFile);
        var evidence = await JsonSerializer.DeserializeAsync<PreDeploymentEvidence>(
            stream,
            SerializerOptions,
            cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Pre-deployment evidence is empty.");
        if (evidence.SchemaVersion != 2 ||
            !string.Equals(evidence.Result, "pass", StringComparison.Ordinal) ||
            !string.Equals(evidence.AuthorizedProfile, profile, StringComparison.Ordinal) ||
            evidence.ExpiresAt <= DateTimeOffset.UtcNow ||
            !evidence.HasBoundedValidationEvidence())
        {
            throw new InvalidOperationException("Pre-deployment evidence does not authorize this lab profile.");
        }

        var repository = Path.Combine(workspaceRoot, "TerraScale.Orchestrator");
        var commit = await ReadGitAsync(repository, ["rev-parse", "HEAD"], cancellationToken);
        var status = await ReadGitAsync(repository, ["status", "--porcelain", "--untracked-files=all"], cancellationToken);
        if (!string.IsNullOrWhiteSpace(status))
        {
            throw new InvalidOperationException(
                "Pre-deployment evidence cannot authorize a dirty Orchestrator worktree.");
        }
        if (!string.Equals(commit.Trim(), evidence.SourceCommit, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Pre-deployment evidence was produced for another source commit.");
        }

        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The current Orchestrator executable path is unavailable.");
        var assembly = Path.Combine(AppContext.BaseDirectory, "terrascale-orchestrator.dll");
        var artifact = File.Exists(assembly)
            ? assembly
            : executable;
        await using var artifactStream = File.OpenRead(artifact);
        var digest = Convert.ToHexString(await SHA256.HashDataAsync(artifactStream, cancellationToken))
            .ToLowerInvariant();
        if (!string.Equals(digest, evidence.BinarySha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Pre-deployment evidence was produced for another binary.");
        }
    }

    internal bool HasBoundedValidationEvidence()
    {
        const long aggregateLimit = 24L * 1024 * 1024 * 1024;
        const long executionLimit = 20L * 1024 * 1024 * 1024;
        const int processLimit = 512;
        if (ResourcePolicy is not
            {
                AggregateMemoryLimitBytes: aggregateLimit,
                ExecutionMemoryLimitBytes: executionLimit,
                ReservedHeadroomBytes: aggregateLimit - executionLimit,
                MaximumParallelTestModules: 1,
                MaximumParallelTests: 4,
                MaximumValidationProcesses: processLimit
            } ||
            TestInventory is not { Count: 5 } ||
            ProcessObservations is not { Count: 7 } ||
            TestInventory.Any(item => item.Tests <= 0 || item.MaximumParallelTests != 4) ||
            TestInventory.Select(item => item.Module).Distinct(StringComparer.Ordinal).Count() != 5 ||
            ProcessObservations.Any(item =>
                item.ProcessId <= 0 ||
                item.PeakMemoryBytes <= 0 || item.PeakMemoryBytes > executionLimit ||
                item.PeakProcessCount <= 0 || item.PeakProcessCount > processLimit ||
                item.DurationMilliseconds < 0))
        {
            return false;
        }

        var observed = ProcessObservations.Select(item => item.Name).ToHashSet(StringComparer.Ordinal);
        return observed.Count == 7 &&
            observed.Contains("solution-build") &&
            observed.Contains("orchestrator-policy-tooling-tests") &&
            TestInventory.All(item => observed.Contains(item.Module));
    }

    private static async Task<string> ReadGitAsync(
        string workingDirectory,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
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
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await ProcessLifecycle.WaitForExitAsync(process, cancellationToken);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Git evidence check failed: {await error}");
        }
        return await output;
    }
}

internal sealed record PreDeploymentResourcePolicy(
    long AggregateMemoryLimitBytes,
    long ExecutionMemoryLimitBytes,
    long ReservedHeadroomBytes,
    int MaximumParallelTestModules,
    int MaximumParallelTests,
    int MaximumValidationProcesses);

internal sealed record PreDeploymentTestModule(string Module, int Tests, int MaximumParallelTests);

internal sealed record PreDeploymentProcessObservation(
    string Name,
    int ProcessId,
    long PeakMemoryBytes,
    int PeakProcessCount,
    long DurationMilliseconds);
