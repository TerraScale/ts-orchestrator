using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Delivery;

internal sealed class CiRunnerBuildKitRuntime
{
    private CiRunnerBuildKitRuntime(
        string runtimeDirectory,
        string homeDirectory,
        string outputRoot,
        string dockerConfigDirectory)
    {
        RuntimeDirectory = runtimeDirectory;
        HomeDirectory = homeDirectory;
        OutputRoot = outputRoot;
        DockerConfigDirectory = dockerConfigDirectory;
        Address = $"unix://{runtimeDirectory}/buildkit/buildkitd.sock";
    }

    internal string RuntimeDirectory { get; }
    internal string HomeDirectory { get; }
    internal string OutputRoot { get; }
    internal string DockerConfigDirectory { get; }
    internal string Address { get; }

    internal static CiRunnerBuildKitRuntime Create(
        string runtimeDirectory,
        string homeDirectory,
        string outputRoot,
        string dockerConfigDirectory)
    {
        var runtime = AbsolutePath(runtimeDirectory, nameof(runtimeDirectory));
        var runtimeParent = Directory.GetParent(runtime);
        if (runtimeParent?.FullName != "/run/user" ||
            !runtimeParent.Name.Equals("user", StringComparison.Ordinal) ||
            !Path.GetFileName(runtime).All(char.IsAsciiDigit))
            throw new ArgumentException("The BuildKit runtime must be a rootless /run/user/<uid> directory.",
                nameof(runtimeDirectory));
        return new(
            runtime,
            AbsolutePath(homeDirectory, nameof(homeDirectory)),
            AbsolutePath(outputRoot, nameof(outputRoot)),
            AbsolutePath(dockerConfigDirectory, nameof(dockerConfigDirectory)));
    }

    private static string AbsolutePath(string value, string parameter)
    {
        if (!Path.IsPathFullyQualified(value) || value.Any(static character =>
                char.IsControl(character) || character == ','))
            throw new ArgumentException("A BuildKit runtime path is invalid.", parameter);
        return Path.GetFullPath(value);
    }
}

internal sealed record CiRunnerBuildKitInvocation(
    string Executable,
    ReadOnlyCollection<string> Arguments,
    string WorkingDirectory,
    ReadOnlyDictionary<string, string> Environment,
    string OutputDirectory,
    string ExportDirectory,
    string MetadataFile,
    TimeSpan Timeout,
    long MaximumLogBytes);

/// <summary>
/// Converts a closed runner plan into the only allowed buildctl command. Every host path and the
/// rootless daemon address are runner-runtime inputs, never repository descriptor inputs.
/// </summary>
internal static class CiRunnerBuildKitInvocationCompiler
{
    internal const string Executable = "/usr/bin/buildctl";

    internal static CiRunnerBuildKitInvocation Create(
        CiRunnerExecutionPlan plan,
        CiRunnerMaterializedSource source,
        CiRunnerBuildKitRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(runtime);
        Validate(plan, source, runtime);
        var output = Path.Combine(runtime.OutputRoot, $"ci-{plan.ExecutionIdentityDigest}");
        var export = Path.Combine(output, plan.Build.Output switch
        {
            CiRunnerExecutionOutputKind.Evidence => "evidence",
            CiRunnerExecutionOutputKind.CandidateArtifacts => "candidate",
            _ => throw new InvalidDataException("The CI BuildKit output kind is invalid."),
        });
        var metadata = Path.Combine(output, "metadata.json");
        var arguments = new List<string>
        {
            "--addr", runtime.Address,
            "build",
            "--progress", "plain",
            "--frontend", CiRunnerExecutionPlanner.Frontend,
            "--local", $"context={source.Root}",
            "--local", $"dockerfile={source.Root}",
            "--opt", $"filename={CiRunnerExecutionPlanner.RecipePath}",
            "--opt", $"target={plan.Build.Target}",
        };
        var platform = Platform(plan.Build.Architectures);
        if (platform is not null)
        {
            arguments.Add("--opt");
            arguments.Add($"platform={platform}");
        }
        if (plan.Build.Cache == CiRunnerCacheScope.UntrustedIsolated)
            arguments.Add("--no-cache");
        arguments.Add("--metadata-file");
        arguments.Add(metadata);
        arguments.Add("--output");
        arguments.Add($"type=local,dest={export}");

        var environment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["PATH"] = "/usr/bin:/bin",
            ["HOME"] = runtime.HomeDirectory,
            ["XDG_RUNTIME_DIR"] = runtime.RuntimeDirectory,
            ["DOCKER_CONFIG"] = runtime.DockerConfigDirectory,
            ["BUILDKIT_PROGRESS"] = "plain",
            ["NO_COLOR"] = "1",
        };
        return new(
            Executable,
            Array.AsReadOnly(arguments.ToArray()),
            source.Root,
            new ReadOnlyDictionary<string, string>(environment),
            output,
            export,
            metadata,
            plan.Build.Timeout,
            plan.Build.MaximumLogBytes);
    }

    private static void Validate(
        CiRunnerExecutionPlan plan,
        CiRunnerMaterializedSource source,
        CiRunnerBuildKitRuntime runtime)
    {
        var build = plan.Build;
        _ = Platform(build.Architectures);
        if (plan.SchemaVersion != 2 || plan.Digest != CiRunnerExecutionPlanner.Digest(plan) ||
            source.PlanDigest != plan.Digest || source.BundleSha256 != plan.Source.BundleSha256 ||
            !Path.IsPathFullyQualified(source.Root) || !Directory.Exists(source.Root) ||
            new DirectoryInfo(source.Root).LinkTarget is not null || UnsafePath(source.Root) ||
            !File.Exists(Path.Combine(source.Root, plan.Source.DescriptorPath)) ||
            !File.Exists(Path.Combine(source.Root, plan.Source.RecipePath)) ||
            build.Frontend != CiRunnerExecutionPlanner.Frontend ||
            !Target(build.Target) ||
            build.Timeout < TimeSpan.FromMinutes(1) || build.Timeout > TimeSpan.FromHours(1) ||
            build.MaximumLogBytes is < 1 or > 64L * 1024 * 1024 ||
            build.Cache is not (CiRunnerCacheScope.UntrustedIsolated or CiRunnerCacheScope.TrustedVerified) ||
            IsWithin(runtime.OutputRoot, source.Root) || IsWithin(source.Root, runtime.OutputRoot) ||
            IsWithin(runtime.HomeDirectory, source.Root) ||
            IsWithin(runtime.DockerConfigDirectory, source.Root))
            throw new InvalidDataException("The CI BuildKit invocation inputs are invalid.");
    }

    private static string? Platform(IReadOnlyCollection<RepositoryCiArchitecture> architectures) =>
        architectures.SequenceEqual([RepositoryCiArchitecture.Any])
            ? null
            : architectures.SequenceEqual([
                RepositoryCiArchitecture.LinuxX64,
                RepositoryCiArchitecture.LinuxArm64])
                ? "linux/amd64,linux/arm64"
                : throw new InvalidDataException("The CI BuildKit architecture set is invalid.");

    private static bool Target(string value) => value is { Length: >= 4 and <= 67 } &&
        value.StartsWith("ci-", StringComparison.Ordinal) && value[3] is >= 'a' and <= 'z' &&
        value[3..].All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool UnsafePath(string value) => value.Any(static character =>
        char.IsControl(character) || character == ',');

    private static bool IsWithin(string path, string parent)
    {
        var normalizedPath = Path.GetFullPath(path);
        var normalizedParent = Path.GetFullPath(parent);
        return normalizedPath == normalizedParent || normalizedPath.StartsWith(
            normalizedParent.EndsWith(Path.DirectorySeparatorChar)
                ? normalizedParent
                : normalizedParent + Path.DirectorySeparatorChar,
            StringComparison.Ordinal);
    }
}
