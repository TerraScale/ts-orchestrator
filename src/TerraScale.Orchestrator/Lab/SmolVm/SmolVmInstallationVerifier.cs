using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed record SmolVmVerifiedArtifact(string Role, string Path, string Sha256);

internal sealed record SmolVmVerifiedInstallation(
    string Version,
    string SourceCommit,
    string LauncherPath,
    bool InternalProvenanceQualified,
    IReadOnlyList<SmolVmVerifiedArtifact> Artifacts);

internal static class SmolVmInstallationVerifier
{
    private const string RequiredVersion = "1.5.0";
    private const string RequiredSourceCommit = "6b178e16a7b95af0ed57ca69a1bbc0202e04157d";
    private static readonly HashSet<string> RequiredRoles =
    [
        "installed-version-metadata",
        "launcher",
        "runtime",
        "hypervisor-library",
        "firmware-library"
    ];

    public static async Task<SmolVmVerifiedInstallation> VerifyAsync(
        string pinPath,
        string installationRoot,
        bool requireInternalProvenance,
        CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(pinPath) || !Path.IsPathFullyQualified(installationRoot))
        {
            throw new ArgumentException("SmolVM pin and installation paths must be absolute.");
        }
        await using var pinStream = new FileStream(
            pinPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var document = await JsonDocument.ParseAsync(pinStream, cancellationToken: cancellationToken);
        var root = document.RootElement;
        RequireNumber(root, "schemaVersion", 1);
        var runtime = RequireString(root, "runtime");
        var version = RequireString(root, "version");
        var sourceCommit = RequireString(root.GetProperty("provenance").GetProperty("source"), "commit");
        if (runtime != "smolvm" || version != RequiredVersion || sourceCommit != RequiredSourceCommit)
        {
            throw new InvalidOperationException("The SmolVM installation pin is not the reviewed v1.5.0 source revision.");
        }
        var host = root.GetProperty("hostPlatform");
        if (RequireString(host, "operatingSystem") != "linux" ||
            RequireString(host, "architecture") != "x86_64" ||
            !RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("The pinned SmolVM lab requires a Linux x86_64 host.");
        }
        var supplyChain = root.GetProperty("provenance").GetProperty("terrascaleSupplyChain");
        var internallyQualified =
            RequireString(supplyChain, "internalMirrorStatus") == "established" &&
            RequireString(supplyChain, "internalSignatureStatus") == "established";
        if (requireInternalProvenance && !internallyQualified)
        {
            throw new InvalidOperationException(
                "SmolVM is not deployment-qualified: the internal mirror and signature are not established.");
        }

        var rootPath = Path.GetFullPath(installationRoot);
        var rootPrefix = rootPath.EndsWith(Path.DirectorySeparatorChar)
            ? rootPath
            : rootPath + Path.DirectorySeparatorChar;
        var artifacts = new List<SmolVmVerifiedArtifact>();
        foreach (var artifact in root.GetProperty("distributionArtifacts").EnumerateArray())
        {
            var relativePath = RequireString(artifact, "path");
            var role = RequireString(artifact, "role");
            var expectedDigest = RequireString(artifact, "sha256");
            if (Path.IsPathFullyQualified(relativePath) ||
                relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(segment => segment is ".." or ".") ||
                !RequiredRoles.Contains(role) ||
                expectedDigest.Length != 64)
            {
                throw new InvalidOperationException("The SmolVM artifact pin contains an invalid entry.");
            }
            var artifactPath = Path.GetFullPath(Path.Combine(rootPath, relativePath));
            if (!artifactPath.StartsWith(rootPrefix, StringComparison.Ordinal) || !File.Exists(artifactPath))
            {
                throw new FileNotFoundException($"Pinned SmolVM artifact '{relativePath}' is unavailable.", artifactPath);
            }
            await using var artifactStream = new FileStream(
                artifactPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actualDigest = Convert.ToHexStringLower(await SHA256.HashDataAsync(artifactStream, cancellationToken));
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actualDigest),
                    Convert.FromHexString(expectedDigest)))
            {
                throw new InvalidOperationException($"Pinned SmolVM artifact '{relativePath}' failed SHA-256 verification.");
            }
            artifacts.Add(new(role, artifactPath, actualDigest));
        }
        if (!RequiredRoles.SetEquals(artifacts.Select(artifact => artifact.Role)) ||
            artifacts.Select(artifact => artifact.Role).Distinct(StringComparer.Ordinal).Count() != RequiredRoles.Count)
        {
            throw new InvalidOperationException("The SmolVM installation pin is missing a required runtime artifact.");
        }
        var launcher = artifacts.Single(artifact => artifact.Role == "launcher").Path;
        return new(version, sourceCommit, launcher, internallyQualified, artifacts);
    }

    private static string RequireString(JsonElement element, string property)
    {
        var value = element.GetProperty(property).GetString();
        return !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException($"SmolVM pin field '{property}' is empty.");
    }

    private static void RequireNumber(JsonElement element, string property, int expected)
    {
        if (element.GetProperty(property).GetInt32() != expected)
        {
            throw new InvalidOperationException($"SmolVM pin field '{property}' is unsupported.");
        }
    }
}
