namespace TerraScale.Orchestrator.Delivery;

public sealed record NativeGitOpsSourcePlan(
    ForgejoResolvedRevision Revision,
    ForgejoSourceFile SourceFile,
    NativeGitOpsPlan Proposed,
    NativeGitOpsDiffPlan Diff);

/// <summary>
/// Loads the native GitOps manifest from an already resolved, signature-verified Forgejo commit.
/// Branch names and other moving references are never accepted at this boundary.
/// </summary>
public static class NativeGitOpsSourceLoader
{
    public const string ManifestPath = ".terrascale/orchestrator.json";

    public static async Task<NativeGitOpsSourcePlan> LoadAsync(
        ForgejoSourceClient source,
        ForgejoResolvedRevision revision,
        NativeGitOpsPlan? accepted = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(revision);
        if (!revision.SignatureVerified)
            throw new InvalidDataException("Native GitOps source requires a signature-verified commit.");

        var file = await source.ReadFileAsync(
            revision.Commit,
            ManifestPath,
            NativeGitOpsManifest.MaximumBytes,
            cancellationToken);
        if (file.Repository != revision.Repository || file.Commit != revision.Commit || file.Path != ManifestPath)
            throw new InvalidDataException("The native GitOps file did not match the resolved source revision.");

        var proposed = NativeGitOpsManifest.Parse(file.Content);
        return new(revision, file, proposed, NativeGitOpsDiff.Compare(accepted, proposed));
    }
}
