using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiSourceBundle(
    ForgejoResolvedRevision Revision,
    string ObjectName,
    string ContentSha256,
    int ContentLength);

/// <summary>
/// Stores an authenticated exact-commit Forgejo archive by content in the runner bundle store.
/// The runner can receive the resulting immutable identity without receiving Forgejo credentials.
/// </summary>
internal sealed class RepositoryCiSourceBundlePublisher(IDeliveryObjectStore objects)
{
    internal async Task<RepositoryCiSourceBundle> PublishAsync(
        ForgejoSourceArchive archive,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ValidateRevision(archive.Revision);
        if (archive.Content.Length is < 3 or > ForgejoSourceClient.MaximumArchiveBytes ||
            archive.Content.Span[0] != 0x1f || archive.Content.Span[1] != 0x8b || archive.Content.Span[2] != 0x08)
            throw new InvalidDataException("The CI source bundle is not a bounded gzip archive.");

        var contentDigest = Convert.ToHexStringLower(SHA256.HashData(archive.Content.Span));
        if (contentDigest != archive.ContentSha256)
            throw new InvalidDataException("The CI source bundle digest does not match its archive bytes.");
        var objectName = ObjectName(contentDigest);
        await objects.PutAsync(objectName, archive.Content, cancellationToken);
        var readback = await objects.GetAsync(objectName, cancellationToken);
        if (readback.Length != archive.ContentLength ||
            Convert.ToHexStringLower(SHA256.HashData(readback)) != contentDigest ||
            !readback.AsSpan().SequenceEqual(archive.Content.Span))
            throw new InvalidDataException("The CI source bundle was not durable after storage.");

        return new(
            archive.Revision,
            objectName,
            contentDigest,
            archive.ContentLength);
    }

    internal static string ObjectName(string contentDigest) => $"ci-source-{contentDigest}";

    private static void ValidateRevision(ForgejoResolvedRevision revision)
    {
        if (!ForgejoWebhookVerifier.IsRepository(revision.Repository) ||
            !IsObjectId(revision.Commit) || revision.Commit.All(static value => value == '0') ||
            !IsObjectId(revision.Tree) || revision.Tree.All(static value => value == '0'))
            throw new InvalidDataException("The CI source bundle revision is invalid.");
    }

    private static bool IsObjectId(string value) => value.Length is 40 or 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

