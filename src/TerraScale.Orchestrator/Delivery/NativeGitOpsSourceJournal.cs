using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsSourceJournalDisposition
{
    Unspecified,
    NotConfigured,
    Recorded,
    Duplicate,
    StaleAuthority,
    StaleSequence,
    IdentityConflict,
    ConcurrentUpdate,
}

internal sealed record NativeGitOpsSourceJournalReceipt(
    NativeGitOpsSourceJournalDisposition Disposition);

internal sealed record NativeGitOpsAcceptedSource(
    string Branch,
    ForgejoResolvedRevision Revision,
    ForgejoSourceFile SourceFile,
    NativeGitOpsPlan Plan,
    long AuthorityEpoch,
    long PollSequence,
    ulong JournalRevision);

internal interface INativeGitOpsManifestStore
{
    Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken);
    Task<byte[]> GetAsync(string name, CancellationToken cancellationToken);
}

internal sealed class NatsNativeGitOpsManifestStore(INatsObjStore store) : INativeGitOpsManifestStore
{
    public async Task PutAsync(
        string name,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken) =>
        _ = await store.PutAsync(name, content.ToArray(), cancellationToken);

    public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken) =>
        store.GetBytesAsync(name, cancellationToken).AsTask();
}

/// <summary>
/// Stores immutable source bytes in Object Store and advances only a bounded CAS pointer in
/// ORCH_DELIVERY. A failed pointer update leaves an unreferenced content-addressed object, never
/// partially accepted desired state.
/// </summary>
internal sealed class NativeGitOpsSourceJournal
{
    private const int MaximumRecordBytes = 8 * 1024;
    private readonly IForgejoDeliveryLedger ledger;
    private readonly INativeGitOpsManifestStore manifests;

    internal NativeGitOpsSourceJournal(
        IForgejoDeliveryLedger ledger,
        INativeGitOpsManifestStore manifests)
    {
        this.ledger = ledger;
        this.manifests = manifests;
    }

    internal async Task<NativeGitOpsAcceptedSource?> ReadAsync(
        string repository,
        string branch,
        CancellationToken cancellationToken = default)
    {
        ValidateSource(repository, branch);
        var entry = await ledger.GetAsync(Index(repository, branch), cancellationToken);
        if (entry is null) return null;

        var document = Deserialize(entry.Value);
        if (document.Repository != repository || document.Branch != branch)
            throw new InvalidDataException("A native GitOps source index changed identity.");
        var content = await manifests.GetAsync(document.ManifestObject, cancellationToken);
        if (content.Length is < 1 or > NativeGitOpsManifest.MaximumBytes ||
            Convert.ToHexStringLower(SHA256.HashData(content)) != document.ContentSha256)
            throw new InvalidDataException("The accepted native GitOps source bytes failed integrity verification.");
        var plan = NativeGitOpsManifest.Parse(content);
        if (plan.Generation != document.Generation || plan.Digest != document.PlanDigest)
            throw new InvalidDataException("The accepted native GitOps plan did not match its durable pointer.");

        return new(
            document.Branch,
            new(document.Repository, document.Commit, document.Tree, signatureVerified: true),
            new(
                document.Repository,
                document.Commit,
                document.FilePath,
                document.Blob,
                document.ContentSha256,
                content),
            plan,
            document.AuthorityEpoch,
            document.PollSequence,
            entry.Revision);
    }

    internal async Task<NativeGitOpsSourceJournalReceipt> RecordAsync(
        string branch,
        NativeGitOpsSourcePlan source,
        long authorityEpoch,
        long pollSequence,
        NativeGitOpsAcceptedSource? expected,
        Func<bool>? authorityStillValid = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ValidateSource(source.Revision.Repository, branch);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (pollSequence <= 0) throw new ArgumentOutOfRangeException(nameof(pollSequence));
        ValidateDiff(branch, source, expected);

        var proposed = NativeGitOpsSourceJournalDocument.From(
            branch,
            source,
            authorityEpoch,
            pollSequence);
        proposed.Validate();
        if (expected is not null)
        {
            if (authorityEpoch < expected.AuthorityEpoch)
                return new(NativeGitOpsSourceJournalDisposition.StaleAuthority);
            if (authorityEpoch == expected.AuthorityEpoch && pollSequence < expected.PollSequence)
                return new(NativeGitOpsSourceJournalDisposition.StaleSequence);
            if (expected.Revision.Commit == source.Revision.Commit &&
                expected.Revision.Tree == source.Revision.Tree && !Same(expected, source))
                return new(NativeGitOpsSourceJournalDisposition.IdentityConflict);
            if (authorityEpoch == expected.AuthorityEpoch && pollSequence == expected.PollSequence)
                return new(Same(expected, source)
                    ? NativeGitOpsSourceJournalDisposition.Duplicate
                    : NativeGitOpsSourceJournalDisposition.IdentityConflict);
        }

        if (expected is null || expected.SourceFile.ContentSha256 != source.SourceFile.ContentSha256)
        {
            await manifests.PutAsync(proposed.ManifestObject, source.SourceFile.Content, cancellationToken);
            var verified = await manifests.GetAsync(proposed.ManifestObject, cancellationToken);
            if (!verified.AsSpan().SequenceEqual(source.SourceFile.Content.Span))
                throw new InvalidDataException("The native GitOps source bytes were not durable after storage.");
        }
        if (authorityStillValid is not null && !authorityStillValid())
            return new(NativeGitOpsSourceJournalDisposition.StaleAuthority);

        var value = Serialize(proposed);
        try
        {
            if (expected is null)
                await ledger.CreateAsync(Index(proposed.Repository, proposed.Branch), value, cancellationToken);
            else
                await ledger.UpdateAsync(
                    Index(proposed.Repository, proposed.Branch),
                    value,
                    expected.JournalRevision,
                    cancellationToken);
            return new(NativeGitOpsSourceJournalDisposition.Recorded);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            return new(NativeGitOpsSourceJournalDisposition.ConcurrentUpdate);
        }
    }

    private static void ValidateDiff(
        string branch,
        NativeGitOpsSourcePlan source,
        NativeGitOpsAcceptedSource? expected)
    {
        var contentSha256 = Convert.ToHexStringLower(SHA256.HashData(source.SourceFile.Content.Span));
        var compiled = NativeGitOpsManifest.Parse(source.SourceFile.Content);
        if (source.Diff.ProposedGeneration != source.Proposed.Generation ||
            source.Diff.ProposedDigest != source.Proposed.Digest ||
            compiled.Generation != source.Proposed.Generation || compiled.Digest != source.Proposed.Digest ||
            contentSha256 != source.SourceFile.ContentSha256 ||
            source.Revision.Repository != source.SourceFile.Repository ||
            source.Revision.Commit != source.SourceFile.Commit ||
            source.SourceFile.Path != NativeGitOpsSourceLoader.ManifestPath ||
            !source.Revision.SignatureVerified)
            throw new InvalidDataException("The native GitOps source plan is internally inconsistent.");
        if (expected is null)
        {
            if (source.Diff.AcceptedGeneration is not null || source.Diff.AcceptedDigest is not null)
                throw new InvalidDataException("A first native GitOps plan cannot claim accepted state.");
            return;
        }
        if (expected.Branch != branch ||
            expected.Revision.Repository != source.Revision.Repository ||
            source.Diff.AcceptedGeneration != expected.Plan.Generation ||
            source.Diff.AcceptedDigest != expected.Plan.Digest)
            throw new InvalidDataException("The native GitOps diff was not based on the expected accepted plan.");
    }

    private static bool Same(NativeGitOpsAcceptedSource accepted, NativeGitOpsSourcePlan source) =>
        accepted.Revision.Repository == source.Revision.Repository &&
        accepted.Revision.Commit == source.Revision.Commit &&
        accepted.Revision.Tree == source.Revision.Tree &&
        accepted.SourceFile.Path == source.SourceFile.Path &&
        accepted.SourceFile.Blob == source.SourceFile.Blob &&
        accepted.SourceFile.ContentSha256 == source.SourceFile.ContentSha256 &&
        accepted.Plan.Generation == source.Proposed.Generation &&
        accepted.Plan.Digest == source.Proposed.Digest;

    private static void ValidateSource(string repository, string branch)
    {
        if (!ForgejoWebhookVerifier.IsRepository(repository) || branch is not ("develop" or "main"))
            throw new ArgumentException("The native GitOps source identity is invalid.");
    }

    private static NativeGitOpsSourceJournalDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsSourceJournalJsonContext.Default.NativeGitOpsSourceJournalDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps source journal record is invalid.", exception);
        }
    }

    private static string Serialize(NativeGitOpsSourceJournalDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsSourceJournalJsonContext.Default.NativeGitOpsSourceJournalDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The native GitOps source journal record exceeded its bound.");
        return value;
    }

    private static string Index(string repository, string branch) => $"gitops.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"native-gitops:{repository}:{branch}")))}";
}

internal sealed record NativeGitOpsSourceJournalDocument(
    int SchemaVersion,
    string Repository,
    string Branch,
    string Commit,
    string Tree,
    string FilePath,
    string Blob,
    string ContentSha256,
    string ManifestObject,
    long Generation,
    string PlanDigest,
    long AuthorityEpoch,
    long PollSequence)
{
    internal static NativeGitOpsSourceJournalDocument From(
        string branch,
        NativeGitOpsSourcePlan source,
        long authorityEpoch,
        long pollSequence) => new(
            1,
            source.Revision.Repository,
            branch,
            source.Revision.Commit,
            source.Revision.Tree,
            source.SourceFile.Path,
            source.SourceFile.Blob,
            source.SourceFile.ContentSha256,
            $"native-gitops-manifest-{source.SourceFile.ContentSha256}",
            source.Proposed.Generation,
            source.Proposed.Digest,
            authorityEpoch,
            pollSequence);

    internal void Validate()
    {
        if (SchemaVersion != 1 || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            Branch is not ("develop" or "main") || !IsObjectId(Commit) || Commit.All(static value => value == '0') ||
            !IsObjectId(Tree) || Tree.All(static value => value == '0') ||
            FilePath != NativeGitOpsSourceLoader.ManifestPath ||
            !IsObjectId(Blob) || Blob.All(static value => value == '0') ||
            !IsDigest(ContentSha256) || !IsDigest(PlanDigest) || Generation <= 0 ||
            ManifestObject != $"native-gitops-manifest-{ContentSha256}" ||
            AuthorityEpoch <= 0 || PollSequence <= 0)
            throw new InvalidDataException("A native GitOps source journal record is invalid.");
    }

    private static bool IsObjectId(string value) => value.Length is 40 or 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool IsDigest(string value) => value.Length == 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(NativeGitOpsSourceJournalDocument))]
internal sealed partial class NativeGitOpsSourceJournalJsonContext : JsonSerializerContext;
