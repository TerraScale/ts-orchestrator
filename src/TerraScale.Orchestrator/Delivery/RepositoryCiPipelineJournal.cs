using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiPipelineJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    IdentityConflict,
    StaleAuthority,
}

internal sealed record RepositoryCiPipelineJournalReceipt(
    RepositoryCiPipelineJournalDisposition Disposition,
    RepositoryCiPipelinePlan Plan);

/// <summary>Stores exact affected CI inputs by content and CAS-indexes one immutable pipeline per event.</summary>
internal sealed class RepositoryCiPipelineJournal(
    IForgejoDeliveryLedger ledger,
    INativeGitOpsManifestStore objects)
{
    private const int MaximumPointerBytes = 8 * 1024;
    private const int MaximumObjectBytes = 32 * 1024 * 1024;
    private const int MaximumRepositories = 64;

    internal async Task<RepositoryCiPipelinePlan?> ReadAsync(
        string dedupeKey,
        CancellationToken cancellationToken = default)
    {
        ValidateDedupeKey(dedupeKey);
        var entry = await ledger.GetAsync(Index(dedupeKey), cancellationToken);
        if (entry is null) return null;
        var pointer = DeserializePointer(entry.Value);
        return await ReadObjectAsync(pointer, dedupeKey, cancellationToken);
    }

    internal async Task<RepositoryCiPipelineJournalReceipt> PlanAndRecordAsync(
        ForgejoCiTriggerPlan trigger,
        IEnumerable<ForgejoSourceFile> descriptorFiles,
        IEnumerable<RepositoryCiChange> changes,
        IEnumerable<ForgejoResolvedRevision> sources,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(descriptorFiles);
        ArgumentNullException.ThrowIfNull(changes);
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateDedupeKey(trigger.Envelope.DedupeKey);
        ForgejoWebhookEventDocument.From(trigger.Envelope).Validate();
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));

        var descriptorArray = Bounded(descriptorFiles, nameof(descriptorFiles));
        var changeArray = Bounded(changes, nameof(changes));
        var sourceArray = Bounded(sources, nameof(sources));
        var plan = CreatePlan(
            trigger,
            descriptorArray,
            changeArray,
            sourceArray,
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence);
        var document = RepositoryCiPipelineObjectDocument.From(
            trigger,
            descriptorArray,
            changeArray,
            sourceArray,
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence,
            plan);
        var content = SerializeObject(document);
        var contentDigest = Hash(content);
        var proposed = RepositoryCiPipelinePointerDocument.From(
            trigger.Envelope.DedupeKey,
            plan.Digest,
            contentDigest,
            authorityEpoch,
            sequence);
        proposed.Validate();
        var key = Index(trigger.Envelope.DedupeKey);
        var existing = await ledger.GetAsync(key, cancellationToken);
        if (existing is not null)
            return await CompareAsync(existing, proposed, trigger.Envelope.DedupeKey, cancellationToken);
        if (!authorityStillValid())
            return new(RepositoryCiPipelineJournalDisposition.StaleAuthority, plan);

        await objects.PutAsync(proposed.ObjectName, content, cancellationToken);
        var verified = await objects.GetAsync(proposed.ObjectName, cancellationToken);
        if (!verified.AsSpan().SequenceEqual(content))
            throw new InvalidDataException("The CI pipeline object was not durable after storage.");
        if (!authorityStillValid())
            return new(RepositoryCiPipelineJournalDisposition.StaleAuthority, plan);

        try
        {
            await ledger.CreateAsync(key, SerializePointer(proposed), cancellationToken);
            return new(RepositoryCiPipelineJournalDisposition.Recorded, plan);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("A concurrently committed CI pipeline pointer disappeared.");
            return await CompareAsync(observed, proposed, trigger.Envelope.DedupeKey, cancellationToken);
        }
    }

    private async Task<RepositoryCiPipelineJournalReceipt> CompareAsync(
        ForgejoDeliveryLedgerEntry entry,
        RepositoryCiPipelinePointerDocument proposed,
        string dedupeKey,
        CancellationToken cancellationToken)
    {
        var observed = DeserializePointer(entry.Value);
        if (observed.DedupeDigest != DedupeDigest(dedupeKey))
            throw new InvalidDataException("A CI pipeline journal index changed event identity.");
        var plan = await ReadObjectAsync(observed, dedupeKey, cancellationToken);
        return new(observed.SameIdentity(proposed)
            ? RepositoryCiPipelineJournalDisposition.Duplicate
            : RepositoryCiPipelineJournalDisposition.IdentityConflict, plan);
    }

    private async Task<RepositoryCiPipelinePlan> ReadObjectAsync(
        RepositoryCiPipelinePointerDocument pointer,
        string dedupeKey,
        CancellationToken cancellationToken)
    {
        if (pointer.DedupeDigest != DedupeDigest(dedupeKey))
            throw new InvalidDataException("A CI pipeline pointer changed event identity.");
        var content = await objects.GetAsync(pointer.ObjectName, cancellationToken);
        if (content.Length is < 1 or > MaximumObjectBytes || Hash(content) != pointer.ContentDigest)
            throw new InvalidDataException("A persisted CI pipeline object failed integrity verification.");
        var plan = DeserializeObject(content).Restore(dedupeKey);
        if (plan.Digest != pointer.PipelineDigest)
            throw new InvalidDataException("A CI pipeline object differs from its durable pointer.");
        return plan;
    }

    internal static RepositoryCiPipelinePlan CreatePlan(
        ForgejoCiTriggerPlan trigger,
        IReadOnlyList<ForgejoSourceFile> descriptorFiles,
        IReadOnlyList<RepositoryCiChange> changes,
        IReadOnlyList<ForgejoResolvedRevision> sources,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        var validatedFiles = descriptorFiles.Select(static file =>
            RepositoryCiPipelineDescriptorDocument.From(file).ToFile()).ToArray();
        if (validatedFiles.Select(static file => file.Repository).Distinct(StringComparer.Ordinal).Count() !=
            validatedFiles.Length)
            throw new InvalidDataException("The CI descriptor set contains a duplicate repository.");
        var descriptorCommits = validatedFiles.ToDictionary(
            static file => file.Repository,
            static file => file.Commit,
            StringComparer.Ordinal);
        foreach (var source in sources)
            if (!descriptorCommits.TryGetValue(source.Repository, out var commit) ||
                !StringComparer.OrdinalIgnoreCase.Equals(commit, source.Commit))
                throw new InvalidDataException("Every affected CI source requires its exact-revision descriptor.");
        var descriptors = validatedFiles.Select(static file => RepositoryCiDescriptor.Parse(file.Content)).ToArray();
        var profile = trigger.JobKind switch
        {
            ControlPlane.Delivery.JobKind.ProductValidation => RepositoryCiProfile.Feature,
            ControlPlane.Delivery.JobKind.TrustedBuild => RepositoryCiProfile.Release,
            _ => throw new InvalidOperationException("The Forgejo trigger cannot create an affected CI pipeline."),
        };
        var impact = RepositoryCiImpactPlanner.Plan(descriptors, changes, profile);
        return RepositoryCiPipelinePlanner.Plan(
            trigger,
            impact,
            sources,
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence);
    }

    private static T[] Bounded<T>(IEnumerable<T> values, string parameter)
    {
        var result = values.Take(MaximumRepositories + 1).ToArray();
        if (result.Length is < 1 or > MaximumRepositories || result.Any(static value => value is null))
            throw new ArgumentException("CI pipeline inputs must be bounded and non-empty.", parameter);
        return result;
    }

    private static byte[] SerializeObject(RepositoryCiPipelineObjectDocument document)
    {
        var content = JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelineObjectDocument);
        if (content.Length is < 1 or > MaximumObjectBytes)
            throw new InvalidDataException("The CI pipeline object exceeded its bound.");
        return content;
    }

    private static RepositoryCiPipelineObjectDocument DeserializeObject(byte[] content)
    {
        try
        {
            return JsonSerializer.Deserialize(
                content,
                RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelineObjectDocument)
                ?? throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A persisted CI pipeline object is invalid.", exception);
        }
    }

    private static string SerializePointer(RepositoryCiPipelinePointerDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelinePointerDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes)
            throw new InvalidDataException("The CI pipeline pointer exceeded its bound.");
        return value;
    }

    private static RepositoryCiPipelinePointerDocument DeserializePointer(string value)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes) throw new JsonException();
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiPipelineJournalJsonContext.Default.RepositoryCiPipelinePointerDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A CI pipeline pointer is invalid.", exception);
        }
    }

    private static string Index(string dedupeKey) => $"ci-pipeline.{DedupeDigest(dedupeKey)}";
    private static string DedupeDigest(string dedupeKey) => Hash(Encoding.UTF8.GetBytes(dedupeKey));
    private static string Hash(ReadOnlySpan<byte> content) => Convert.ToHexStringLower(SHA256.HashData(content));

    private static void ValidateDedupeKey(string? value)
    {
        if (value is not { Length: >= 1 and <= 512 } || value.Any(char.IsControl))
            throw new ArgumentException("Forgejo trigger dedupe identity is invalid.", nameof(value));
    }
}

internal sealed record RepositoryCiPipelinePointerDocument(
    int SchemaVersion,
    string DedupeDigest,
    string PipelineDigest,
    string ContentDigest,
    string ObjectName,
    long AuthorityEpoch,
    long Sequence)
{
    internal static RepositoryCiPipelinePointerDocument From(
        string dedupeKey,
        string pipelineDigest,
        string contentDigest,
        long authorityEpoch,
        long sequence)
    {
        var dedupeDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(dedupeKey)));
        return new(
            1,
            dedupeDigest,
            pipelineDigest,
            contentDigest,
            $"ci-pipeline-{pipelineDigest}-{contentDigest}",
            authorityEpoch,
            sequence);
    }

    internal bool SameIdentity(RepositoryCiPipelinePointerDocument other) =>
        DedupeDigest == other.DedupeDigest && PipelineDigest == other.PipelineDigest &&
        ContentDigest == other.ContentDigest && ObjectName == other.ObjectName;

    internal void Validate()
    {
        if (SchemaVersion != 1 || !Digest(DedupeDigest) || !Digest(PipelineDigest) ||
            !Digest(ContentDigest) || ObjectName != $"ci-pipeline-{PipelineDigest}-{ContentDigest}" ||
            AuthorityEpoch <= 0 || Sequence <= 0)
            throw new InvalidDataException("A CI pipeline pointer is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiPipelineObjectDocument(
    int SchemaVersion,
    ForgejoWebhookEventDocument Event,
    RepositoryCiPipelineDescriptorDocument[] Descriptors,
    RepositoryCiPipelineChangeDocument[] Changes,
    RepositoryCiPipelineSourceDocument[] Sources,
    long Generation,
    long MinimumRunnerSequence,
    long MaximumRunnerSequence,
    string Pipeline,
    string PipelineDigest,
    string ImpactDigest,
    int JobCount)
{
    internal static RepositoryCiPipelineObjectDocument From(
        ForgejoCiTriggerPlan trigger,
        IEnumerable<ForgejoSourceFile> descriptorFiles,
        IEnumerable<RepositoryCiChange> changes,
        IEnumerable<ForgejoResolvedRevision> sources,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence,
        RepositoryCiPipelinePlan plan) => new(
            1,
            ForgejoWebhookEventDocument.From(trigger.Envelope),
            descriptorFiles.OrderBy(static file => file.Repository, StringComparer.Ordinal)
                .Select(RepositoryCiPipelineDescriptorDocument.From).ToArray(),
            changes.OrderBy(static change => change.Repository, StringComparer.Ordinal)
                .Select(RepositoryCiPipelineChangeDocument.From).ToArray(),
            sources.OrderBy(static source => source.Repository, StringComparer.Ordinal)
                .Select(RepositoryCiPipelineSourceDocument.From).ToArray(),
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence,
            plan.Pipeline.Value,
            plan.Digest,
            plan.ImpactDigest,
            plan.Jobs.Count);

    internal RepositoryCiPipelinePlan Restore(string expectedDedupeKey)
    {
        if (SchemaVersion != 1 || Event is null || Event.DedupeKey != expectedDedupeKey ||
            Descriptors is not { Length: > 0 and <= 64 } || Changes is not { Length: > 0 and <= 64 } ||
            Sources is not { Length: > 0 and <= 64 } || Generation <= 0 || MinimumRunnerSequence <= 0 ||
            MaximumRunnerSequence < MinimumRunnerSequence || !Digest(PipelineDigest) || !Digest(ImpactDigest) ||
            Pipeline != $"ci-{PipelineDigest[..24]}" || JobCount <= 0)
            throw new InvalidDataException("A persisted CI pipeline object is invalid.");
        var trigger = ForgejoCiTriggerPlanner.Plan(Event.ToEnvelope());
        var descriptorFiles = Descriptors.Select(static descriptor => descriptor.ToFile()).ToArray();
        var changes = Changes.Select(static change => change.ToChange()).ToArray();
        var sources = Sources.Select(static source => source.ToSource()).ToArray();
        var plan = RepositoryCiPipelineJournal.CreatePlan(
            trigger,
            descriptorFiles,
            changes,
            sources,
            Generation,
            MinimumRunnerSequence,
            MaximumRunnerSequence);
        if (plan.Pipeline.Value != Pipeline || plan.Digest != PipelineDigest ||
            plan.ImpactDigest != ImpactDigest || plan.Jobs.Count != JobCount)
            throw new InvalidDataException("A persisted CI pipeline object changed its deterministic plan.");
        return plan;
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiPipelineDescriptorDocument(
    string Repository,
    string Commit,
    string Path,
    string Blob,
    string ContentSha256,
    byte[] Content)
{
    internal static RepositoryCiPipelineDescriptorDocument From(ForgejoSourceFile file) => new(
        file.Repository,
        file.Commit,
        file.Path,
        file.Blob,
        file.ContentSha256,
        file.Content.ToArray());

    internal ForgejoSourceFile ToFile()
    {
        if (!ForgejoWebhookVerifier.IsRepository(Repository) || !ObjectId(Commit) || !ObjectId(Blob) ||
            Path != RepositoryCiImpactPlanner.DescriptorPath || !Digest(ContentSha256) ||
            Content is not { Length: > 0 and <= RepositoryCiDescriptor.MaximumBytes } ||
            Convert.ToHexStringLower(SHA256.HashData(Content)) != ContentSha256)
            throw new InvalidDataException("A persisted CI descriptor source is invalid.");
        var file = new ForgejoSourceFile(Repository, Commit, Path, Blob, ContentSha256, Content);
        var descriptor = RepositoryCiDescriptor.Parse(file.Content);
        if (descriptor.Repository != Repository)
            throw new InvalidDataException("A persisted CI descriptor changed repository identity.");
        return file;
    }

    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F') &&
        value.Any(static character => character != '0');

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiPipelineChangeDocument(string Repository, string[] Paths)
{
    internal static RepositoryCiPipelineChangeDocument From(RepositoryCiChange change) =>
        new(change.Repository, change.Paths.ToArray());

    internal RepositoryCiChange ToChange() => new(
        Repository,
        Paths ?? throw new InvalidDataException("A persisted CI change has no paths."));
}

internal sealed record RepositoryCiPipelineSourceDocument(
    string Repository,
    string Commit,
    string Tree,
    bool SignatureVerified)
{
    internal static RepositoryCiPipelineSourceDocument From(ForgejoResolvedRevision source) => new(
        source.Repository,
        source.Commit,
        source.Tree,
        source.SignatureVerified);

    internal ForgejoResolvedRevision ToSource() => new(Repository, Commit, Tree, SignatureVerified);
}

[JsonSerializable(typeof(RepositoryCiPipelinePointerDocument))]
[JsonSerializable(typeof(RepositoryCiPipelineObjectDocument))]
internal sealed partial class RepositoryCiPipelineJournalJsonContext : JsonSerializerContext;
