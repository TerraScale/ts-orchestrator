using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiCandidateJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    IdentityConflict,
    StaleAuthority,
}

internal sealed record RepositoryCiCandidateJournalReceipt(
    RepositoryCiCandidateJournalDisposition Disposition);

/// <summary>Stores large immutable candidate records by content and commits only bounded global pointers.</summary>
internal sealed class RepositoryCiCandidateJournal
{
    private const int MaximumPointerBytes = 8 * 1024;
    private const int MaximumCandidateBytes = 64 * 1024 * 1024;
    private readonly IForgejoDeliveryLedger ledger;
    private readonly IDeliveryObjectStore objects;
    private readonly TimeProvider timeProvider;

    internal RepositoryCiCandidateJournal(
        IForgejoDeliveryLedger ledger,
        IDeliveryObjectStore objects,
        TimeProvider? timeProvider = null)
    {
        this.ledger = ledger;
        this.objects = objects;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    internal Task<RepositoryCiCandidate?> ReadCandidateAsync(
        string digest,
        CancellationToken cancellationToken = default) =>
        ReadCandidateCoreAsync(digest, required: false, cancellationToken);

    internal async Task<RepositoryCiCandidate?> FindCandidateAsync(
        IEnumerable<ForgejoBranchObservation> currentMainSources,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentMainSources);
        var observations = currentMainSources.Take(65).ToArray();
        if (observations.Length is < 1 or > 64 || observations.Any(static observation => observation is null))
            throw new ArgumentException("Current main sources must be bounded and non-empty.", nameof(currentMainSources));
        foreach (var observation in observations)
        {
            var source = observation.Revision;
            if (observation.Branch != "main" || !observation.Protected || !source.SignatureVerified ||
                !ForgejoWebhookVerifier.IsRepository(source.Repository) || !IsObjectId(source.Tree))
                throw new InvalidDataException("Candidate lookup requires signed protected-main sources.");
        }
        if (observations.Select(static observation => observation.Revision.Repository)
                .Distinct(StringComparer.Ordinal).Count() != observations.Length)
            throw new InvalidDataException("Candidate lookup contains a duplicate repository.");

        var treeSetDigest = TreeSetDigest(observations.Select(static observation =>
            (observation.Revision.Repository, observation.Revision.Tree)));
        var entry = await ledger.GetAsync(TreeIndex(treeSetDigest), cancellationToken);
        if (entry is null) return null;
        var index = DeserializeTreeIndex(entry.Value);
        if (index.TreeSetDigest != treeSetDigest)
            throw new InvalidDataException("A candidate tree-set index changed identity.");
        var candidate = await ReadCandidateCoreAsync(index.CandidateDigest, required: true, cancellationToken)
            ?? throw new InvalidDataException("A candidate tree-set index lost its candidate.");
        if (TreeSetDigest(candidate.Sources.Select(static source => (source.Repository, source.Tree))) != treeSetDigest)
            throw new InvalidDataException("A candidate does not match its durable tree-set index.");
        var lifecycle = await ReadLifecycleAsync(candidate, required: true, cancellationToken);
        if (lifecycle!.State is not (RepositoryCiCandidateLifecycleState.Active or
                RepositoryCiCandidateLifecycleState.QualificationPrepared or
                RepositoryCiCandidateLifecycleState.Qualified))
            return null;
        return candidate;
    }

    internal async Task<RepositoryCiQualifiedCandidate?> ReadQualifiedAsync(
        string digest,
        CancellationToken cancellationToken = default)
    {
        ValidateDigest(digest, nameof(digest));
        var pointer = await ReadPointerAsync(RepositoryCiCandidateRecordKind.Qualified, digest, cancellationToken);
        if (pointer is null) return null;
        var content = await ReadContentAsync(pointer, cancellationToken);
        var document = DeserializeQualified(content);
        if (document.SchemaVersion != 1 || document.Digest != digest ||
            document.CandidateDigest != pointer.CandidateDigest)
            throw new InvalidDataException("The qualified candidate object differs from its durable pointer.");
        var candidate = await ReadCandidateCoreAsync(document.CandidateDigest, required: true, cancellationToken)
            ?? throw new InvalidDataException("The qualified candidate lost its durable candidate.");
        var lifecycle = await ReadLifecycleAsync(candidate, required: true, cancellationToken);
        if (lifecycle!.State != RepositoryCiCandidateLifecycleState.Qualified ||
            lifecycle.QualifiedDigest != digest)
            throw new InvalidDataException("The qualified candidate has not reached its durable lifecycle commit.");
        return RepositoryCiCandidateResolver.Restore(document.Digest, candidate, document.Sources);
    }

    internal async Task<RepositoryCiCandidateJournalReceipt> RecordCandidateAsync(
        RepositoryCiCandidate candidate,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var content = SerializeCandidate(candidate);
        var recorded = await RecordAsync(
            RepositoryCiCandidateRecordKind.Candidate,
            candidate.Digest,
            candidate.Digest,
            content,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (recorded.Disposition is not (RepositoryCiCandidateJournalDisposition.Recorded or
                RepositoryCiCandidateJournalDisposition.Duplicate))
            return recorded;
        var indexed = await EnsureTreeIndexAsync(
            candidate,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (indexed.Disposition is RepositoryCiCandidateJournalDisposition.IdentityConflict or
            RepositoryCiCandidateJournalDisposition.StaleAuthority)
            return indexed;
        var lifecycle = await EnsureLifecycleAsync(
            candidate,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (lifecycle.Disposition is RepositoryCiCandidateJournalDisposition.IdentityConflict or
            RepositoryCiCandidateJournalDisposition.StaleAuthority)
            return lifecycle;
        return new(recorded.Disposition == RepositoryCiCandidateJournalDisposition.Recorded ||
            indexed.Disposition == RepositoryCiCandidateJournalDisposition.Recorded ||
            lifecycle.Disposition == RepositoryCiCandidateJournalDisposition.Recorded
                ? RepositoryCiCandidateJournalDisposition.Recorded
                : RepositoryCiCandidateJournalDisposition.Duplicate);
    }

    internal async Task<RepositoryCiCandidateJournalReceipt> RecordQualifiedAsync(
        RepositoryCiQualifiedCandidate qualified,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(qualified);
        var persisted = await ReadCandidateCoreAsync(qualified.Candidate.Digest, required: true, cancellationToken);
        if (persisted is null || persisted.Digest != qualified.Candidate.Digest)
            throw new InvalidDataException("Qualification requires the exact durable candidate first.");
        var prepared = await PrepareQualificationAsync(
            qualified,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (prepared.Disposition is not (RepositoryCiCandidateJournalDisposition.Recorded or
                RepositoryCiCandidateJournalDisposition.Duplicate))
            return prepared;
        var content = SerializeQualified(qualified);
        var recorded = await RecordAsync(
            RepositoryCiCandidateRecordKind.Qualified,
            qualified.Digest,
            qualified.Candidate.Digest,
            content,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (recorded.Disposition is not (RepositoryCiCandidateJournalDisposition.Recorded or
                RepositoryCiCandidateJournalDisposition.Duplicate))
            return recorded;
        var completed = await CompleteQualificationAsync(
            qualified,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (completed.Disposition is not (RepositoryCiCandidateJournalDisposition.Recorded or
                RepositoryCiCandidateJournalDisposition.Duplicate))
            return completed;
        return new(prepared.Disposition == RepositoryCiCandidateJournalDisposition.Recorded ||
            recorded.Disposition == RepositoryCiCandidateJournalDisposition.Recorded ||
            completed.Disposition == RepositoryCiCandidateJournalDisposition.Recorded
                ? RepositoryCiCandidateJournalDisposition.Recorded
                : RepositoryCiCandidateJournalDisposition.Duplicate);
    }

    private async Task<RepositoryCiCandidateJournalReceipt> RecordAsync(
        RepositoryCiCandidateRecordKind kind,
        string identityDigest,
        string candidateDigest,
        byte[] content,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        ValidateDigest(identityDigest, nameof(identityDigest));
        ValidateDigest(candidateDigest, nameof(candidateDigest));
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (content.Length is < 1 or > MaximumCandidateBytes)
            throw new InvalidDataException("The persisted candidate object exceeds its bound.");

        var contentDigest = Convert.ToHexStringLower(SHA256.HashData(content));
        var proposed = RepositoryCiCandidatePointerDocument.From(
            kind,
            identityDigest,
            candidateDigest,
            contentDigest,
            authorityEpoch,
            sequence);
        proposed.Validate();
        var existing = await ledger.GetAsync(Index(kind, identityDigest), cancellationToken);
        if (existing is not null) return Compare(existing, proposed);
        if (!authorityStillValid()) return new(RepositoryCiCandidateJournalDisposition.StaleAuthority);

        await objects.PutAsync(proposed.ObjectName, content, cancellationToken);
        var verified = await objects.GetAsync(proposed.ObjectName, cancellationToken);
        if (!verified.AsSpan().SequenceEqual(content))
            throw new InvalidDataException("The candidate object was not durable after storage.");
        if (!authorityStillValid()) return new(RepositoryCiCandidateJournalDisposition.StaleAuthority);

        try
        {
            await ledger.CreateAsync(
                Index(kind, identityDigest),
                SerializePointer(proposed),
                cancellationToken);
            return new(RepositoryCiCandidateJournalDisposition.Recorded);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(Index(kind, identityDigest), cancellationToken)
                ?? throw new InvalidDataException("A concurrently committed candidate pointer disappeared.");
            return Compare(observed, proposed);
        }
    }

    private async Task<RepositoryCiCandidateJournalReceipt> EnsureTreeIndexAsync(
        RepositoryCiCandidate candidate,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var treeSetDigest = TreeSetDigest(candidate.Sources.Select(static source =>
            (source.Repository, source.Tree)));
        var proposed = new RepositoryCiCandidateTreeIndexDocument(
            1,
            treeSetDigest,
            candidate.Digest,
            authorityEpoch,
            sequence);
        proposed.Validate();
        var key = TreeIndex(treeSetDigest);
        var existing = await ledger.GetAsync(key, cancellationToken);
        if (existing is not null) return CompareTreeIndex(existing, proposed);
        if (!authorityStillValid()) return new(RepositoryCiCandidateJournalDisposition.StaleAuthority);
        try
        {
            await ledger.CreateAsync(key, SerializeTreeIndex(proposed), cancellationToken);
            return new(RepositoryCiCandidateJournalDisposition.Recorded);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("A concurrently committed candidate tree index disappeared.");
            return CompareTreeIndex(observed, proposed);
        }
    }

    private async Task<RepositoryCiCandidateJournalReceipt> EnsureLifecycleAsync(
        RepositoryCiCandidate candidate,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var createdAt = timeProvider.GetUtcNow().ToUniversalTime();
        var proposed = RepositoryCiCandidateLifecycleDocument.Active(
            candidate.Digest,
            createdAt,
            candidate.CandidateRetentionDays,
            authorityEpoch,
            sequence);
        proposed.Validate();
        var key = LifecycleIndex(candidate.Digest);
        var existing = await ledger.GetAsync(key, cancellationToken);
        if (existing is not null)
        {
            var observed = DeserializeLifecycle(existing.Value);
            return CompareLifecycle(candidate, observed);
        }
        if (!authorityStillValid()) return new(RepositoryCiCandidateJournalDisposition.StaleAuthority);
        try
        {
            await ledger.CreateAsync(key, SerializeLifecycle(proposed), cancellationToken);
            return new(RepositoryCiCandidateJournalDisposition.Recorded);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("A concurrently committed candidate lifecycle disappeared.");
            var document = DeserializeLifecycle(observed.Value);
            return CompareLifecycle(candidate, document);
        }
    }

    private static RepositoryCiCandidateJournalReceipt CompareLifecycle(
        RepositoryCiCandidate candidate,
        RepositoryCiCandidateLifecycleDocument lifecycle)
    {
        if (lifecycle.CandidateDigest != candidate.Digest)
            return new(RepositoryCiCandidateJournalDisposition.IdentityConflict);
        if (lifecycle.RetainUntilUtc != lifecycle.CreatedAtUtc.AddDays(candidate.CandidateRetentionDays))
            throw new InvalidDataException("A candidate lifecycle differs from its immutable candidate.");
        return new(lifecycle.State is RepositoryCiCandidateLifecycleState.Active or
            RepositoryCiCandidateLifecycleState.QualificationPrepared or
            RepositoryCiCandidateLifecycleState.Qualified
                ? RepositoryCiCandidateJournalDisposition.Duplicate
                : RepositoryCiCandidateJournalDisposition.IdentityConflict);
    }

    private Task<RepositoryCiCandidateJournalReceipt> PrepareQualificationAsync(
        RepositoryCiQualifiedCandidate qualified,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken) => TransitionQualificationAsync(
        qualified,
        RepositoryCiCandidateLifecycleState.QualificationPrepared,
        authorityEpoch,
        sequence,
        authorityStillValid,
        cancellationToken);

    private Task<RepositoryCiCandidateJournalReceipt> CompleteQualificationAsync(
        RepositoryCiQualifiedCandidate qualified,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken) => TransitionQualificationAsync(
        qualified,
        RepositoryCiCandidateLifecycleState.Qualified,
        authorityEpoch,
        sequence,
        authorityStillValid,
        cancellationToken);

    private async Task<RepositoryCiCandidateJournalReceipt> TransitionQualificationAsync(
        RepositoryCiQualifiedCandidate qualified,
        RepositoryCiCandidateLifecycleState target,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var key = LifecycleIndex(qualified.Candidate.Digest);
        var entry = await ledger.GetAsync(key, cancellationToken)
            ?? throw new InvalidDataException("Qualification requires a durable candidate lifecycle.");
        var observed = DeserializeLifecycle(entry.Value);
        if (observed.CandidateDigest != qualified.Candidate.Digest ||
            observed.QualifiedDigest is not null && observed.QualifiedDigest != qualified.Digest)
            return new(RepositoryCiCandidateJournalDisposition.IdentityConflict);
        if ((target == RepositoryCiCandidateLifecycleState.QualificationPrepared &&
                observed.State is RepositoryCiCandidateLifecycleState.QualificationPrepared or
                    RepositoryCiCandidateLifecycleState.Qualified) ||
            (target == RepositoryCiCandidateLifecycleState.Qualified &&
                observed.State == RepositoryCiCandidateLifecycleState.Qualified))
            return new(RepositoryCiCandidateJournalDisposition.Duplicate);
        var expected = target switch
        {
            RepositoryCiCandidateLifecycleState.QualificationPrepared =>
                RepositoryCiCandidateLifecycleState.Active,
            RepositoryCiCandidateLifecycleState.Qualified =>
                RepositoryCiCandidateLifecycleState.QualificationPrepared,
            _ => throw new ArgumentOutOfRangeException(nameof(target)),
        };
        if (observed.State != expected)
            return new(RepositoryCiCandidateJournalDisposition.IdentityConflict);
        if (!authorityStillValid()) return new(RepositoryCiCandidateJournalDisposition.StaleAuthority);
        var proposed = observed with
        {
            State = target,
            QualifiedDigest = qualified.Digest,
            AuthorityEpoch = authorityEpoch,
            Sequence = sequence,
        };
        proposed.Validate();
        try
        {
            await ledger.UpdateAsync(key, SerializeLifecycle(proposed), entry.Revision, cancellationToken);
            return new(RepositoryCiCandidateJournalDisposition.Recorded);
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var concurrent = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("A candidate lifecycle disappeared during qualification.");
            var document = DeserializeLifecycle(concurrent.Value);
            return new(document.CandidateDigest == qualified.Candidate.Digest &&
                document.QualifiedDigest == qualified.Digest &&
                (document.State == target || target == RepositoryCiCandidateLifecycleState.QualificationPrepared &&
                    document.State == RepositoryCiCandidateLifecycleState.Qualified)
                    ? RepositoryCiCandidateJournalDisposition.Duplicate
                    : RepositoryCiCandidateJournalDisposition.IdentityConflict);
        }
    }

    private async Task<RepositoryCiCandidateLifecycleDocument?> ReadLifecycleAsync(
        RepositoryCiCandidate candidate,
        bool required,
        CancellationToken cancellationToken)
    {
        var entry = await ledger.GetAsync(LifecycleIndex(candidate.Digest), cancellationToken);
        if (entry is null)
        {
            if (required) throw new InvalidDataException("A durable candidate lost its lifecycle record.");
            return null;
        }
        var lifecycle = DeserializeLifecycle(entry.Value);
        if (lifecycle.CandidateDigest != candidate.Digest ||
            lifecycle.RetainUntilUtc != lifecycle.CreatedAtUtc.AddDays(candidate.CandidateRetentionDays))
            throw new InvalidDataException("A candidate lifecycle differs from its immutable candidate.");
        return lifecycle;
    }

    private async Task<RepositoryCiCandidate?> ReadCandidateCoreAsync(
        string digest,
        bool required,
        CancellationToken cancellationToken)
    {
        ValidateDigest(digest, nameof(digest));
        var pointer = await ReadPointerAsync(RepositoryCiCandidateRecordKind.Candidate, digest, cancellationToken);
        if (pointer is null)
        {
            if (required) throw new InvalidDataException("The required durable candidate does not exist.");
            return null;
        }
        var content = await ReadContentAsync(pointer, cancellationToken);
        var document = DeserializeCandidate(content);
        if (document.SchemaVersion != 2 || document.Digest != digest ||
            document.CandidateDigest != pointer.CandidateDigest)
            throw new InvalidDataException("The candidate object differs from its durable pointer.");
        return RepositoryCiCandidateAssembler.Restore(
            document.Digest,
            document.Pipeline,
            document.PipelineDigest,
            document.ImpactDigest,
            document.CandidateRetentionDays,
            document.Sources,
            document.Jobs,
            document.Artifacts);
    }

    private async Task<RepositoryCiCandidatePointerDocument?> ReadPointerAsync(
        RepositoryCiCandidateRecordKind kind,
        string digest,
        CancellationToken cancellationToken)
    {
        var entry = await ledger.GetAsync(Index(kind, digest), cancellationToken);
        if (entry is null) return null;
        var document = DeserializePointer(entry.Value);
        if (document.Kind != kind || document.IdentityDigest != digest)
            throw new InvalidDataException("A candidate journal index changed identity.");
        return document;
    }

    private async Task<byte[]> ReadContentAsync(
        RepositoryCiCandidatePointerDocument pointer,
        CancellationToken cancellationToken)
    {
        var content = await objects.GetAsync(pointer.ObjectName, cancellationToken);
        if (content.Length is < 1 or > MaximumCandidateBytes ||
            Convert.ToHexStringLower(SHA256.HashData(content)) != pointer.ContentDigest)
            throw new InvalidDataException("A persisted candidate object failed integrity verification.");
        return content;
    }

    private static RepositoryCiCandidateJournalReceipt Compare(
        ForgejoDeliveryLedgerEntry entry,
        RepositoryCiCandidatePointerDocument proposed)
    {
        var observed = DeserializePointer(entry.Value);
        return new(observed.SameIdentity(proposed)
            ? RepositoryCiCandidateJournalDisposition.Duplicate
            : RepositoryCiCandidateJournalDisposition.IdentityConflict);
    }

    private static RepositoryCiCandidateJournalReceipt CompareTreeIndex(
        ForgejoDeliveryLedgerEntry entry,
        RepositoryCiCandidateTreeIndexDocument proposed)
    {
        var observed = DeserializeTreeIndex(entry.Value);
        return new(observed.TreeSetDigest == proposed.TreeSetDigest &&
            observed.CandidateDigest == proposed.CandidateDigest
                ? RepositoryCiCandidateJournalDisposition.Duplicate
                : RepositoryCiCandidateJournalDisposition.IdentityConflict);
    }

    private static byte[] SerializeCandidate(RepositoryCiCandidate candidate)
    {
        var document = RepositoryCiCandidateObjectDocument.From(candidate);
        _ = RepositoryCiCandidateAssembler.Restore(
            document.Digest,
            document.Pipeline,
            document.PipelineDigest,
            document.ImpactDigest,
            document.CandidateRetentionDays,
            document.Sources,
            document.Jobs,
            document.Artifacts);
        return JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateObjectDocument);
    }

    private static byte[] SerializeQualified(RepositoryCiQualifiedCandidate qualified)
    {
        var document = RepositoryCiQualifiedObjectDocument.From(qualified);
        _ = RepositoryCiCandidateResolver.Restore(document.Digest, qualified.Candidate, document.Sources);
        return JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiQualifiedObjectDocument);
    }

    private static RepositoryCiCandidateObjectDocument DeserializeCandidate(byte[] content)
    {
        try
        {
            return JsonSerializer.Deserialize(
                content,
                RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateObjectDocument)
                ?? throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A persisted candidate object is invalid.", exception);
        }
    }

    private static RepositoryCiQualifiedObjectDocument DeserializeQualified(byte[] content)
    {
        try
        {
            return JsonSerializer.Deserialize(
                content,
                RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiQualifiedObjectDocument)
                ?? throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A persisted qualified candidate object is invalid.", exception);
        }
    }

    private static RepositoryCiCandidatePointerDocument DeserializePointer(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidatePointerDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A candidate journal pointer is invalid.", exception);
        }
    }

    private static RepositoryCiCandidateTreeIndexDocument DeserializeTreeIndex(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateTreeIndexDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A candidate tree-set index is invalid.", exception);
        }
    }

    private static RepositoryCiCandidateLifecycleDocument DeserializeLifecycle(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateLifecycleDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A candidate lifecycle is invalid.", exception);
        }
    }

    private static string SerializePointer(RepositoryCiCandidatePointerDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidatePointerDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes)
            throw new InvalidDataException("The candidate journal pointer exceeded its bound.");
        return value;
    }

    private static string SerializeTreeIndex(RepositoryCiCandidateTreeIndexDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateTreeIndexDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes)
            throw new InvalidDataException("The candidate tree-set index exceeded its bound.");
        return value;
    }

    private static string SerializeLifecycle(RepositoryCiCandidateLifecycleDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiCandidateJournalJsonContext.Default.RepositoryCiCandidateLifecycleDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes)
            throw new InvalidDataException("The candidate lifecycle exceeded its bound.");
        return value;
    }

    private static string Index(RepositoryCiCandidateRecordKind kind, string digest) =>
        $"ci-{kind.ToString().ToLowerInvariant()}.{digest}";

    private static string TreeIndex(string treeSetDigest) => $"ci-tree-set.{treeSetDigest}";

    private static string LifecycleIndex(string candidateDigest) => $"ci-candidate-lifecycle.{candidateDigest}";

    internal static string TreeSetDigest(IEnumerable<(string Repository, string Tree)> sources)
    {
        var value = new StringBuilder();
        foreach (var source in sources.OrderBy(static source => source.Repository, StringComparer.Ordinal))
            value.Append(source.Repository).Append(':').Append(source.Tree.ToLowerInvariant()).Append('\n');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    private static bool IsObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F') &&
        value.Any(static character => character != '0');

    private static void ValidateDigest(string? value, string parameter) =>
        _ = value is { Length: 64 } &&
            value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
            value.Any(static character => character != '0')
            ? true
            : throw new ArgumentException("Candidate digest is invalid.", parameter);
}

internal enum RepositoryCiCandidateRecordKind
{
    Unspecified,
    Candidate,
    Qualified,
}

internal enum RepositoryCiCandidateLifecycleState
{
    Unspecified,
    Active,
    QualificationPrepared,
    Qualified,
    DeletionPrepared,
    Deleted,
}

internal sealed record RepositoryCiCandidateLifecycleDocument(
    int SchemaVersion,
    string CandidateDigest,
    RepositoryCiCandidateLifecycleState State,
    string? QualifiedDigest,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset RetainUntilUtc,
    long AuthorityEpoch,
    long Sequence)
{
    internal static RepositoryCiCandidateLifecycleDocument Active(
        string candidateDigest,
        DateTimeOffset createdAtUtc,
        int retentionDays,
        long authorityEpoch,
        long sequence) => new(
        1,
        candidateDigest,
        RepositoryCiCandidateLifecycleState.Active,
        null,
        createdAtUtc,
        createdAtUtc.AddDays(retentionDays),
        authorityEpoch,
        sequence);

    internal void Validate()
    {
        var duration = RetainUntilUtc - CreatedAtUtc;
        var qualifiedState = State is RepositoryCiCandidateLifecycleState.QualificationPrepared or
            RepositoryCiCandidateLifecycleState.Qualified;
        if (SchemaVersion != 1 || !Digest(CandidateDigest) ||
            State is RepositoryCiCandidateLifecycleState.Unspecified ||
            qualifiedState != (QualifiedDigest is not null) ||
            QualifiedDigest is not null && !Digest(QualifiedDigest) ||
            CreatedAtUtc.Offset != TimeSpan.Zero || RetainUntilUtc.Offset != TimeSpan.Zero ||
            duration.Ticks < TimeSpan.TicksPerDay || duration.Ticks > 30 * TimeSpan.TicksPerDay ||
            duration.Ticks % TimeSpan.TicksPerDay != 0 || AuthorityEpoch <= 0 || Sequence <= 0)
            throw new InvalidDataException("A candidate lifecycle is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiCandidatePointerDocument(
    int SchemaVersion,
    RepositoryCiCandidateRecordKind Kind,
    string IdentityDigest,
    string CandidateDigest,
    string ContentDigest,
    string ObjectName,
    long AuthorityEpoch,
    long Sequence)
{
    internal static RepositoryCiCandidatePointerDocument From(
        RepositoryCiCandidateRecordKind kind,
        string identityDigest,
        string candidateDigest,
        string contentDigest,
        long authorityEpoch,
        long sequence) => new(
            1,
            kind,
            identityDigest,
            candidateDigest,
            contentDigest,
            $"ci-{kind.ToString().ToLowerInvariant()}-{identityDigest}-{contentDigest}",
            authorityEpoch,
            sequence);

    internal bool SameIdentity(RepositoryCiCandidatePointerDocument other) =>
        Kind == other.Kind && IdentityDigest == other.IdentityDigest &&
        CandidateDigest == other.CandidateDigest && ContentDigest == other.ContentDigest &&
        ObjectName == other.ObjectName;

    internal void Validate()
    {
        if (SchemaVersion != 1 || Kind is not (RepositoryCiCandidateRecordKind.Candidate or
                RepositoryCiCandidateRecordKind.Qualified) || !Digest(IdentityDigest) ||
            !Digest(CandidateDigest) || !Digest(ContentDigest) || AuthorityEpoch <= 0 || Sequence <= 0 ||
            ObjectName != $"ci-{Kind.ToString().ToLowerInvariant()}-{IdentityDigest}-{ContentDigest}")
            throw new InvalidDataException("A candidate journal pointer is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiCandidateTreeIndexDocument(
    int SchemaVersion,
    string TreeSetDigest,
    string CandidateDigest,
    long AuthorityEpoch,
    long Sequence)
{
    internal void Validate()
    {
        if (SchemaVersion != 1 || !Digest(TreeSetDigest) || !Digest(CandidateDigest) ||
            AuthorityEpoch <= 0 || Sequence <= 0)
            throw new InvalidDataException("A candidate tree-set index is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal sealed record RepositoryCiCandidateObjectDocument(
    int SchemaVersion,
    string Digest,
    string CandidateDigest,
    string Pipeline,
    string PipelineDigest,
    string ImpactDigest,
    int CandidateRetentionDays,
    RepositoryCiCandidateSource[] Sources,
    RepositoryCiJobResult[] Jobs,
    RepositoryCiArtifactResult[] Artifacts)
{
    internal static RepositoryCiCandidateObjectDocument From(RepositoryCiCandidate candidate) => new(
        2,
        candidate.Digest,
        candidate.Digest,
        candidate.Pipeline.Value,
        candidate.PipelineDigest,
        candidate.ImpactDigest,
        candidate.CandidateRetentionDays,
        candidate.Sources.ToArray(),
        candidate.Jobs.ToArray(),
        candidate.Artifacts.ToArray());
}

internal sealed record RepositoryCiQualifiedObjectDocument(
    int SchemaVersion,
    string Digest,
    string CandidateDigest,
    RepositoryCiQualifiedSource[] Sources)
{
    internal static RepositoryCiQualifiedObjectDocument From(RepositoryCiQualifiedCandidate qualified) => new(
        1,
        qualified.Digest,
        qualified.Candidate.Digest,
        qualified.Sources.ToArray());
}

[JsonSerializable(typeof(RepositoryCiCandidatePointerDocument))]
[JsonSerializable(typeof(RepositoryCiCandidateTreeIndexDocument))]
[JsonSerializable(typeof(RepositoryCiCandidateLifecycleDocument))]
[JsonSerializable(typeof(RepositoryCiCandidateObjectDocument))]
[JsonSerializable(typeof(RepositoryCiQualifiedObjectDocument))]
internal sealed partial class RepositoryCiCandidateJournalJsonContext : JsonSerializerContext;
