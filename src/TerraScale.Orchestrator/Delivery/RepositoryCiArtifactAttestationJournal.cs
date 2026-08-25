using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiArtifactAttestationJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    IdentityConflict,
    StaleAuthority,
}

internal enum RepositoryCiArtifactProofKind
{
    Unspecified,
    ArtifactSignature,
    RuntimeObservation,
}

/// <summary>
/// Stores signed proof bytes by content and commits one fenced CAS pointer for each exact artifact
/// subject. The original randomized signature must be replayed; a replacement never overwrites it.
/// </summary>
internal sealed class RepositoryCiArtifactAttestationJournal(
    IForgejoDeliveryLedger ledger,
    IDeliveryObjectStore objects,
    int proofHistoryCap = 8192,
    int pruneInterval = 64)
{
    private const int MaximumPointerBytes = 8 * 1024;
    private const int MaximumProofBytes = 64 * 1024;
    private readonly IForgejoDeliveryLedger ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
    private readonly IDeliveryObjectStore objects = objects ?? throw new ArgumentNullException(nameof(objects));

    internal Task<RepositoryCiArtifactAttestationJournalDisposition> RecordArtifactAsync(
        RepositoryCiSignedArtifact artifact,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        if (!RepositoryCiArtifactAttestation.StructurallyValid(artifact))
            throw new ArgumentException("The signed artifact proof is invalid.", nameof(artifact));
        return RecordAsync(
            RepositoryCiArtifactProofKind.ArtifactSignature,
            RepositoryCiArtifactAttestation.SubjectDigest(artifact.Subject),
            Serialize(RepositoryCiArtifactProofDocument.From(artifact)),
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
    }

    internal Task<RepositoryCiArtifactAttestationJournalDisposition> RecordRuntimeAsync(
        RepositoryCiSignedRuntimeObservation runtime,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        if (!RepositoryCiArtifactAttestation.StructurallyValid(runtime) ||
            runtime.ObservedRuntimeDigest != runtime.Subject.Digest)
            throw new ArgumentException("The signed runtime proof is invalid.", nameof(runtime));
        return RecordAsync(
            RepositoryCiArtifactProofKind.RuntimeObservation,
            RepositoryCiArtifactAttestation.SubjectDigest(runtime.Subject),
            Serialize(RepositoryCiArtifactProofDocument.From(runtime)),
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
    }

    internal async Task<RepositoryCiSignedArtifact?> ReadArtifactAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken = default)
    {
        var document = await ReadAsync(
            RepositoryCiArtifactProofKind.ArtifactSignature,
            subject,
            cancellationToken);
        return document?.Artifact();
    }

    internal async Task<RepositoryCiSignedRuntimeObservation?> ReadRuntimeAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken = default)
    {
        var document = await ReadAsync(
            RepositoryCiArtifactProofKind.RuntimeObservation,
            subject,
            cancellationToken);
        return document?.Runtime();
    }

    /// <summary>The authority epoch of the durable artifact-signature pointer, or -1 when absent.</summary>
    internal async Task<long> ReadArtifactAuthorityEpochAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken = default)
    {
        var entry = await ledger.GetAsync(
            Index(RepositoryCiArtifactProofKind.ArtifactSignature,
                RepositoryCiArtifactAttestation.SubjectDigest(subject)),
            cancellationToken);
        return entry is null
            ? -1
            : DeserializePointer(entry.Value).AuthorityEpoch;
    }

    private async Task<RepositoryCiArtifactAttestationJournalDisposition> RecordAsync(
        RepositoryCiArtifactProofKind kind,
        string subjectDigest,
        byte[] content,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (content.Length is < 1 or > MaximumProofBytes)
            throw new InvalidDataException("The artifact proof exceeds its durable bound.");
        var contentDigest = Hash(content);
        var proposed = new RepositoryCiArtifactProofPointerDocument(
            1,
            kind,
            subjectDigest,
            contentDigest,
            ObjectName(contentDigest),
            authorityEpoch,
            sequence);
        proposed.Validate();
        var key = Index(kind, subjectDigest);
        var existing = await ledger.GetAsync(key, cancellationToken);
        if (existing is not null) return Compare(existing, proposed);
        if (!authorityStillValid()) return RepositoryCiArtifactAttestationJournalDisposition.StaleAuthority;

        await objects.PutAsync(proposed.ObjectName, content, cancellationToken);
        var readback = await objects.GetAsync(proposed.ObjectName, cancellationToken);
        if (!readback.AsSpan().SequenceEqual(content))
            throw new InvalidDataException("The artifact proof was not durable after storage.");
        if (!authorityStillValid()) return RepositoryCiArtifactAttestationJournalDisposition.StaleAuthority;
        try
        {
            await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
            await PruneAsync(cancellationToken).ConfigureAwait(false);
            return RepositoryCiArtifactAttestationJournalDisposition.Recorded;
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var observed = await ledger.GetAsync(key, cancellationToken) ??
                throw new InvalidDataException("A concurrent artifact proof pointer disappeared.");
            return Compare(observed, proposed);
        }
    }

    /// <summary>
    /// Bounded oldest-first proof-pointer retention. Pruning a
    /// pointer deletes its proof object with it; a later gate run for the same exact subject
    /// re-derives and re-records the proof (signatures are subject-bound, not content history).
    /// </summary>
    private async Task PruneAsync(CancellationToken cancellationToken)
    {
        if (ledger is not IForgejoDeliveryRetentionLedger retention) return;
        // The configured interval is an optimization hint only; skipping a scan would permit
        // the durable proof-key count to exceed the declared cap.
        _ = pruneInterval;
        await DeliveryJournalRetention.PruneAsync(
            retention,
            "ci-artifact-proof.",
            proofHistoryCap,
            (entry, _, _) => Task.FromResult(new DeliveryJournalPruneDecision(
                true,
                DeserializePointer(entry.Value).ObjectName)),
            "artifact proof pointers",
            cancellationToken,
            objects as IDeliveryRetentionObjectStore).ConfigureAwait(false);
    }

    private async Task<RepositoryCiArtifactProofDocument?> ReadAsync(
        RepositoryCiArtifactProofKind kind,
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken)
    {
        var subjectDigest = RepositoryCiArtifactAttestation.SubjectDigest(subject);
        var entry = await ledger.GetAsync(Index(kind, subjectDigest), cancellationToken);
        if (entry is null) return null;
        var pointer = DeserializePointer(entry.Value);
        if (pointer.Kind != kind || pointer.SubjectDigest != subjectDigest)
            throw new InvalidDataException("An artifact proof pointer changed identity.");
        var content = await objects.GetAsync(pointer.ObjectName, cancellationToken);
        if (content.Length is < 1 or > MaximumProofBytes || Hash(content) != pointer.ContentDigest)
            throw new InvalidDataException("A durable artifact proof failed integrity verification.");
        var document = DeserializeProof(content);
        if (document.Kind != kind || document.Subject.Value() != subject ||
            !content.AsSpan().SequenceEqual(Serialize(document)))
            throw new InvalidDataException("A durable artifact proof changed its canonical subject.");
        return document;
    }

    private static RepositoryCiArtifactAttestationJournalDisposition Compare(
        ForgejoDeliveryLedgerEntry entry,
        RepositoryCiArtifactProofPointerDocument proposed)
    {
        var observed = DeserializePointer(entry.Value);
        return observed.Kind == proposed.Kind && observed.SubjectDigest == proposed.SubjectDigest &&
            observed.ContentDigest == proposed.ContentDigest
                ? RepositoryCiArtifactAttestationJournalDisposition.Duplicate
                : RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict;
    }

    internal static byte[] Serialize(RepositoryCiArtifactProofDocument document) =>
        JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiArtifactAttestationJournalJsonContext.Default.RepositoryCiArtifactProofDocument);

    private static string Serialize(RepositoryCiArtifactProofPointerDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiArtifactAttestationJournalJsonContext.Default.RepositoryCiArtifactProofPointerDocument);
        if (value.Length is < 2 or > MaximumPointerBytes)
            throw new InvalidDataException("The artifact proof pointer exceeds its bound.");
        return value;
    }

    internal static RepositoryCiArtifactProofDocument DeserializeProof(byte[] content)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                content,
                RepositoryCiArtifactAttestationJournalJsonContext.Default.RepositoryCiArtifactProofDocument) ??
                throw new JsonException();
            document.Validate();
            return document;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidDataException)
        {
            throw new InvalidDataException("A durable artifact proof is invalid.", exception);
        }
    }

    private static RepositoryCiArtifactProofPointerDocument DeserializePointer(string content)
    {
        try
        {
            if (content.Length is < 2 or > MaximumPointerBytes) throw new JsonException();
            var document = JsonSerializer.Deserialize(
                content,
                RepositoryCiArtifactAttestationJournalJsonContext.Default.RepositoryCiArtifactProofPointerDocument) ??
                throw new JsonException();
            document.Validate();
            if (Serialize(document) != content) throw new JsonException();
            return document;
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            throw new InvalidDataException("A durable artifact proof pointer is invalid.", exception);
        }
    }

    private static string Index(RepositoryCiArtifactProofKind kind, string subjectDigest) =>
        $"ci-artifact-proof.{(int)kind}.{subjectDigest}";

    private static string ObjectName(string contentDigest) => $"ci-artifact-proof-{contentDigest}";

    private static string Hash(ReadOnlySpan<byte> content) =>
        Convert.ToHexStringLower(SHA256.HashData(content));
}

/// <summary>Canonical bounded wire representation for one independently signed native observation.</summary>
internal static class RepositoryCiRuntimeObservationWireCodec
{
    internal const int MaximumWireBytes = 64 * 1024;

    internal static byte[] Encode(RepositoryCiSignedRuntimeObservation runtime)
    {
        if (!RepositoryCiArtifactAttestation.StructurallyValid(runtime) ||
            runtime.ObservedRuntimeDigest != runtime.Subject.Digest)
            throw new ArgumentException("The native runtime observation is invalid.", nameof(runtime));
        var content = RepositoryCiArtifactAttestationJournal.Serialize(
            RepositoryCiArtifactProofDocument.From(runtime));
        if (content.Length is < 2 or > MaximumWireBytes)
            throw new InvalidDataException("The native runtime observation exceeds its wire bound.");
        return content;
    }

    internal static RepositoryCiSignedRuntimeObservation Decode(ReadOnlySpan<byte> content)
    {
        if (content.Length is < 2 or > MaximumWireBytes)
            throw new InvalidDataException("The native runtime observation wire payload is invalid.");
        var bytes = content.ToArray();
        var document = RepositoryCiArtifactAttestationJournal.DeserializeProof(bytes);
        if (document.Kind != RepositoryCiArtifactProofKind.RuntimeObservation ||
            !bytes.AsSpan().SequenceEqual(RepositoryCiArtifactAttestationJournal.Serialize(document)))
            throw new InvalidDataException("The native runtime observation wire payload is not canonical.");
        return document.Runtime();
    }

    internal static string MessageId(RepositoryCiSignedRuntimeObservation runtime) =>
        $"ci-runtime-proof:{RepositoryCiArtifactAttestation.SubjectDigest(runtime.Subject)}:" +
        runtime.SignatureId.Value;
}

internal sealed record RepositoryCiArtifactProofSubjectDocument(
    string PipelineDigest,
    string Job,
    string Artifact,
    RepositoryCiArchitecture Architecture,
    string Digest,
    string EntrypointsDigest)
{
    internal static RepositoryCiArtifactProofSubjectDocument From(RepositoryCiArtifactSubject value) => new(
        value.PipelineDigest,
        value.Job.Value,
        value.Artifact.Value,
        value.Architecture,
        value.Digest.Value,
        value.EntrypointsDigest);

    internal RepositoryCiArtifactSubject Value() => new(
        PipelineDigest,
        new JobId(Job),
        new ArtifactId(Artifact),
        Architecture,
        new DigestId(Digest),
        EntrypointsDigest);
}

internal sealed record RepositoryCiArtifactProofDocument(
    int SchemaVersion,
    RepositoryCiArtifactProofKind Kind,
    RepositoryCiArtifactProofSubjectDocument Subject,
    string SigningIdentity,
    string ObservedRuntimeDigest,
    string SignatureId,
    byte[] Signature)
{
    internal static RepositoryCiArtifactProofDocument From(RepositoryCiSignedArtifact value) => new(
        1,
        RepositoryCiArtifactProofKind.ArtifactSignature,
        RepositoryCiArtifactProofSubjectDocument.From(value.Subject),
        value.SigningIdentity.Value,
        string.Empty,
        value.SignatureId.Value,
        value.Signature.Bytes.ToArray());

    internal static RepositoryCiArtifactProofDocument From(RepositoryCiSignedRuntimeObservation value) => new(
        1,
        RepositoryCiArtifactProofKind.RuntimeObservation,
        RepositoryCiArtifactProofSubjectDocument.From(value.Subject),
        value.RunnerIdentity,
        value.ObservedRuntimeDigest.Value,
        value.SignatureId.Value,
        value.Signature.Bytes.ToArray());

    internal RepositoryCiSignedArtifact Artifact()
    {
        if (!OpaqueSignature.TryCopyFrom(Signature, out var signature) || signature is null)
            throw new InvalidDataException("The artifact proof signature is missing.");
        return new(Subject.Value(), new(SigningIdentity), new(SignatureId), signature);
    }

    internal RepositoryCiSignedRuntimeObservation Runtime()
    {
        if (!OpaqueSignature.TryCopyFrom(Signature, out var signature) || signature is null)
            throw new InvalidDataException("The runtime proof signature is missing.");
        return new(
            Subject.Value(),
            SigningIdentity,
            new(ObservedRuntimeDigest),
            new(SignatureId),
            signature);
    }

    internal void Validate()
    {
        if (SchemaVersion != 1 || Subject is null || Signature is not { Length: > 0 and <=
                RepositoryCiArtifactAttestation.MaximumSignatureBytes } ||
            Kind == RepositoryCiArtifactProofKind.ArtifactSignature &&
                (!RepositoryCiArtifactAttestation.StructurallyValid(Artifact()) ||
                    ObservedRuntimeDigest.Length != 0) ||
            Kind == RepositoryCiArtifactProofKind.RuntimeObservation &&
                (!RepositoryCiArtifactAttestation.StructurallyValid(Runtime()) ||
                    Runtime().ObservedRuntimeDigest != Runtime().Subject.Digest) ||
            Kind is not (RepositoryCiArtifactProofKind.ArtifactSignature or
                RepositoryCiArtifactProofKind.RuntimeObservation))
            throw new InvalidDataException("The artifact proof document is invalid.");
    }
}

internal sealed record RepositoryCiArtifactProofPointerDocument(
    int SchemaVersion,
    RepositoryCiArtifactProofKind Kind,
    string SubjectDigest,
    string ContentDigest,
    string ObjectName,
    long AuthorityEpoch,
    long Sequence)
{
    internal void Validate()
    {
        if (SchemaVersion != 1 || Kind is not (RepositoryCiArtifactProofKind.ArtifactSignature or
                RepositoryCiArtifactProofKind.RuntimeObservation) || !Digest(SubjectDigest) ||
            !Digest(ContentDigest) || ObjectName != $"ci-artifact-proof-{ContentDigest}" ||
            AuthorityEpoch <= 0 || Sequence <= 0)
            throw new InvalidDataException("The artifact proof pointer is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(RepositoryCiArtifactProofDocument))]
[JsonSerializable(typeof(RepositoryCiArtifactProofPointerDocument))]
internal sealed partial class RepositoryCiArtifactAttestationJournalJsonContext : JsonSerializerContext;
