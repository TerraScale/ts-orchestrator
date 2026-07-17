using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsSignedHandoffJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    StaleAuthority,
    StaleSourceRevision,
    StaleGeneration,
    GenerationConflict,
    ConcurrentUpdate,
}

internal sealed record NativeGitOpsPreparedCellSpec(
    string Cell,
    string PayloadSha256,
    string WireSha256,
    NativeGitOpsCellWireMessage Message);

internal sealed record NativeGitOpsPreparedHandoff(
    string Repository,
    string Branch,
    ulong SourceJournalRevision,
    long AuthorityEpoch,
    NativeGitOpsCellHandoffDescriptor Descriptor,
    IReadOnlyList<NativeGitOpsPreparedCellSpec> Cells,
    ulong JournalRevision);

internal sealed record NativeGitOpsSignedHandoffJournalReceipt(
    NativeGitOpsSignedHandoffJournalDisposition Disposition,
    NativeGitOpsPreparedHandoff? Handoff);

/// <summary>
/// Persists the exact signed CellSpec wire bytes before publication. A retry therefore reuses the
/// original randomized signature and message body instead of assigning one message ID to new bytes.
/// </summary>
internal sealed class NativeGitOpsSignedHandoffJournal(
    IForgejoDeliveryLedger ledger,
    IDeliveryObjectStore objects)
{
    internal const int MaximumPointerBytes = 16 * 1024;
    private const int MaximumWireObjectBytes = 2 * NativeGitOpsCellWireCodec.MaximumWireBytes;

    internal async Task<NativeGitOpsPreparedHandoff?> ReadAsync(
        string repository,
        string branch,
        CancellationToken cancellationToken = default)
    {
        ValidateSource(repository, branch);
        var entry = await ledger.GetAsync(Index(repository, branch), cancellationToken);
        return entry is null ? null : await RestoreAsync(entry, repository, branch, cancellationToken);
    }

    internal async Task<NativeGitOpsSignedHandoffJournalReceipt> PrepareAsync(
        string branch,
        NativeGitOpsSourcePlan source,
        ulong sourceJournalRevision,
        long authorityEpoch,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        INativeGitOpsCellSpecSigner signer,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateSource(source.Revision.Repository, branch);
        if (sourceJournalRevision == 0) throw new ArgumentOutOfRangeException(nameof(sourceJournalRevision));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (issuedAt == default || expiresAt <= issuedAt)
            throw new ArgumentException("The native GitOps signed handoff validity window is invalid.");

        var handoff = NativeGitOpsCellSpecCompiler.Compile(source);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)
            ?? throw new InvalidDataException("The native GitOps handoff has no publishable regional cells.");
        var key = Index(source.Revision.Repository, branch);
        var existingEntry = await ledger.GetAsync(key, cancellationToken);
        NativeGitOpsPreparedHandoff? existing = null;
        if (existingEntry is not null)
        {
            existing = await RestoreAsync(
                existingEntry,
                source.Revision.Repository,
                branch,
                cancellationToken);
            var disposition = Compare(existing, descriptor, sourceJournalRevision, authorityEpoch);
            if (disposition is not null)
                return new(disposition.Value, existing);
        }
        if (!authorityStillValid())
            return new(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority, existing);

        var prepared = new List<PreparedWire>(handoff.Cells.Count);
        foreach (var cell in handoff.Cells)
        {
            if (!authorityStillValid())
                return new(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority, existing);
            var envelope = NativeGitOpsCellEnvelope.Sign(
                handoff,
                cell.Cell,
                authorityEpoch,
                issuedAt,
                expiresAt,
                signer);
            var wire = NativeGitOpsCellWireCodec.Encode(handoff, envelope);
            var content = SerializeWire(NativeGitOpsCellWireObject.From(cell.Cell, wire));
            prepared.Add(new(
                cell.Cell,
                cell.PayloadSha256,
                ComputeWireSha256(content),
                content));
        }

        foreach (var cell in prepared)
        {
            if (!authorityStillValid())
                return new(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority, existing);
            await objects.PutAsync(ObjectName(cell.WireSha256), cell.Content, cancellationToken);
            var readback = await objects.GetAsync(ObjectName(cell.WireSha256), cancellationToken);
            if (!readback.AsSpan().SequenceEqual(cell.Content))
                throw new InvalidDataException("A native GitOps signed CellSpec was not durable after storage.");
        }
        if (!authorityStillValid())
            return new(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority, existing);

        var document = NativeGitOpsSignedHandoffDocument.From(
            source.Revision.Repository,
            branch,
            sourceJournalRevision,
            authorityEpoch,
            descriptor,
            issuedAt,
            expiresAt,
            prepared);
        var value = SerializePointer(document);
        try
        {
            ForgejoDeliveryLedgerEntry committed;
            if (existing is null)
                committed = await ledger.CreateAsync(key, value, cancellationToken);
            else
                committed = await ledger.UpdateAsync(key, value, existing.JournalRevision, cancellationToken);
            return new(
                NativeGitOpsSignedHandoffJournalDisposition.Recorded,
                await RestoreAsync(committed, source.Revision.Repository, branch, cancellationToken));
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var winnerEntry = await ledger.GetAsync(key, cancellationToken);
            if (winnerEntry is null)
                return new(NativeGitOpsSignedHandoffJournalDisposition.ConcurrentUpdate, null);
            var winner = await RestoreAsync(
                winnerEntry,
                source.Revision.Repository,
                branch,
                cancellationToken);
            var disposition = Compare(winner, descriptor, sourceJournalRevision, authorityEpoch);
            return new(
                disposition ?? NativeGitOpsSignedHandoffJournalDisposition.ConcurrentUpdate,
                winner);
        }
    }

    private async Task<NativeGitOpsPreparedHandoff> RestoreAsync(
        ForgejoDeliveryLedgerEntry entry,
        string repository,
        string branch,
        CancellationToken cancellationToken)
    {
        var document = DeserializePointer(entry.Value);
        if (document.Repository != repository || document.Branch != branch)
            throw new InvalidDataException("A native GitOps signed handoff pointer changed source identity.");
        var descriptor = document.Descriptor();
        var cells = new List<NativeGitOpsPreparedCellSpec>(document.Cells.Count);
        foreach (var cell in document.Cells)
        {
            var content = await objects.GetAsync(ObjectName(cell.WireSha256), cancellationToken);
            if (content.Length is < 1 or > MaximumWireObjectBytes || Hash(content) != cell.WireSha256)
                throw new InvalidDataException("A persisted native GitOps signed CellSpec failed integrity verification.");
            var wireObject = DeserializeWire(content);
            if (wireObject.Cell != cell.Cell)
                throw new InvalidDataException("A native GitOps signed CellSpec changed cell identity.");
            var wire = wireObject.Message();
            var decoded = NativeGitOpsCellWireCodec.Decode(wire.Payload, wire.Headers);
            if (!Same(decoded.Handoff, descriptor) ||
                decoded.Envelope.Cell.Value != cell.Cell ||
                decoded.Envelope.WriterEpoch.Value != document.AuthorityEpoch ||
                !document.MatchesWindow(decoded.Envelope) ||
                Convert.ToHexStringLower(decoded.Envelope.PayloadDigest.Bytes) != cell.PayloadSha256)
                throw new InvalidDataException("A native GitOps signed CellSpec changed durable handoff identity.");
            cells.Add(new(cell.Cell, cell.PayloadSha256, cell.WireSha256, wire));
        }
        return new(
            document.Repository,
            document.Branch,
            document.SourceJournalRevision,
            document.AuthorityEpoch,
            descriptor,
            new ReadOnlyCollection<NativeGitOpsPreparedCellSpec>(cells.ToArray()),
            entry.Revision);
    }

    private static NativeGitOpsSignedHandoffJournalDisposition? Compare(
        NativeGitOpsPreparedHandoff current,
        NativeGitOpsCellHandoffDescriptor proposed,
        ulong sourceJournalRevision,
        long authorityEpoch)
    {
        if (authorityEpoch < current.AuthorityEpoch)
            return NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority;
        if (proposed.Generation < current.Descriptor.Generation)
            return NativeGitOpsSignedHandoffJournalDisposition.StaleGeneration;
        if (proposed.Generation == current.Descriptor.Generation && !Same(proposed, current.Descriptor))
            return NativeGitOpsSignedHandoffJournalDisposition.GenerationConflict;
        if (sourceJournalRevision < current.SourceJournalRevision ||
            proposed.Generation > current.Descriptor.Generation &&
            sourceJournalRevision == current.SourceJournalRevision)
            return NativeGitOpsSignedHandoffJournalDisposition.StaleSourceRevision;
        return proposed.Generation == current.Descriptor.Generation &&
            authorityEpoch == current.AuthorityEpoch
            ? NativeGitOpsSignedHandoffJournalDisposition.Duplicate
            : null;
    }

    private static bool Same(
        NativeGitOpsCellHandoffDescriptor left,
        NativeGitOpsCellHandoffDescriptor right) =>
        left.Generation == right.Generation &&
        left.GlobalPlanDigest == right.GlobalPlanDigest &&
        left.HandoffDigest == right.HandoffDigest &&
        left.Cells.SequenceEqual(right.Cells);

    private static byte[] SerializeWire(NativeGitOpsCellWireObject document)
    {
        document.Validate();
        var value = JsonSerializer.SerializeToUtf8Bytes(
            document,
            NativeGitOpsSignedHandoffJsonContext.Default.NativeGitOpsCellWireObject);
        if (value.Length > MaximumWireObjectBytes)
            throw new InvalidDataException("A native GitOps signed CellSpec object exceeded its bound.");
        return value;
    }

    private static NativeGitOpsCellWireObject DeserializeWire(byte[] value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsSignedHandoffJsonContext.Default.NativeGitOpsCellWireObject)
                ?? throw new JsonException();
            document.Validate();
            if (!value.AsSpan().SequenceEqual(SerializeWire(document))) throw new JsonException();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps signed CellSpec object is invalid.", exception);
        }
    }

    private static string SerializePointer(NativeGitOpsSignedHandoffDocument document)
    {
        document.Validate();
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsSignedHandoffJsonContext.Default.NativeGitOpsSignedHandoffDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumPointerBytes)
            throw new InvalidDataException("A native GitOps signed handoff pointer exceeded its bound.");
        return value;
    }

    private static NativeGitOpsSignedHandoffDocument DeserializePointer(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsSignedHandoffJsonContext.Default.NativeGitOpsSignedHandoffDocument)
                ?? throw new JsonException();
            document.Validate();
            if (value != SerializePointer(document)) throw new JsonException();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps signed handoff pointer is invalid.", exception);
        }
    }

    private static void ValidateSource(string repository, string branch)
    {
        if (!ForgejoWebhookVerifier.IsRepository(repository) || branch is not ("develop" or "main"))
            throw new ArgumentException("The native GitOps signed handoff source identity is invalid.");
    }

    private static string Index(string repository, string branch) => $"gitops.signed.{Hash(
        Encoding.UTF8.GetBytes($"native-gitops-signed:{repository}:{branch}"))}";

    private static string ObjectName(string digest) => $"native-gitops-cell-wire-{digest}";

    internal static string ComputeWireSha256(NativeGitOpsPreparedCellSpec prepared) =>
        ComputeWireSha256(SerializeWire(NativeGitOpsCellWireObject.From(prepared.Cell, prepared.Message)));

    private static string ComputeWireSha256(ReadOnlySpan<byte> content) => Hash(content);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    internal sealed record PreparedWire(
        string Cell,
        string PayloadSha256,
        string WireSha256,
        byte[] Content);
}

internal sealed record NativeGitOpsCellWireObject(
    int SchemaVersion,
    string Cell,
    string PayloadBase64,
    Dictionary<string, string> Headers)
{
    internal static NativeGitOpsCellWireObject From(string cell, NativeGitOpsCellWireMessage message) => new(
        1,
        cell,
        Convert.ToBase64String(message.Payload.Span),
        message.Headers.ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal));

    internal NativeGitOpsCellWireMessage Message() => new(
        Convert.FromBase64String(PayloadBase64),
        new ReadOnlyDictionary<string, string>(Headers));

    internal void Validate()
    {
        if (SchemaVersion != 1 || string.IsNullOrWhiteSpace(Cell) || Headers is not { Count: 16 })
            throw new InvalidDataException("A native GitOps signed CellSpec object is invalid.");
        try
        {
            var payload = Convert.FromBase64String(PayloadBase64);
            if (payload.Length is < 1 or > NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes ||
                Convert.ToBase64String(payload) != PayloadBase64)
                throw new InvalidDataException("A native GitOps signed CellSpec object is invalid.");
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A native GitOps signed CellSpec object is invalid.", exception);
        }
    }
}

internal sealed record NativeGitOpsSignedHandoffCellDocument(
    [property: JsonPropertyName("c")] string Cell,
    [property: JsonPropertyName("p")] string PayloadSha256,
    [property: JsonPropertyName("w")] string WireSha256);

internal sealed record NativeGitOpsSignedHandoffDocument(
    [property: JsonPropertyName("v")] int SchemaVersion,
    [property: JsonPropertyName("r")] string Repository,
    [property: JsonPropertyName("b")] string Branch,
    [property: JsonPropertyName("s")] ulong SourceJournalRevision,
    [property: JsonPropertyName("e")] long AuthorityEpoch,
    [property: JsonPropertyName("g")] long Generation,
    [property: JsonPropertyName("p")] string GlobalPlanDigest,
    [property: JsonPropertyName("h")] string HandoffDigest,
    [property: JsonPropertyName("i")] string IssuedAt,
    [property: JsonPropertyName("x")] string ExpiresAt,
    [property: JsonPropertyName("c")] IReadOnlyList<NativeGitOpsSignedHandoffCellDocument> Cells)
{
    internal static NativeGitOpsSignedHandoffDocument From(
        string repository,
        string branch,
        ulong sourceJournalRevision,
        long authorityEpoch,
        NativeGitOpsCellHandoffDescriptor handoff,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyList<NativeGitOpsSignedHandoffJournal.PreparedWire> cells) => new(
        1,
        repository,
        branch,
        sourceJournalRevision,
        authorityEpoch,
        handoff.Generation,
        handoff.GlobalPlanDigest,
        handoff.HandoffDigest,
        issuedAt.ToString("O", CultureInfo.InvariantCulture),
        expiresAt.ToString("O", CultureInfo.InvariantCulture),
        Array.AsReadOnly(cells.Select(static cell => new NativeGitOpsSignedHandoffCellDocument(
            cell.Cell,
            cell.PayloadSha256,
            cell.WireSha256)).ToArray()));

    internal NativeGitOpsCellHandoffDescriptor Descriptor() => new(
        Generation,
        GlobalPlanDigest,
        HandoffDigest,
        Array.AsReadOnly(Cells.Select(static cell =>
            new NativeGitOpsCellDigest(cell.Cell, cell.PayloadSha256)).ToArray()));

    internal bool MatchesWindow(Protocol.CommandEnvelope envelope) =>
        envelope.IssuedAt.ToString("O", CultureInfo.InvariantCulture) == IssuedAt &&
        envelope.ExpiresAt.ToString("O", CultureInfo.InvariantCulture) == ExpiresAt;

    internal void Validate()
    {
        var descriptor = Descriptor();
        var window = TryWindow(IssuedAt, out var issuedAt) && TryWindow(ExpiresAt, out var expiresAt) &&
            expiresAt > issuedAt;
        if (SchemaVersion != 1 || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            Branch is not ("develop" or "main") || SourceJournalRevision == 0 || AuthorityEpoch <= 0 ||
            !window ||
            !NativeGitOpsCellEnvelope.IsValidDescriptor(descriptor) ||
            Cells.Any(static cell => !Digest(cell.WireSha256)))
            throw new InvalidDataException("A native GitOps signed handoff pointer is invalid.");
    }

    private static bool TryWindow(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParseExact(
            value,
            "O",
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out parsed) && parsed.ToString("O", CultureInfo.InvariantCulture) == value;

    private static bool Digest(string value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(NativeGitOpsCellWireObject))]
[JsonSerializable(typeof(NativeGitOpsSignedHandoffDocument))]
internal sealed partial class NativeGitOpsSignedHandoffJsonContext : JsonSerializerContext;
