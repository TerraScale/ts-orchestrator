using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

/// <summary>
/// The operator's member-lifecycle intent for one database, stored in
/// <c>ORCH_DELIVERY</c> under <c>placement.intent.{database}</c>. Per-Region seat
/// count is fixed by <see cref="DatabasePlacementPolicy.ActiveReplicationFactor"/>
/// — exactly two seats per active Region — so the intent carries only the active
/// Region set; the reconciler derives every seat from it.
/// </summary>
internal sealed record PlacementIntentDocument(
    int SchemaVersion,
    string Database,
    string[] ActiveRegions,
    string PartitionId,
    long Revision)
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumDatabaseNameLength = 63;

    public static string Key(string database) => $"placement.intent.{database}";

    /// <summary>
    /// Structural validity only: the database placement evaluator re-derives and
    /// re-validates the full placement every tick, so a stored document that is
    /// structurally sound but semantically wrong (an unknown or duplicate Region)
    /// reaches the evaluator and is refused there — with zero mutations.
    /// </summary>
    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            !IsValidDatabaseName(Database) ||
            ActiveRegions is not { Length: >= DatabasePlacementPolicy.MinimumActiveRegionCount } ||
            ActiveRegions.Length > DatabasePlacementPolicy.MaximumActiveRegionCount ||
            ActiveRegions.Any(static region => string.IsNullOrWhiteSpace(region)) ||
            string.IsNullOrWhiteSpace(PartitionId) || PartitionId.Length > MaximumDatabaseNameLength ||
            Revision < 1)
            throw new InvalidOperationException("The placement intent document is invalid.");
    }

    /// <summary>
    /// Admission-time validation for the writer: Regions must be canonical
    /// (<c>GRU</c>/<c>SFO</c>/<c>FRA</c>) and unique — an operator never stores a
    /// document the evaluator would refuse.
    /// </summary>
    public void ValidateAdmission()
    {
        Validate();
        if (ActiveRegions.Any(static region => !IsValidRegion(region)) ||
            ActiveRegions.Distinct(StringComparer.Ordinal).Count() != ActiveRegions.Length)
            throw new InvalidOperationException("The placement intent Regions must be unique canonical Region codes.");
    }

    /// <summary>A database name is a bounded lowercase DNS-style token (the edge placement name format).</summary>
    internal static bool IsValidDatabaseName(string? value) =>
        value is { Length: >= 1 and <= MaximumDatabaseNameLength } &&
        char.IsAsciiLetterLower(value[0]) && char.IsAsciiLetterOrDigit(value[^1]) &&
        value.All(static character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character == '-');

    private static bool IsValidRegion(string? value) =>
        RegionCode.TryCreate(value, out _);
}

/// <summary>
/// The durable per-member execution state, stored in <c>ORCH_DELIVERY</c> under
/// <c>placement.state.{database}.{member}</c>. The stage ladder mirrors the
/// <c>ScaleOutState</c>/<c>ScaleInState</c> compute contracts: one reconciler
/// step advances it by at most one stage per tick, leader-gated and CAS-written.
/// </summary>
internal sealed record PlacementMemberStateDocument(
    int SchemaVersion,
    string Database,
    string MemberId,
    string Region,
    string MemberKind,
    string Stage,
    string? InstanceId,
    string? ETag,
    long HostSequence,
    long IntentRevision,
    string? Trace,
    DateTimeOffset UpdatedAt)
{
    public const int CurrentSchemaVersion = 1;

    public static string Key(string database, string member) => $"placement.state.{database}.{member}";

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            !PlacementIntentDocument.IsValidDatabaseName(Database) ||
            string.IsNullOrWhiteSpace(MemberId) ||
            !TerraBaseRegionCode.TryCreate(Region, out _) ||
            PlacementTopology.KindOf(MemberId) == TerraBaseMemberKind.Unknown ||
            !Stages.Contains(Stage, StringComparer.Ordinal) ||
            RevisionInvalid(HostSequence) || RevisionInvalid(IntentRevision))
            throw new InvalidOperationException("The placement member state document is invalid.");
    }

    /// <summary>The closed stage vocabulary, in ladder order.</summary>
    public static readonly IReadOnlyList<string> Stages =
    [
        StageProvisioning,
        StageAwaitingHealthy,
        StageServing,
        StageReplacing,
        StageRemoveCandidate,
        StageCordoned,
        StageDraining,
        StageDrained,
        StageDeregistered,
        StageStorageHandled,
        StageRevoked,
        StageTerminated,
        StageRemoved
    ];

    public const string StageProvisioning = "provisioning";
    public const string StageAwaitingHealthy = "awaiting-healthy";
    public const string StageServing = "serving";
    public const string StageReplacing = "replacing";
    public const string StageRemoveCandidate = "remove-candidate";
    public const string StageCordoned = "cordoned";
    public const string StageDraining = "draining";
    public const string StageDrained = "drained";
    public const string StageDeregistered = "deregistered";
    public const string StageStorageHandled = "storage-handled";
    public const string StageRevoked = "revoked";
    public const string StageTerminated = "terminated";
    public const string StageRemoved = "removed";

    /// <summary>True while the member sits in an execution ladder this reconciler still drives.</summary>
    public bool InFlight => Stage is StageProvisioning or StageAwaitingHealthy or StageReplacing or
        StageRemoveCandidate or StageCordoned or StageDraining or StageDrained or StageDeregistered or
        StageStorageHandled or StageRevoked or StageTerminated;

    public bool InRemovalLadder => Stage is StageRemoveCandidate or StageCordoned or StageDraining or
        StageDrained or StageDeregistered or StageStorageHandled or StageRevoked or StageTerminated;

    private static bool RevisionInvalid(long value) => value < 1;
}

/// <summary>
/// The durable per-member volume identity, stored in <c>ORCH_DELIVERY</c> under
/// <c>placement.volume.{database}.{member}</c>. The strictly-increasing
/// <see cref="WriterEpoch"/> is the writer fence: a replacement reattaches the
/// SAME volume at <c>WriterEpoch + 1</c>, never a new volume, and the CAS write
/// makes the advance single-writer.
/// </summary>
internal sealed record PlacementVolumeStateDocument(
    int SchemaVersion,
    string Database,
    string MemberId,
    string ProviderVolumeId,
    string AttachmentId,
    ulong WriterEpoch,
    string Disposition,
    DateTimeOffset UpdatedAt)
{
    public const int CurrentSchemaVersion = 1;
    public const string RetainedStateful = "retained-stateful";

    public static string Key(string database, string member) => $"placement.volume.{database}.{member}";

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            !PlacementIntentDocument.IsValidDatabaseName(Database) ||
            string.IsNullOrWhiteSpace(MemberId) ||
            string.IsNullOrWhiteSpace(ProviderVolumeId) ||
            string.IsNullOrWhiteSpace(AttachmentId) ||
            WriterEpoch < 1 ||
            !string.Equals(Disposition, RetainedStateful, StringComparison.Ordinal))
            throw new InvalidOperationException("The placement volume state document is invalid.");
    }
}

/// <summary>
/// The per-tick reconciler status published to <c>ORCH_RUNTIME</c> under
/// <c>placement.reconciler.{cell}</c>: what the leader observed, which database
/// and member it acted on, and the first error of the pass.
/// </summary>
internal sealed record PlacementTickObservation(
    int SchemaVersion,
    string Cell,
    string State,
    string? Database,
    string? Member,
    string? Action,
    string? Error,
    long Revision,
    DateTimeOffset ObservedAt)
{
    public const int CurrentSchemaVersion = 1;

    public static string Key(string cell) => $"placement.reconciler.{cell}";

    public const string StateNotLeader = "not-leader";
    public const string StateAuthorityLost = "authority-lost";
    public const string StateIdle = "idle";
    public const string StateRejected = "rejected";
    public const string StateHeld = "held";
    public const string StateTransferWait = "transfer-wait";
    public const string StateError = "error";
}

/// <summary>The pure derivation from one placement intent to its desired member seats.</summary>
internal static class PlacementTopology
{
    /// <summary>The canonical Region order: permanent member assignment and seat ordering derive from it.</summary>
    public static readonly IReadOnlyList<RegionCode> CanonicalRegions =
        [RegionCode.Gru, RegionCode.Sfo, RegionCode.Fra];

    /// <summary>One desired member seat: its stable member id, Region, kind, and failure domain.</summary>
    internal sealed record DesiredSeat(string MemberId, RegionCode Region, TerraBaseMemberKind Kind, string FailureDomain);

    /// <summary>
    /// The permanent member id and kind of one Region: <c>PermanentA/B/C</c> map to
    /// <c>GRU/SFO/FRA</c> and never leave their Region; they are never removable.
    /// </summary>
    public static string PermanentMember(RegionCode region) => region switch
    {
        var value when value == RegionCode.Gru => "permanent-a",
        var value when value == RegionCode.Sfo => "permanent-b",
        var value when value == RegionCode.Fra => "permanent-c",
        _ => throw new ArgumentOutOfRangeException(nameof(region), region.Value, "Unknown canonical Region."),
    };

    /// <summary>The elastic member id of one Region: exactly one elastic seat per active Region.</summary>
    public static string ElasticMember(RegionCode region) =>
        $"elastic-{region.Value.ToLowerInvariant()}";

    public static TerraBaseMemberKind KindOf(string memberId) => memberId switch
    {
        "permanent-a" => TerraBaseMemberKind.PermanentA,
        "permanent-b" => TerraBaseMemberKind.PermanentB,
        "permanent-c" => TerraBaseMemberKind.PermanentC,
        _ => memberId.StartsWith("elastic-", StringComparison.Ordinal)
            ? TerraBaseMemberKind.Elastic
            : TerraBaseMemberKind.Unknown,
    };

    /// <summary>Every desired seat of one intent: permanent first, elastic second, in canonical Region order.</summary>
    public static IReadOnlyList<DesiredSeat> Seats(PlacementIntentDocument intent)
    {
        intent.Validate();
        var seats = new List<DesiredSeat>();
        foreach (var region in CanonicalRegions)
        {
            if (!intent.ActiveRegions.Contains(region.Value, StringComparer.Ordinal))
                continue;
            var lower = region.Value.ToLowerInvariant();
            seats.Add(new(PermanentMember(region), region, KindOf(PermanentMember(region)), $"{lower}-fd0"));
            seats.Add(new(ElasticMember(region), region, TerraBaseMemberKind.Elastic, $"{lower}-fd1"));
        }
        return seats;
    }

    /// <summary>Assembles the exact <see cref="DatabasePlacementRequest"/> the evaluator re-validates every tick.</summary>
    public static DatabasePlacementRequest ToPlacementRequest(PlacementIntentDocument intent)
    {
        intent.Validate();
        var partition = new PartitionId(intent.PartitionId);
        // The Region set travels exactly as written — duplicates and unknown codes
        // included — so the evaluator, never this projection, is the refusing gate.
        var active = intent.ActiveRegions
            .Select(static region => RegionCode.TryCreate(region, out var code) ? code : default)
            .ToList();
        var placements = new List<PartitionRegionPlacement>();
        foreach (var region in CanonicalRegions)
        {
            if (!intent.ActiveRegions.Contains(region.Value, StringComparer.Ordinal))
                continue;
            var lower = region.Value.ToLowerInvariant();
            placements.Add(new(region, new ActiveMemberSeat[]
            {
                new(new(PermanentMember(region)), region, partition, new($"{lower}-fd0")),
                new(new(ElasticMember(region)), region, partition, new($"{lower}-fd1")),
            }));
        }
        return new(active, [new LogicalPartitionPlacement(partition, placements)], null);
    }
}

/// <summary>Validated, monotonic, compare-and-set writes of placement intents.</summary>
internal static class PlacementIntentStore
{
    /// <summary>
    /// Writes one intent: <c>Create</c> when the database has none, otherwise a
    /// revision-checked <c>Update</c> — a revision that does not strictly advance the
    /// stored one is refused. The write is single-key CAS, so two operators racing
    /// converge on exactly one winner.
    /// </summary>
    public static async Task<string> ApplyAsync(
        INatsKVStore delivery,
        PlacementIntentDocument intent,
        CancellationToken cancellationToken)
    {
        intent.ValidateAdmission();
        var key = PlacementIntentDocument.Key(intent.Database);
        var json = JsonSerializer.Serialize(intent, TerraBasePlacementJsonContext.Default.PlacementIntentDocument);
        try
        {
            await delivery.CreateAsync(key, json, cancellationToken: cancellationToken).ConfigureAwait(false);
            return "created";
        }
        catch (NatsKVCreateException)
        {
        }
        NatsKVEntry<string> entry;
        try
        {
            entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
        }
        catch (Exception exception) when (
            exception is NatsKVKeyDeletedException or
                NatsKVException)
        {
            throw new InvalidOperationException("The stored placement intent could not be read for the revision check.");
        }
        var existing = JsonSerializer.Deserialize(
            entry.Value ?? string.Empty, TerraBasePlacementJsonContext.Default.PlacementIntentDocument);
        if (existing is null)
            throw new InvalidDataException("The stored placement intent document is invalid.");
        existing.Validate();
        if (intent.Revision <= existing.Revision)
            throw new ArgumentException(
                $"The placement intent revision must advance the stored revision {existing.Revision}.");
        await delivery.UpdateAsync(key, json, entry.Revision, cancellationToken: cancellationToken).ConfigureAwait(false);
        return "updated";
    }
}

[JsonSerializable(typeof(PlacementIntentDocument))]
[JsonSerializable(typeof(PlacementMemberStateDocument))]
[JsonSerializable(typeof(PlacementVolumeStateDocument))]
[JsonSerializable(typeof(PlacementTickObservation))]
internal sealed partial class TerraBasePlacementJsonContext : JsonSerializerContext;
