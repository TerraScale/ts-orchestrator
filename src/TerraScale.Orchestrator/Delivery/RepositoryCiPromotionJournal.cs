using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

public enum RepositoryCiPromotionPhase
{
    Unspecified,
    Authorized,
    PublishStarted,
    Published,
    SfoDeploymentStarted,
    SfoVerified,
    FraDeploymentStarted,
    FraVerified,
    GruDeploymentStarted,
    GruVerified,
    Completed,
    RollbackStarted,
    RollbackGruStarted,
    GruRolledBack,
    RollbackFraStarted,
    FraRolledBack,
    RollbackSfoStarted,
    SfoRolledBack,
    RolledBack,
}

public enum RepositoryCiPromotionJournalDisposition
{
    Unspecified,
    Acquired,
    Resumed,
    TakenOver,
    Advanced,
    Duplicate,
    StaleAuthority,
    LeaseHeld,
    StaleLease,
    AuthorizationConflict,
    PhaseConflict,
}

public sealed class RepositoryCiPromotionLease
{
    internal RepositoryCiPromotionLease(RepositoryCiPromotionJournalDocument document)
    {
        QualifiedDigest = document.QualifiedDigest;
        AuthorizationDigest = document.AuthorizationDigest;
        CandidateDigest = document.CandidateDigest;
        ControllerId = document.ControllerId;
        AuthorityEpoch = document.AuthorityEpoch;
        FencingToken = document.FencingToken;
        Phase = document.Phase;
        PhaseSequence = document.PhaseSequence;
        OperationId = document.OperationId;
        EvidenceDigest = document.EvidenceDigest;
    }

    public string QualifiedDigest { get; }
    public string AuthorizationDigest { get; }
    public string CandidateDigest { get; }
    public string ControllerId { get; }
    public long AuthorityEpoch { get; }
    public long FencingToken { get; }
    public RepositoryCiPromotionPhase Phase { get; }
    public long PhaseSequence { get; }
    public string OperationId { get; }
    public string EvidenceDigest { get; }
}

public sealed class RepositoryCiPromotionJournalReceipt
{
    internal RepositoryCiPromotionJournalReceipt(
        RepositoryCiPromotionJournalDisposition disposition,
        RepositoryCiPromotionJournalDocument document)
    {
        Disposition = disposition;
        Lease = new(document);
    }

    public RepositoryCiPromotionJournalDisposition Disposition { get; }
    public RepositoryCiPromotionLease Lease { get; }
    public bool CanContinue => Disposition is RepositoryCiPromotionJournalDisposition.Acquired or
        RepositoryCiPromotionJournalDisposition.Resumed or
        RepositoryCiPromotionJournalDisposition.TakenOver or
        RepositoryCiPromotionJournalDisposition.Advanced or
        RepositoryCiPromotionJournalDisposition.Duplicate;
}

/// <summary>Serializes one fenced writer and the recoverable phase of an exact qualified release set.</summary>
public sealed class RepositoryCiPromotionJournal
{
    private const int MaximumConflictRetries = 8;
    private readonly IForgejoDeliveryLedger ledger;

    internal RepositoryCiPromotionJournal(IForgejoDeliveryLedger ledger) => this.ledger = ledger;

    public async Task<RepositoryCiPromotionJournalReceipt> AcquireAsync(
        RepositoryCiPromotionAuthorization authorization,
        string controllerId,
        long authorityEpoch,
        CancellationToken cancellationToken = default)
    {
        ValidateAuthorization(authorization);
        if (!IsIdentity(controllerId)) throw new ArgumentException("Controller identity is invalid.", nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));

        var proposed = RepositoryCiPromotionJournalDocument.From(authorization, controllerId, authorityEpoch);
        proposed.Validate();
        var key = Index(proposed.QualifiedDigest);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var current = await ledger.GetAsync(key, cancellationToken);
            if (current is null)
            {
                try
                {
                    await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
                    return new(RepositoryCiPromotionJournalDisposition.Acquired, proposed);
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                    continue;
                }
            }

            var observed = Read(current);
            if (observed.QualifiedDigest != proposed.QualifiedDigest)
                throw new InvalidDataException("A promotion journal index changed release-set identity.");
            if (observed.AuthorizationDigest != proposed.AuthorizationDigest ||
                observed.CandidateDigest != proposed.CandidateDigest)
                return new(RepositoryCiPromotionJournalDisposition.AuthorizationConflict, observed);
            if (authorityEpoch < observed.AuthorityEpoch)
                return new(RepositoryCiPromotionJournalDisposition.StaleAuthority, observed);
            if (authorityEpoch == observed.AuthorityEpoch)
                return new(controllerId == observed.ControllerId
                    ? RepositoryCiPromotionJournalDisposition.Resumed
                    : RepositoryCiPromotionJournalDisposition.LeaseHeld, observed);

            RepositoryCiPromotionJournalDocument takeover;
            try
            {
                takeover = observed with
                {
                    ControllerId = controllerId,
                    AuthorityEpoch = authorityEpoch,
                    FencingToken = checked(observed.FencingToken + 1),
                };
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The promotion fencing token is exhausted.", exception);
            }
            takeover.Validate();
            try
            {
                await ledger.UpdateAsync(key, Serialize(takeover), current.Revision, cancellationToken);
                return new(RepositoryCiPromotionJournalDisposition.TakenOver, takeover);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        throw new InvalidOperationException("The promotion journal could not resolve concurrent lease acquisition.");
    }

    public async Task<RepositoryCiPromotionJournalReceipt> AdvanceAsync(
        RepositoryCiPromotionLease lease,
        RepositoryCiPromotionPhase nextPhase,
        string operationId,
        string evidenceDigest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (!Enum.IsDefined(nextPhase) || nextPhase == RepositoryCiPromotionPhase.Unspecified)
            throw new ArgumentOutOfRangeException(nameof(nextPhase));
        if (!IsIdentity(operationId)) throw new ArgumentException("Promotion operation identity is invalid.", nameof(operationId));
        if (!IsDigest(evidenceDigest)) throw new ArgumentException("Promotion evidence digest is invalid.", nameof(evidenceDigest));

        var key = Index(lease.QualifiedDigest);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var current = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The promotion journal lease disappeared.");
            var observed = Read(current);
            if (observed.QualifiedDigest != lease.QualifiedDigest ||
                observed.AuthorizationDigest != lease.AuthorizationDigest ||
                observed.CandidateDigest != lease.CandidateDigest ||
                observed.ControllerId != lease.ControllerId ||
                observed.AuthorityEpoch != lease.AuthorityEpoch ||
                observed.FencingToken != lease.FencingToken)
                return new(RepositoryCiPromotionJournalDisposition.StaleLease, observed);
            if (observed.Phase == nextPhase)
                return new(observed.OperationId == operationId && observed.EvidenceDigest == evidenceDigest
                    ? RepositoryCiPromotionJournalDisposition.Duplicate
                    : RepositoryCiPromotionJournalDisposition.PhaseConflict, observed);
            if (observed.Phase != lease.Phase || !IsTransitionAllowed(observed.Phase, nextPhase))
                return new(RepositoryCiPromotionJournalDisposition.PhaseConflict, observed);

            RepositoryCiPromotionJournalDocument advanced;
            try
            {
                advanced = observed with
                {
                    PreviousPhase = observed.Phase,
                    Phase = nextPhase,
                    PhaseSequence = checked(observed.PhaseSequence + 1),
                    OperationId = operationId,
                    EvidenceDigest = evidenceDigest,
                };
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The promotion phase sequence is exhausted.", exception);
            }
            advanced.Validate();
            try
            {
                await ledger.UpdateAsync(key, Serialize(advanced), current.Revision, cancellationToken);
                return new(RepositoryCiPromotionJournalDisposition.Advanced, advanced);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        throw new InvalidOperationException("The promotion journal could not resolve a concurrent phase update.");
    }

    internal static bool IsTransitionAllowed(RepositoryCiPromotionPhase current, RepositoryCiPromotionPhase next) =>
        (current, next) switch
        {
            (RepositoryCiPromotionPhase.Authorized, RepositoryCiPromotionPhase.PublishStarted) => true,
            (RepositoryCiPromotionPhase.PublishStarted, RepositoryCiPromotionPhase.Published) => true,
            (RepositoryCiPromotionPhase.Published, RepositoryCiPromotionPhase.SfoDeploymentStarted) => true,
            (RepositoryCiPromotionPhase.SfoDeploymentStarted, RepositoryCiPromotionPhase.SfoVerified) => true,
            (RepositoryCiPromotionPhase.SfoVerified, RepositoryCiPromotionPhase.FraDeploymentStarted) => true,
            (RepositoryCiPromotionPhase.FraDeploymentStarted, RepositoryCiPromotionPhase.FraVerified) => true,
            (RepositoryCiPromotionPhase.FraVerified, RepositoryCiPromotionPhase.GruDeploymentStarted) => true,
            (RepositoryCiPromotionPhase.GruDeploymentStarted, RepositoryCiPromotionPhase.GruVerified) => true,
            (RepositoryCiPromotionPhase.GruVerified, RepositoryCiPromotionPhase.Completed) => true,
            (RepositoryCiPromotionPhase.PublishStarted or RepositoryCiPromotionPhase.Published,
                RepositoryCiPromotionPhase.RollbackStarted) => true,
            (RepositoryCiPromotionPhase.RollbackStarted, RepositoryCiPromotionPhase.RolledBack) => true,
            (RepositoryCiPromotionPhase.SfoDeploymentStarted or RepositoryCiPromotionPhase.SfoVerified,
                RepositoryCiPromotionPhase.RollbackSfoStarted) => true,
            (RepositoryCiPromotionPhase.FraDeploymentStarted or RepositoryCiPromotionPhase.FraVerified,
                RepositoryCiPromotionPhase.RollbackFraStarted) => true,
            (RepositoryCiPromotionPhase.GruDeploymentStarted or RepositoryCiPromotionPhase.GruVerified,
                RepositoryCiPromotionPhase.RollbackGruStarted) => true,
            (RepositoryCiPromotionPhase.RollbackGruStarted, RepositoryCiPromotionPhase.GruRolledBack) => true,
            (RepositoryCiPromotionPhase.GruRolledBack, RepositoryCiPromotionPhase.RollbackFraStarted) => true,
            (RepositoryCiPromotionPhase.RollbackFraStarted, RepositoryCiPromotionPhase.FraRolledBack) => true,
            (RepositoryCiPromotionPhase.FraRolledBack, RepositoryCiPromotionPhase.RollbackSfoStarted) => true,
            (RepositoryCiPromotionPhase.RollbackSfoStarted, RepositoryCiPromotionPhase.SfoRolledBack) => true,
            (RepositoryCiPromotionPhase.SfoRolledBack, RepositoryCiPromotionPhase.RolledBack) => true,
            _ => false,
        };

    private static void ValidateAuthorization(RepositoryCiPromotionAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        if (!IsDigest(authorization.Digest) || authorization.Id != $"promotion-{authorization.Digest}" ||
            authorization.Qualified is null || !IsDigest(authorization.Qualified.Digest) ||
            authorization.Qualified.Id != $"qualified-{authorization.Qualified.Digest}" ||
            authorization.Qualified.Candidate is null || !IsDigest(authorization.Qualified.Candidate.Digest) ||
            authorization.Job is null || authorization.Job.Idempotency?.Value != $"promotion-{authorization.Digest}" ||
            authorization.Job.Generation <= 0)
            throw new InvalidDataException("The promotion authorization is invalid.");
    }

    private static RepositoryCiPromotionJournalDocument Read(ForgejoDeliveryLedgerEntry entry)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                entry.Value,
                RepositoryCiPromotionJournalJsonContext.Default.RepositoryCiPromotionJournalDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A promotion journal record is invalid.", exception);
        }
    }

    private static string Serialize(RepositoryCiPromotionJournalDocument document) => JsonSerializer.Serialize(
        document,
        RepositoryCiPromotionJournalJsonContext.Default.RepositoryCiPromotionJournalDocument);

    private static string Index(string qualifiedDigest) => $"promotion.{qualifiedDigest}";

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool IsIdentity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}

internal sealed record RepositoryCiPromotionJournalDocument(
    int SchemaVersion,
    string QualifiedDigest,
    string AuthorizationDigest,
    string CandidateDigest,
    string ControllerId,
    long AuthorityEpoch,
    long FencingToken,
    RepositoryCiPromotionPhase PreviousPhase,
    RepositoryCiPromotionPhase Phase,
    long PhaseSequence,
    string OperationId,
    string EvidenceDigest)
{
    internal static RepositoryCiPromotionJournalDocument From(
        RepositoryCiPromotionAuthorization authorization,
        string controllerId,
        long authorityEpoch) => new(
            1,
            authorization.Qualified.Digest,
            authorization.Digest,
            authorization.Qualified.Candidate.Digest,
            controllerId,
            authorityEpoch,
            1,
            RepositoryCiPromotionPhase.Unspecified,
            RepositoryCiPromotionPhase.Authorized,
            0,
            authorization.Id,
            authorization.Digest);

    internal void Validate()
    {
        if (SchemaVersion != 1 || !Digest(QualifiedDigest) || !Digest(AuthorizationDigest) ||
            !Digest(CandidateDigest) || !Identity(ControllerId) || AuthorityEpoch <= 0 ||
            FencingToken <= 0 || !Enum.IsDefined(Phase) || Phase == RepositoryCiPromotionPhase.Unspecified ||
            !Enum.IsDefined(PreviousPhase) || PhaseSequence < 0 || PhaseSequence > 64 ||
            !Identity(OperationId) || !Digest(EvidenceDigest) ||
            (Phase == RepositoryCiPromotionPhase.Authorized &&
                (PreviousPhase != RepositoryCiPromotionPhase.Unspecified || PhaseSequence != 0)) ||
            (Phase != RepositoryCiPromotionPhase.Authorized &&
                (PreviousPhase == RepositoryCiPromotionPhase.Unspecified || PhaseSequence == 0 ||
                    !RepositoryCiPromotionJournal.IsTransitionAllowed(PreviousPhase, Phase))))
            throw new InvalidDataException("A promotion journal record is invalid.");
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}

[JsonSerializable(typeof(RepositoryCiPromotionJournalDocument))]
internal sealed partial class RepositoryCiPromotionJournalJsonContext : JsonSerializerContext;
