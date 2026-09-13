using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Authority;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record RegionalAuthoritySnapshot(
    string State,
    bool IsLeader,
    long Epoch,
    long KvRevision,
    DateTimeOffset? LeaseExpiresAt,
    DateTimeOffset ObservedAt,
    string? Error)
{
    public bool Ready =>
        State is "leader" or "follower" &&
        Error is null &&
        ObservedAt >= DateTimeOffset.UtcNow.AddSeconds(-30) &&
        LeaseExpiresAt > DateTimeOffset.UtcNow;
}

internal sealed record RegionalAuthorityLeaseDocument(
    int SchemaVersion,
    string AuthorityId,
    long Epoch,
    string CandidateId,
    string LeaseId,
    DateTimeOffset IssuedAt,
    long DurationMilliseconds)
{
    public static RegionalAuthorityLeaseDocument From(
        string authorityId,
        long epoch,
        AuthorityLease lease) =>
        new(1, authorityId, epoch, lease.CandidateId, lease.LeaseId,
            lease.ServerIssuedAt, checked((long)lease.Duration.TotalMilliseconds));

    public AuthorityLease ToLease()
    {
        Validate();
        return new(CandidateId, LeaseId, IssuedAt, TimeSpan.FromMilliseconds(DurationMilliseconds));
    }

    public void Validate()
    {
        if (SchemaVersion != 1 || string.IsNullOrWhiteSpace(AuthorityId) || Epoch <= 0 ||
            string.IsNullOrWhiteSpace(CandidateId) || string.IsNullOrWhiteSpace(LeaseId) ||
            DurationMilliseconds is < 1 or > 60_000 ||
            IssuedAt == default || IssuedAt > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new InvalidOperationException("The regional authority lease document is invalid.");
        }
    }
}

internal sealed class RegionalAuthorityCoordinator : IAsyncDisposable
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(3);

    private readonly INatsKVStore store;
    private readonly string authorityId;
    private readonly string candidateId;
    private readonly string leaseKey;
    private readonly bool tolerateTransientFailures;
    private readonly Stopwatch confirmedLeaseAge = new();
    private readonly CancellationTokenSource stopping = new();
    // Keep only the current pure-engine state. Replaying an unbounded renewal
    // journal every tick grows to tens of thousands of SHA-256 validations and
    // eventually makes lease readiness fail after multi-hour lab uptime.
    private AuthorityState journalState = AuthorityState.Empty;
    private Task? loop;
    private RegionalAuthoritySnapshot snapshot = new(
        "follower", false, 0, 0, null, DateTimeOffset.MinValue, "authority-not-observed");

    private RegionalAuthorityCoordinator(
        INatsKVStore store,
        string authorityId,
        string candidateId,
        string leaseKey,
        bool tolerateTransientFailures = false)
    {
        this.store = store;
        this.authorityId = authorityId;
        this.candidateId = candidateId;
        this.leaseKey = leaseKey;
        this.tolerateTransientFailures = tolerateTransientFailures;
    }

    public RegionalAuthoritySnapshot Snapshot => Volatile.Read(ref snapshot);

    public Task Completion => loop ?? Task.CompletedTask;

    public static async Task<RegionalAuthorityCoordinator> StartAsync(
        INatsKVStore store,
        string cell,
        string instance,
        CancellationToken cancellationToken)
    {
        var coordinator = new RegionalAuthorityCoordinator(
            store,
            $"{cell}-regional",
            $"{cell}-controller-{instance}",
            "authority.regional");
        await coordinator.TickAsync(cancellationToken);
        coordinator.loop = coordinator.RunAsync(coordinator.stopping.Token);
        return coordinator;
    }

    public static async Task<RegionalAuthorityCoordinator> StartGlobalAsync(
        INatsKVStore store,
        string cell,
        string instance,
        CancellationToken cancellationToken)
    {
        if (!GlobalNatsTopology.IsCellToken(cell))
            throw new ArgumentException("The global authority candidate cell is invalid.", nameof(cell));
        var coordinator = new RegionalAuthorityCoordinator(
            store,
            "global",
            $"global-controller-{cell}-{instance}",
            "authority.global",
            tolerateTransientFailures: true);
        await coordinator.TickAsync(cancellationToken);
        coordinator.loop = coordinator.RunAsync(coordinator.stopping.Token);
        return coordinator;
    }

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        if (loop is not null)
        {
            try
            {
                await loop;
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
            }
        }
        stopping.Dispose();
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TickInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            try
            {
                await TickAsync(cancellationToken);
            }
            catch (Exception exception) when (
                tolerateTransientFailures && IsTransient(exception))
            {
                var confirmed = journalState.Confirmed ?? new AuthorityObservation(
                    authorityId, 0, 0, "global-nats-unavailable", null);
                journalState = AuthorityState.Empty;
                confirmedLeaseAge.Reset();
                Publish(
                    "unavailable",
                    false,
                    confirmed,
                    "global-nats-unavailable",
                    DateTimeOffset.UtcNow);
            }
        }
    }

    private async Task TickAsync(CancellationToken cancellationToken)
    {
        var state = journalState;
        if (state.Status == AuthorityStatus.Leader && state.Confirmed is not null)
        {
            await RenewAsync(state.Confirmed, cancellationToken);
            return;
        }
        if (state.Status == AuthorityStatus.Fenced)
        {
            throw new InvalidOperationException("The regional authority candidate is fenced and must restart.");
        }

        var observed = await ReadAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (observed.Lease is not null &&
            observed.Lease.ServerIssuedAt + observed.Lease.Duration > now)
        {
            Publish("follower", false, observed, null, now);
            return;
        }

        var requestId = $"acquire-{Guid.NewGuid():N}";
        var health = Health(now, TimeSpan.Zero);
        var acquisition = AuthorityEngine.Decide(journalState, new AcquireAuthority(
            authorityId,
            candidateId,
            requestId,
            $"lease-{Guid.NewGuid():N}",
            observed,
            health,
            LeaseDuration));
        Apply(acquisition);
        if (acquisition.Intents.SingleOrDefault() is not CompareAndSetLeaseIntent intent)
        {
            PublishDecision(acquisition, observed, now);
            return;
        }

        await ExecuteSetAsync(intent, cancellationToken);
    }

    private async Task RenewAsync(
        AuthorityObservation current,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var requestId = $"renew-{Guid.NewGuid():N}";
        var renewal = AuthorityEngine.Decide(journalState, new RenewAuthority(
            authorityId,
            candidateId,
            requestId,
            current,
            Health(now, confirmedLeaseAge.Elapsed),
            LeaseDuration));
        Apply(renewal);
        if (renewal.Intents.SingleOrDefault() is not CompareAndSetLeaseIntent intent)
        {
            PublishDecision(renewal, current, now);
            return;
        }

        await ExecuteSetAsync(intent, cancellationToken);
    }

    private async Task ExecuteSetAsync(
        CompareAndSetLeaseIntent intent,
        CancellationToken cancellationToken)
    {
        try
        {
            var document = RegionalAuthorityLeaseDocument.From(
                authorityId,
                intent.ProposedEpoch,
                intent.ProposedLease);
            var value = JsonSerializer.Serialize(
                document,
                RegionalAuthorityLeaseJsonContext.Default.RegionalAuthorityLeaseDocument);
            var revision = intent.ExpectedRevision == 0
                ? await store.CreateAsync(leaseKey, value, cancellationToken: cancellationToken)
                : await store.UpdateAsync(
                    leaseKey,
                    value,
                    checked((ulong)intent.ExpectedRevision),
                    cancellationToken: cancellationToken);
            var observed = new AuthorityObservation(
                authorityId,
                checked((long)revision),
                intent.ProposedEpoch,
                $"kv-{revision}",
                intent.ProposedLease);
            var result = AuthorityEngine.Decide(journalState, new ObserveAuthorityCas(
                authorityId,
                candidateId,
                intent.RequestId,
                AuthorityCasOutcome.Succeeded,
                observed,
                Health(DateTimeOffset.UtcNow, TimeSpan.Zero)));
            Apply(result);
            if (result.State.Status == AuthorityStatus.Leader)
            {
                confirmedLeaseAge.Restart();
            }
            PublishDecision(result, observed, DateTimeOffset.UtcNow);
        }
        // NATS.Net may surface a simultaneous create loser as KeyNotFound while
        // resolving the failed create response. It is still a normal CAS conflict:
        // re-read the authoritative key and enter the follower path.
        catch (Exception exception) when (
            exception is NatsKVWrongLastRevisionException or NatsKVCreateException or NatsKVKeyNotFoundException)
        {
            var observed = await ReadAsync(cancellationToken);
            var result = AuthorityEngine.Decide(journalState, new ObserveAuthorityCas(
                authorityId,
                candidateId,
                intent.RequestId,
                AuthorityCasOutcome.Conflict,
                observed,
                Health(DateTimeOffset.UtcNow, TimeSpan.Zero)));
            Apply(result);
            // Losing a CAS is the normal follower path. It denies mutation
            // authority but does not make the read-serving controller unhealthy.
            Publish("follower", false, observed, null, DateTimeOffset.UtcNow);
        }
    }

    private async Task<AuthorityObservation> ReadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var entry = await store.GetEntryAsync<string>(leaseKey, cancellationToken: cancellationToken);
            entry.EnsureSuccess();
            var document = JsonSerializer.Deserialize(
                entry.Value ?? throw new InvalidOperationException("The regional authority lease is empty."),
                RegionalAuthorityLeaseJsonContext.Default.RegionalAuthorityLeaseDocument)
                ?? throw new InvalidOperationException("The regional authority lease is empty.");
            document.Validate();
            if (document.AuthorityId != authorityId)
            {
                throw new InvalidOperationException("The regional authority lease belongs to another cell.");
            }
            return new AuthorityObservation(
                authorityId,
                checked((long)entry.Revision),
                document.Epoch,
                $"kv-{entry.Revision}",
                document.ToLease());
        }
        catch (NatsKVKeyNotFoundException)
        {
            return new AuthorityObservation(authorityId, 0, 0, "kv-absent", null);
        }
    }

    internal static AuthorityHealth Health(DateTimeOffset now, TimeSpan confirmedLeaseAge) =>
        new(now, confirmedLeaseAge, PartitionCertain: true, ClockCertain: true);

    private static bool IsTransient(Exception exception) =>
        exception is NatsException or NatsJSApiNoResponseException or NatsJSTimeoutException or
            NatsJSConnectionException;

    private void Apply(AuthorityDecision decision)
    {
        if (decision.EventsToAppend.Count != 0)
        {
            journalState = decision.State;
        }
    }

    private void PublishDecision(
        AuthorityDecision decision,
        AuthorityObservation observed,
        DateTimeOffset now)
    {
        var state = decision.State;
        var error = decision.Errors.Count == 0 ? null : decision.Errors[0].Code.ToString();
        Publish(
            state.Status == AuthorityStatus.Leader ? "leader" :
            state.Status == AuthorityStatus.Fenced ? "fenced" :
            state.Status == AuthorityStatus.ReadOnlyHeld ? "held" : "follower",
            state.Status == AuthorityStatus.Leader && decision.MutationPermit is not null,
            state.Confirmed ?? observed,
            error,
            now);
    }

    private void Publish(
        string state,
        bool isLeader,
        AuthorityObservation observed,
        string? error,
        DateTimeOffset now)
    {
        DateTimeOffset? expiresAt = observed.Lease is null
            ? null
            : observed.Lease.ServerIssuedAt + observed.Lease.Duration;
        Volatile.Write(ref snapshot, new RegionalAuthoritySnapshot(
            state,
            isLeader,
            observed.Epoch,
            observed.KvRevision,
            expiresAt,
            now,
            error));
    }
}

[JsonSerializable(typeof(RegionalAuthorityLeaseDocument))]
internal sealed partial class RegionalAuthorityLeaseJsonContext : JsonSerializerContext;

