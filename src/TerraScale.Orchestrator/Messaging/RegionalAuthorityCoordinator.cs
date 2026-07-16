using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    private const string LeaseKey = "authority.regional";
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(3);

    private readonly INatsKVStore store;
    private readonly string authorityId;
    private readonly string candidateId;
    private readonly Stopwatch confirmedLeaseAge = new();
    private readonly CancellationTokenSource stopping = new();
    private readonly List<AuthorityEvent> history = [];
    private Task? loop;
    private RegionalAuthoritySnapshot snapshot = new(
        "follower", false, 0, 0, null, DateTimeOffset.MinValue, "authority-not-observed");

    private RegionalAuthorityCoordinator(INatsKVStore store, string cell, string instance)
    {
        this.store = store;
        authorityId = $"{cell}-regional";
        candidateId = $"{cell}-controller-{instance}";
    }

    public RegionalAuthoritySnapshot Snapshot => Volatile.Read(ref snapshot);

    public Task Completion => loop ?? Task.CompletedTask;

    public static async Task<RegionalAuthorityCoordinator> StartAsync(
        INatsKVStore store,
        string cell,
        string instance,
        CancellationToken cancellationToken)
    {
        var coordinator = new RegionalAuthorityCoordinator(store, cell, instance);
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
            await TickAsync(cancellationToken);
        }
    }

    private async Task TickAsync(CancellationToken cancellationToken)
    {
        var state = AuthorityEngine.Replay(history).State;
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
        var acquisition = AuthorityEngine.Decide(history, new AcquireAuthority(
            authorityId,
            candidateId,
            requestId,
            $"lease-{Guid.NewGuid():N}",
            observed,
            health,
            LeaseDuration));
        Append(acquisition);
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
        var renewal = AuthorityEngine.Decide(history, new RenewAuthority(
            authorityId,
            candidateId,
            requestId,
            current,
            Health(now, confirmedLeaseAge.Elapsed),
            LeaseDuration));
        Append(renewal);
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
                ? await store.CreateAsync(LeaseKey, value, cancellationToken: cancellationToken)
                : await store.UpdateAsync(
                    LeaseKey,
                    value,
                    checked((ulong)intent.ExpectedRevision),
                    cancellationToken: cancellationToken);
            var observed = new AuthorityObservation(
                authorityId,
                checked((long)revision),
                intent.ProposedEpoch,
                $"kv-{revision}",
                intent.ProposedLease);
            var result = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
                authorityId,
                candidateId,
                intent.RequestId,
                AuthorityCasOutcome.Succeeded,
                observed,
                Health(DateTimeOffset.UtcNow, TimeSpan.Zero)));
            Append(result);
            if (result.State.Status == AuthorityStatus.Leader)
            {
                confirmedLeaseAge.Restart();
            }
            PublishDecision(result, observed, DateTimeOffset.UtcNow);
        }
        catch (Exception exception) when (
            exception is NatsKVWrongLastRevisionException or NatsKVCreateException)
        {
            var observed = await ReadAsync(cancellationToken);
            var result = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
                authorityId,
                candidateId,
                intent.RequestId,
                AuthorityCasOutcome.Conflict,
                observed,
                Health(DateTimeOffset.UtcNow, TimeSpan.Zero)));
            Append(result);
            // Losing a CAS is the normal follower path. It denies mutation
            // authority but does not make the read-serving controller unhealthy.
            Publish("follower", false, observed, null, DateTimeOffset.UtcNow);
        }
    }

    private async Task<AuthorityObservation> ReadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var entry = await store.GetEntryAsync<string>(LeaseKey, cancellationToken: cancellationToken);
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

    private void Append(AuthorityDecision decision)
    {
        history.AddRange(decision.EventsToAppend);
    }

    private void PublishDecision(
        AuthorityDecision decision,
        AuthorityObservation observed,
        DateTimeOffset now)
    {
        var state = decision.State;
        var error = decision.Errors.FirstOrDefault()?.Code.ToString();
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
