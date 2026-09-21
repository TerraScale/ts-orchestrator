using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal enum RegionalHostSessionDecision
{
    Accepted = 1, InvalidRequest, EnrollmentDenied, StaleGeneration, GenerationConflict,
    SessionHeld, SessionMismatch, LeaseExpired, StaleRequest, Revoked, InvalidStore,
    StoreUnavailable, Contention, ReplayCapacity
}

internal sealed record RegionalHostSessionResponse(int SchemaVersion, string RequestId, string RequestDigest,
    RegionalHostSessionDecision Decision, ulong Generation, ulong Epoch, DateTimeOffset? ExpiresAt)
{
    [JsonIgnore] public bool Accepted => Decision == RegionalHostSessionDecision.Accepted;

    internal void RequireBinding(RegionalHostSessionRequest request)
    {
        if (SchemaVersion != 2 || RequestId != request.RequestId || RequestDigest != request.RequestDigest ||
            Generation != request.Enrollment.BootstrapGeneration || !Enum.IsDefined(Decision) ||
            (Accepted
                ? Epoch == 0 || ExpiresAt != request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime ||
                    request.Operation == RegionalHostSessionOperation.Renew && Epoch != request.Epoch
                : Epoch != 0 || ExpiresAt is not null))
            throw new InvalidDataException("The controller session response is not bound to the exact request and lease.");
    }
}

internal sealed record RegionalHostConsumedGrant(string GrantId, string Nonce, DateTimeOffset ExpiresAt);

internal sealed record RegionalHostSessionRecord(int SchemaVersion, string Cell, string NodeId,
    ulong Generation, DateTimeOffset EnrolledAt, DateTimeOffset SessionStartedAt, string EnrollmentDigest, string GrantId, string Nonce, string SessionId, ulong Epoch,
    string RequestDigest, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, bool Revoked,
    IReadOnlyList<RegionalHostConsumedGrant> ConsumedGrants);

internal sealed record RegionalHostActionAuthorization(RegionalHostSessionDecision Decision, DateTimeOffset? ExpiresAt)
{
    internal bool Authorized => Decision == RegionalHostSessionDecision.Accepted;
}

/// <summary>
/// Controller-owned, durable node enrollment and process leases. Every transition uses a
/// single revision-checked record; no host opens this private KV store. Lease expiry fences
/// session authorization only. Guest workload stop/storage fencing must enforce it separately.
/// </summary>
internal sealed class RegionalHostSessionAuthority(INatsKVStore store, RegionalHostEnrollmentPolicy policy, TimeProvider? clock = null)
{
    internal static readonly TimeSpan LeaseLifetime = TimeSpan.FromSeconds(30);
    private const int MaximumConsumedGrants = 16;
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 16
    };
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    internal string Cell => policy.Cell;
    internal DateTimeOffset Now => time.GetUtcNow();
    internal static string Key(string nodeId) => "node-enrollment." +
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            RegionalNodeEnrollmentEnvelope.ValidateToken(nodeId, nameof(nodeId)))));

    internal async Task<RegionalHostSessionResponse> ProcessAsync(RegionalHostSessionRequest request, CancellationToken cancellationToken)
    {
        try
        {
            _ = request.Serialize(); // Enforce wire bounds for direct callers as well as broker ingress.
            if (!request.HasValidProof(Cell, time.GetUtcNow()) || request.IssuedAt > DateTimeOffset.MaxValue - LeaseLifetime)
                return Deny(request, RegionalHostSessionDecision.InvalidRequest);
            await ValidateStoreAsync(cancellationToken).ConfigureAwait(false);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var (current, revision) = await ReadAsync(request.Enrollment.NodeId, cancellationToken).ConfigureAwait(false);
                var now = time.GetUtcNow();
                if (!request.HasValidProof(Cell, now)) return Deny(request, RegionalHostSessionDecision.InvalidRequest);
                var enrollment = request.Enrollment;
                var continuing = current is not null && current.Generation == enrollment.BootstrapGeneration &&
                    current.EnrollmentDigest == request.EnrollmentDigest;
                var leaseExpiresAt = request.IssuedAt + LeaseLifetime;
                if (!(continuing ? policy.AllowsContinuingEnrollment(enrollment, now, leaseExpiresAt) : policy.AllowsFreshEnrollment(enrollment, now, leaseExpiresAt)))
                    return Deny(request, RegionalHostSessionDecision.EnrollmentDenied);
                var grant = enrollment.Grant.ParsePayload();
                if (continuing && (current!.EnrolledAt < grant.IssuedAt || current.EnrolledAt >= grant.ExpiresAt))
                    return Deny(request, RegionalHostSessionDecision.InvalidStore);
                if (current is not null && now < current.EnrolledAt)
                    return Deny(request, RegionalHostSessionDecision.StaleRequest);
                if (current is not null)
                {
                    if (enrollment.BootstrapGeneration < current.Generation)
                        return Deny(request, RegionalHostSessionDecision.StaleGeneration);
                    if (enrollment.BootstrapGeneration == current.Generation && !continuing)
                        return Deny(request, RegionalHostSessionDecision.GenerationConflict);
                    if (continuing && current.Revoked) return Deny(request, RegionalHostSessionDecision.Revoked);
                    if (continuing && current.RequestDigest == request.RequestDigest)
                    {
                        if (current.ExpiresAt <= now) return Deny(request, RegionalHostSessionDecision.LeaseExpired);
                        try
                        {
                            await ConfirmCurrentAsync(current, revision, cancellationToken).ConfigureAwait(false);
                            return current.ExpiresAt > time.GetUtcNow()
                                ? Accept(request, current)
                                : Deny(request, RegionalHostSessionDecision.LeaseExpired);
                        }
                        catch (NatsKVWrongLastRevisionException) { continue; }
                    }
                    if (request.IssuedAt <= current.IssuedAt)
                        return Deny(request, RegionalHostSessionDecision.StaleRequest);
                    if (!continuing && current.ConsumedGrants.Any(consumed =>
                            consumed.GrantId == grant.GrantId.Value || consumed.Nonce == grant.Nonce))
                        return Deny(request, RegionalHostSessionDecision.GenerationConflict);
                }

                ulong epoch;
                if (request.Operation == RegionalHostSessionOperation.Renew)
                {
                    if (!continuing || current!.SessionId != request.SessionId || current.Epoch != request.Epoch)
                        return Deny(request, RegionalHostSessionDecision.SessionMismatch);
                    if (current.ExpiresAt <= now) return Deny(request, RegionalHostSessionDecision.LeaseExpired);
                    epoch = current.Epoch;
                }
                else
                {
                    // A new process or credential generation never overlaps a live lease, even after revocation.
                    if (current is not null && current.ExpiresAt > now)
                        return Deny(request, RegionalHostSessionDecision.SessionHeld);
                    epoch = checked((current?.Epoch ?? 0) + 1);
                }

                var consumedGrants = continuing ? current!.ConsumedGrants :
                    (current?.ConsumedGrants ?? []).Where(consumed => consumed.ExpiresAt > request.IssuedAt).ToArray();
                if (!continuing)
                {
                    if (consumedGrants.Count >= MaximumConsumedGrants)
                        return Deny(request, RegionalHostSessionDecision.ReplayCapacity);
                    consumedGrants = [.. consumedGrants, new(grant.GrantId.Value, grant.Nonce, grant.ExpiresAt)];
                }
                var candidate = new RegionalHostSessionRecord(2, Cell, enrollment.NodeId,
                    enrollment.BootstrapGeneration, continuing ? current!.EnrolledAt : now,
                    request.Operation == RegionalHostSessionOperation.Renew ? current!.SessionStartedAt : now,
                    request.EnrollmentDigest, grant.GrantId.Value, grant.Nonce,
                    request.SessionId, epoch, request.RequestDigest, request.IssuedAt,
                    request.IssuedAt + LeaseLifetime, Revoked: false, consumedGrants);
                try
                {
                    // Revision zero is create-if-absent. NATS CreateAsync may resurrect a tombstone;
                    // direct CAS must instead fail if any prior record or tombstone won the race.
                    await store.UpdateAsync(Key(enrollment.NodeId),
                        JsonSerializer.Serialize(candidate, JsonOptions), revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                    return candidate.ExpiresAt > time.GetUtcNow()
                        ? Accept(request, candidate)
                        : Deny(request, RegionalHostSessionDecision.LeaseExpired);
                }
                catch (NatsKVWrongLastRevisionException) { }
            }
            return Deny(request, RegionalHostSessionDecision.Contention);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or NatsKVKeyDeletedException)
        {
            return Deny(request, RegionalHostSessionDecision.InvalidStore);
        }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException)
        {
            return Deny(request, RegionalHostSessionDecision.StoreUnavailable);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidOperationException)
        {
            return Deny(request, RegionalHostSessionDecision.InvalidRequest);
        }
    }

    /// <summary>Revokes only the observed generation/process epoch; a delayed revocation cannot hit its replacement.</summary>
    internal async Task<bool> RevokeAsync(string nodeId, ulong generation, ulong epoch, CancellationToken cancellationToken)
    {
        await ValidateStoreAsync(cancellationToken).ConfigureAwait(false);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var (current, revision) = await ReadAsync(nodeId, cancellationToken).ConfigureAwait(false);
            if (current is null || current.Generation != generation || current.Epoch != epoch) return false;
            if (current.Revoked) return true;
            try
            {
                await store.UpdateAsync(Key(nodeId), JsonSerializer.Serialize(current with { Revoked = true }, JsonOptions),
                    revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (NatsKVWrongLastRevisionException) { }
        }
        return false;
    }

    internal Task<RegionalHostActionAuthorization> AuthorizeAdmissionReportAsync(RegionalHostReportProof proof,
        HostAdmissionObservation report, CancellationToken cancellationToken) =>
        report.SchemaVersion != HostAdmissionObservation.CurrentSchemaVersion ||
        report.Environment != proof.Enrollment.Scope.Environment
            ? Task.FromResult(DenyAction(RegionalHostSessionDecision.InvalidRequest))
            : AuthorizeReportAsync(proof, RegionalHostReportKind.Admission, report.Cell, report.Instance,
                report.ArtifactKey, report.Digest, report.ObservedAt,
                JsonSerializer.SerializeToUtf8Bytes(report, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation), cancellationToken);

    internal Task<RegionalHostActionAuthorization> AuthorizeRuntimeReportAsync(RegionalHostReportProof proof,
        HostConvergenceObservation report, CancellationToken cancellationToken)
    {
        try { report.Validate(); }
        catch (InvalidOperationException) { return Task.FromResult(DenyAction(RegionalHostSessionDecision.InvalidRequest)); }
        return report.SchemaVersion != HostConvergenceObservation.CurrentSchemaVersion ||
            report.State.Length > 64 || report.UnitName?.Length > 256 || report.Error?.Length > 1024 || report.MemberRole?.Length > 32
                ? Task.FromResult(DenyAction(RegionalHostSessionDecision.InvalidRequest))
                : AuthorizeReportAsync(proof, RegionalHostReportKind.Runtime, report.Cell, report.Instance,
                    report.ArtifactKey, report.Digest, report.ObservedAt,
                    JsonSerializer.SerializeToUtf8Bytes(report, HostConvergenceJsonContext.Default.HostConvergenceObservation), cancellationToken);
    }

    private async Task<RegionalHostActionAuthorization> AuthorizeReportAsync(RegionalHostReportProof proof,
        RegionalHostReportKind kind, string cell, string nodeId, string artifact, string digest,
        DateTimeOffset observedAt, byte[] payload, CancellationToken cancellationToken)
    {
        try
        {
            _ = proof.Serialize();
            var role = AdmittedRoleCatalog.All.SingleOrDefault(value => value.ArtifactKey == artifact);
            if (cell != Cell || nodeId != proof.Enrollment.NodeId || role is null ||
                !HostDesiredArtifactReader.ValidDigest(digest) || digest != digest.ToLowerInvariant() ||
                observedAt == default || observedAt.Offset != TimeSpan.Zero || observedAt > proof.IssuedAt ||
                proof.IssuedAt - observedAt >= HostObservationRelay.MaximumReportAge ||
                !proof.Verifies(Cell, role.Role, kind, payload, time.GetUtcNow()))
                return DenyAction(RegionalHostSessionDecision.InvalidRequest);

            var freshnessDeadline = proof.IssuedAt + RegionalHostSessionRequest.MaximumAge;
            var observationDeadline = observedAt + HostObservationRelay.MaximumReportAge;
            if (observationDeadline < freshnessDeadline) freshnessDeadline = observationDeadline;
            return await AuthorizeActionAsync(proof.Enrollment, proof.SessionId, proof.Epoch, observedAt,
                freshnessDeadline, now => proof.Verifies(Cell, role.Role, kind, payload, now) &&
                    now - observedAt < HostObservationRelay.MaximumReportAge, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { return DenyAction(RegionalHostSessionDecision.InvalidRequest); }
    }

    internal Task<RegionalHostActionAuthorization> AuthorizeDesiredAsync(RegionalHostDesiredRequest request,
        CancellationToken cancellationToken)
    {
        try { _ = request.Serialize(); }
        catch (InvalidOperationException) { return Task.FromResult(DenyAction(RegionalHostSessionDecision.InvalidRequest)); }
        return AuthorizeActionAsync(request.Enrollment, request.SessionId, request.Epoch, request.IssuedAt,
            request.IssuedAt + RegionalHostSessionRequest.MaximumAge, now => request.HasValidProof(Cell, now), cancellationToken);
    }

    private async Task<RegionalHostActionAuthorization> AuthorizeActionAsync(RegionalNodeEnrollmentEnvelope enrollment,
        string sessionId, ulong epoch, DateTimeOffset actionAt, DateTimeOffset freshnessDeadline,
        Func<DateTimeOffset, bool> verify, CancellationToken cancellationToken)
    {
        try
        {
            if (!verify(time.GetUtcNow())) return DenyAction(RegionalHostSessionDecision.InvalidRequest);
            await ValidateStoreAsync(cancellationToken).ConfigureAwait(false);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var (current, revision) = await ReadAsync(enrollment.NodeId, cancellationToken).ConfigureAwait(false);
                var now = time.GetUtcNow();
                if (!verify(now))
                    return DenyAction(RegionalHostSessionDecision.InvalidRequest);
                if (current is null || current.Generation != enrollment.BootstrapGeneration ||
                    current.EnrollmentDigest != enrollment.Digest)
                    return DenyAction(RegionalHostSessionDecision.EnrollmentDenied);
                if (current.Revoked) return DenyAction(RegionalHostSessionDecision.Revoked);
                if (current.SessionId != sessionId || current.Epoch != epoch)
                    return DenyAction(RegionalHostSessionDecision.SessionMismatch);
                if (current.ExpiresAt <= now) return DenyAction(RegionalHostSessionDecision.LeaseExpired);
                if (actionAt < current.SessionStartedAt || now < current.SessionStartedAt)
                    return DenyAction(RegionalHostSessionDecision.StaleRequest);
                if (!policy.AllowsContinuingEnrollment(enrollment, now, current.ExpiresAt))
                    return DenyAction(RegionalHostSessionDecision.EnrollmentDenied);
                var grant = enrollment.Grant.ParsePayload();
                if (current.EnrolledAt < grant.IssuedAt || current.EnrolledAt >= grant.ExpiresAt)
                    return DenyAction(RegionalHostSessionDecision.InvalidStore);
                try
                {
                    await ConfirmCurrentAsync(current, revision, cancellationToken).ConfigureAwait(false);
                    // A successful CAS linearizes against renewal, replacement and revocation.
                    // Its result is an instant authorization, not a promise against future revoke.
                    now = time.GetUtcNow();
                    if (current.ExpiresAt <= now) return DenyAction(RegionalHostSessionDecision.LeaseExpired);
                    if (!verify(now))
                        return DenyAction(RegionalHostSessionDecision.InvalidRequest);
                    return new(RegionalHostSessionDecision.Accepted,
                        current.ExpiresAt < freshnessDeadline ? current.ExpiresAt : freshnessDeadline);
                }
                catch (NatsKVWrongLastRevisionException) { }
            }
            return DenyAction(RegionalHostSessionDecision.Contention);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or NatsKVKeyDeletedException)
        { return DenyAction(RegionalHostSessionDecision.InvalidStore); }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException)
        { return DenyAction(RegionalHostSessionDecision.StoreUnavailable); }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { return DenyAction(RegionalHostSessionDecision.InvalidRequest); }
    }

    private static RegionalHostActionAuthorization DenyAction(RegionalHostSessionDecision decision) => new(decision, null);

    private async Task<(RegionalHostSessionRecord? Record, ulong Revision)> ReadAsync(string nodeId, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await store.GetEntryAsync<string>(Key(nodeId), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            if (entry.Value is not { Length: > 0 and <= 8192 }) throw new InvalidDataException("Invalid host session record size.");
            var value = JsonSerializer.Deserialize<RegionalHostSessionRecord>(entry.Value, JsonOptions);
            if (value is null || value.SchemaVersion != 2 || value.Cell != Cell || value.NodeId != nodeId ||
                value.Generation == 0 || value.Epoch == 0 || value.IssuedAt == default || value.IssuedAt.Offset != TimeSpan.Zero ||
                value.EnrolledAt == default || value.EnrolledAt.Offset != TimeSpan.Zero || value.EnrolledAt >= value.ExpiresAt ||
                value.SessionStartedAt.Offset != TimeSpan.Zero || value.SessionStartedAt < value.EnrolledAt || value.SessionStartedAt >= value.ExpiresAt ||
                value.IssuedAt > DateTimeOffset.MaxValue - LeaseLifetime || value.ExpiresAt != value.IssuedAt + LeaseLifetime ||
                value.ConsumedGrants is not { Count: > 0 and <= MaximumConsumedGrants } ||
                value.ConsumedGrants.Any(static consumed => consumed is null || consumed.ExpiresAt == default) ||
                value.ConsumedGrants.DistinctBy(static consumed => consumed.GrantId).Count() != value.ConsumedGrants.Count ||
                value.ConsumedGrants.DistinctBy(static consumed => consumed.Nonce).Count() != value.ConsumedGrants.Count ||
                !value.ConsumedGrants.Any(consumed => consumed.GrantId == value.GrantId && consumed.Nonce == value.Nonce))
                throw new InvalidDataException("Invalid host session record identity or lease.");
            try
            {
                _ = new BootstrapUlid(value.GrantId);
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(value.Nonce, 64, nameof(value.Nonce));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(value.EnrollmentDigest, 64, nameof(value.EnrollmentDigest));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(value.RequestDigest, 64, nameof(value.RequestDigest));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(value.SessionId, 32, nameof(value.SessionId));
                foreach (var consumed in value.ConsumedGrants)
                {
                    _ = new BootstrapUlid(consumed.GrantId);
                    _ = BootstrapGrantCanonical.ValidateLowercaseHex(consumed.Nonce, 64, nameof(consumed.Nonce));
                }
            }
            catch (ArgumentException exception) { throw new InvalidDataException("Invalid host session record fields.", exception); }
            return (value, entry.Revision);
        }
        catch (NatsKVKeyNotFoundException) { return (null, 0); }
    }

    internal async Task ValidateStoreAsync(CancellationToken cancellationToken)
    {
        var configuration = (await store.GetStatusAsync(cancellationToken).ConfigureAwait(false)).Info.Config;
        ValidateStoreConfiguration(configuration);
    }

    internal static void ValidateStoreConfiguration(StreamConfig configuration)
    {
        if (configuration.Name != "KV_ORCH_NODE_ENROLLMENTS" || configuration.Storage != StreamConfigStorage.File ||
            configuration.NumReplicas != 3 || configuration.MaxAge != TimeSpan.Zero || configuration.MaxMsgs != -1 ||
            configuration.Discard != StreamConfigDiscard.New || configuration.AllowMsgTTL || configuration.NoAck ||
            configuration.Retention != StreamConfigRetention.Limits || configuration.SubjectDeleteMarkerTTL != TimeSpan.Zero ||
            configuration.Mirror is not null || configuration.Sources is { Count: > 0 })
            throw new InvalidDataException("Host sessions require a non-expiring, non-evicting regional R3 file store.");
    }

    private static RegionalHostSessionResponse Deny(RegionalHostSessionRequest request, RegionalHostSessionDecision decision) =>
        new(2, request.RequestId, request.RequestDigest, decision, request.Enrollment.BootstrapGeneration, 0, null);

    private static RegionalHostSessionResponse Accept(RegionalHostSessionRequest request, RegionalHostSessionRecord record) =>
        new(2, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
            record.Generation, record.Epoch, record.ExpiresAt);

    private async Task ConfirmCurrentAsync(RegionalHostSessionRecord record, ulong revision, CancellationToken cancellationToken) =>
        // An unchanged CAS confirms the replica read against the current leader. It extends
        // neither enrollment nor session. Epoch/request/expiry identify the lease; KV revision
        // is an internal concurrency fence and is intentionally absent from the wire response.
        _ = await store.UpdateAsync(Key(record.NodeId), JsonSerializer.Serialize(record, JsonOptions),
            revision, cancellationToken: cancellationToken).ConfigureAwait(false);
}
