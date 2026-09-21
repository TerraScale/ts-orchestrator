using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal enum RegionalHostCyclePhase { Active = 1, Failed, Succeeded }

internal sealed record RegionalHostCycleRecord(int SchemaVersion, string Cell, string NodeId, string Environment,
    AdmittedRole Role, string ArtifactDigest, ulong TargetRevision, ulong Generation, string EnrollmentDigest,
    string SessionId, ulong Epoch, string AttemptId, string CycleId, ulong Fence, RegionalHostCyclePhase Phase,
    int Failures, DateTimeOffset UpdatedAt, DateTimeOffset? NotBefore);

/// <summary>
/// Durable retry bookkeeping, not an execution lease. A bounded record per node/scope/role
/// holds the current cycle and its last outcome; stale outcomes cannot clear newer failures.
/// </summary>
internal sealed class RegionalHostCycleAuthority(INatsKVStore delivery, RegionalHostSessionAuthority sessions)
{
    private readonly RegionalHostTargetReader targets = new(delivery);
    internal string Cell => sessions.Cell;
    internal DateTimeOffset Now => sessions.Now;

    internal static string Key(string cell, string node, string environment, AdmittedRole role) => "host.cycle." +
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(BootstrapGrantCanonical.EncodeFields([
            cell, node, environment, role.ToString()]))));

    internal static TimeSpan Backoff(int failures) => TimeSpan.FromSeconds(Math.Min(900, 30 << (Math.Clamp(failures, 1, 6) - 1)));

    internal async Task<RegionalHostCycleResponse> ProcessAsync(RegionalHostCycleRequest request, CancellationToken cancellationToken)
    {
        try
        {
            _ = request.Serialize();
            var initial = await sessions.AuthorizeCycleAsync(request, cancellationToken).ConfigureAwait(false);
            if (!initial.Authorized) return Deny(initial.Decision);
            ValidateStoreConfiguration((await delivery.GetStatusAsync(cancellationToken).ConfigureAwait(false)).Info.Config);
            var key = Key(Cell, request.Enrollment.NodeId, request.Enrollment.Scope.Environment, request.Role);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var authorized = await sessions.AuthorizeCycleAsync(request, cancellationToken).ConfigureAwait(false);
                if (!authorized.Authorized) return Deny(authorized.Decision);
                RegionalHostTarget? target = null;
                if (request.Operation == RegionalHostCycleOperation.Begin)
                {
                    target = await ReadTargetAsync(request, cancellationToken).ConfigureAwait(false);
                    if (target.Decision != RegionalHostSessionDecision.Accepted) return Deny(target.Decision);
                    if (target.Digest != request.ArtifactDigest) return Deny(RegionalHostSessionDecision.EnrollmentDenied);
                }
                var (current, revision) = await ReadAsync(key, request, cancellationToken).ConfigureAwait(false);
                var now = Now;
                if (!request.HasValidProof(Cell, now)) return Deny(RegionalHostSessionDecision.InvalidRequest);
                if (current is not null && (now < current.UpdatedAt || current.Generation > request.Enrollment.BootstrapGeneration))
                    return Deny(RegionalHostSessionDecision.StaleRequest);
                RegionalHostCycleRecord next;
                RegionalHostCycleDisposition disposition;
                if (request.Operation == RegionalHostCycleOperation.Begin)
                {
                    if (current is not null && current.TargetRevision > target!.Revision) continue;
                    var sameDigest = current?.ArtifactDigest == request.ArtifactDigest;
                    if (sameDigest && SameSession(current!, request) && current!.AttemptId == request.AttemptId)
                    {
                        next = current;
                        disposition = current.Phase == RegionalHostCyclePhase.Active ? RegionalHostCycleDisposition.Active : RegionalHostCycleDisposition.Settled;
                    }
                    else if (current is not null && request.IssuedAt < current.UpdatedAt)
                        return Deny(RegionalHostSessionDecision.StaleRequest);
                    else if (sameDigest && current!.Phase == RegionalHostCyclePhase.Active)
                    {
                        if (SameSession(current, request))
                        {
                            next = current;
                            disposition = RegionalHostCycleDisposition.Busy;
                        }
                        else
                        {
                            // A new process cannot inherit an unfinished cycle. Count the abandoned
                            // outcome exactly once, then preserve its deadline across process restarts.
                            next = Failed(current, now) with { TargetRevision = target!.Revision };
                            disposition = RegionalHostCycleDisposition.Backoff;
                        }
                    }
                    else if (sameDigest && current!.Phase == RegionalHostCyclePhase.Failed && current.NotBefore > now)
                    {
                        next = current;
                        disposition = RegionalHostCycleDisposition.Backoff;
                    }
                    else
                    {
                        if (current?.Fence == ulong.MaxValue) return Deny(RegionalHostSessionDecision.InvalidStore);
                        next = new(1, Cell, request.Enrollment.NodeId, request.Enrollment.Scope.Environment, request.Role,
                            request.ArtifactDigest, target!.Revision, request.Enrollment.BootstrapGeneration, request.Enrollment.Digest,
                            request.SessionId, request.Epoch, request.AttemptId, Guid.NewGuid().ToString("N"), (current?.Fence ?? 0) + 1,
                            RegionalHostCyclePhase.Active, sameDigest ? current!.Failures : 0, now, null);
                        disposition = RegionalHostCycleDisposition.Active;
                    }
                }
                else
                {
                    if (current is null || !SameSession(current, request) || current.ArtifactDigest != request.ArtifactDigest ||
                        current.AttemptId != request.AttemptId || current.CycleId != request.CycleId || current.Fence != request.Fence)
                        return Deny(RegionalHostSessionDecision.StaleRequest);
                    var expected = request.Operation == RegionalHostCycleOperation.Complete ? RegionalHostCyclePhase.Succeeded : RegionalHostCyclePhase.Failed;
                    if (current.Phase != RegionalHostCyclePhase.Active && current.Phase != expected)
                        return Deny(RegionalHostSessionDecision.StaleRequest);
                    next = current.Phase == expected ? current : expected == RegionalHostCyclePhase.Failed ? Failed(current, now) :
                        current with { Phase = expected, Failures = 0, UpdatedAt = now, NotBefore = null };
                    disposition = RegionalHostCycleDisposition.Settled;
                }
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    // Expected revision zero creates only truly absent keys. SDK CreateAsync can
                    // recreate tombstones, which would erase the durable cycle fence.
                    await delivery.UpdateAsync(key, JsonSerializer.Serialize(next, RegionalHostSessionAuthority.JsonOptions),
                        revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                }
                catch (NatsKVWrongLastRevisionException) { continue; }
                if (request.Operation == RegionalHostCycleOperation.Begin)
                {
                    var after = await ReadTargetAsync(request, cancellationToken).ConfigureAwait(false);
                    if (after.Decision != RegionalHostSessionDecision.Accepted) return Deny(after.Decision);
                    if (after.Digest != request.ArtifactDigest) return Deny(RegionalHostSessionDecision.EnrollmentDenied);
                }
                var final = await sessions.AuthorizeCycleAsync(request, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (!final.Authorized) return Deny(final.Decision);
                return new(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
                    request.Enrollment.BootstrapGeneration, request.Epoch,
                    authorized.ExpiresAt < final.ExpiresAt ? authorized.ExpiresAt : final.ExpiresAt,
                    disposition, next.CycleId, next.Fence, next.Failures, next.NotBefore,
                    disposition == RegionalHostCycleDisposition.Settled ? next.Phase == RegionalHostCyclePhase.Succeeded : null);
            }
            return Deny(RegionalHostSessionDecision.Contention);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or NatsKVKeyDeletedException)
        { return Deny(RegionalHostSessionDecision.InvalidStore); }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException)
        { return Deny(RegionalHostSessionDecision.StoreUnavailable); }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidOperationException)
        { return Deny(RegionalHostSessionDecision.InvalidRequest); }

        RegionalHostCycleResponse Deny(RegionalHostSessionDecision decision) => RegionalHostCycleResponse.Deny(request, decision);
    }

    private Task<RegionalHostTarget> ReadTargetAsync(RegionalHostCycleRequest request, CancellationToken cancellationToken) =>
        targets.ReadAsync(AdmittedRoleCatalog.Get(request.Role).ArtifactKey, request.Enrollment.Scope.Environment, Cell, cancellationToken);

    private static bool SameSession(RegionalHostCycleRecord record, RegionalHostCycleRequest request) =>
        record.Generation == request.Enrollment.BootstrapGeneration && record.EnrollmentDigest == request.Enrollment.Digest &&
        record.SessionId == request.SessionId && record.Epoch == request.Epoch;

    private static RegionalHostCycleRecord Failed(RegionalHostCycleRecord record, DateTimeOffset now)
    {
        var failures = Math.Min(6, record.Failures + 1);
        return record with { Phase = RegionalHostCyclePhase.Failed, Failures = failures, UpdatedAt = now, NotBefore = now + Backoff(failures) };
    }

    private async Task<(RegionalHostCycleRecord? Record, ulong Revision)> ReadAsync(string key, RegionalHostCycleRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            if (entry.Revision == 0 || entry.Value is not { Length: > 0 and <= 4096 } json || Encoding.UTF8.GetByteCount(json) > 4096)
                throw new InvalidDataException("The host cycle record exceeds its bounds.");
            var record = JsonSerializer.Deserialize<RegionalHostCycleRecord>(json, RegionalHostSessionAuthority.JsonOptions);
            if (record is null || record.SchemaVersion != 1 || record.Cell != Cell || record.NodeId != request.Enrollment.NodeId ||
                record.Environment != request.Enrollment.Scope.Environment || record.Role != request.Role || record.TargetRevision == 0 ||
                record.Generation == 0 || record.Epoch == 0 || record.Fence == 0 || !Enum.IsDefined(record.Phase) || record.Failures is < 0 or > 6 ||
                !HostDesiredArtifactReader.ValidDigest(record.ArtifactDigest) || record.ArtifactDigest != record.ArtifactDigest.ToLowerInvariant() ||
                record.UpdatedAt == default || record.UpdatedAt.Offset != TimeSpan.Zero || record.UpdatedAt > DateTimeOffset.MaxValue - TimeSpan.FromMinutes(15) ||
                (record.Phase == RegionalHostCyclePhase.Failed
                    ? record.Failures == 0 || record.NotBefore != record.UpdatedAt + Backoff(record.Failures)
                    : record.NotBefore is not null) || record.Phase == RegionalHostCyclePhase.Succeeded && record.Failures != 0)
                throw new InvalidDataException("The host cycle record is malformed or belongs to another scope.");
            try
            {
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(record.EnrollmentDigest, 64, nameof(record.EnrollmentDigest));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(record.SessionId, 32, nameof(record.SessionId));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(record.AttemptId, 32, nameof(record.AttemptId));
                _ = BootstrapGrantCanonical.ValidateLowercaseHex(record.CycleId, 32, nameof(record.CycleId));
            }
            catch (ArgumentException exception) { throw new InvalidDataException("The host cycle record identities are malformed.", exception); }
            return (record, entry.Revision);
        }
        catch (NatsKVKeyNotFoundException) { return (null, 0); }
    }

    internal static void ValidateStoreConfiguration(StreamConfig configuration)
    {
        if (configuration.Name != "KV_ORCH_DELIVERY" || configuration.Storage != StreamConfigStorage.File || configuration.NumReplicas != 3 ||
            configuration.MaxAge != TimeSpan.Zero || configuration.MaxMsgs != -1 || configuration.MaxMsgsPerSubject != 2 ||
            configuration.MaxBytes != 256L * 1024 * 1024 || configuration.MaxMsgSize != 16 * 1024 ||
            configuration.Discard != StreamConfigDiscard.New || configuration.AllowMsgTTL || configuration.NoAck ||
            configuration.Retention != StreamConfigRetention.Limits || configuration.SubjectDeleteMarkerTTL != TimeSpan.Zero ||
            configuration.Mirror is not null || configuration.Sources is { Count: > 0 })
            throw new InvalidDataException("Host cycles require the bounded, non-expiring, non-evicting regional R3 delivery store.");
    }
}
