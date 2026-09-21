using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostReportRelaySnapshot(long Accepted, long Rejected, long Failed, bool RetryPending);

/// <summary>Only controllers authorize and atomically persist session proofs with host observations.</summary>
internal sealed class HostObservationRelay : IAsyncDisposable
{
    internal static readonly TimeSpan MaximumReportAge = TimeSpan.FromSeconds(30);
    internal static JsonSerializerOptions JsonOptions => RegionalHostSessionAuthority.JsonOptions;
    private readonly INatsConnection connection;
    private readonly INatsKVStore runtime;
    private readonly RegionalHostSessionAuthority authority;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private long accepted;
    private long rejected;
    private long failed;
    private int retryPending;
    private readonly HashSet<string> failedKeys = new(StringComparer.Ordinal);
    private bool failureTrackingOverflow;

    private HostObservationRelay(INatsConnection connection, INatsKVStore runtime,
        RegionalHostSessionAuthority authority, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.runtime = runtime;
        this.authority = authority;
        this.subscription = subscription;
        loop = RunAsync();
    }

    internal Task Completion => loop;
    internal HostReportRelaySnapshot Snapshot => new(Interlocked.Read(ref accepted), Interlocked.Read(ref rejected),
        Interlocked.Read(ref failed), Volatile.Read(ref retryPending) != 0);
    internal static string ReportSubject(string cell, string instance) =>
        NatsSubjectTaxonomy.HostAgentObservationSubject(cell, instance, "report");
    internal static string ReplySubject(string cell, string instance, string requestId) =>
        NatsSubjectTaxonomy.HostAgentCommandSubject(cell, instance, "report-" + requestId);

    internal static async Task<HostObservationRelay> StartAsync(INatsConnection connection,
        INatsKVStore runtime, RegionalHostSessionAuthority authority, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        INatsSub<string>? subscription = null;
        try
        {
            await authority.ValidateStoreAsync(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            var status = await runtime.GetStatusAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            ValidateStoreConfiguration(status.Info.Config);
            var pattern = NatsSubjectTaxonomy.RegionalRoot(authority.Cell) + ".agent.*.observation.report";
            subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-report-relay",
                cancellationToken: deadline.Token).ConfigureAwait(false);
            await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            return new(connection, runtime, authority, subscription);
        }
        catch (Exception exception)
        {
            if (subscription is not null) await subscription.DisposeAsync().ConfigureAwait(false);
            if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                throw new TimeoutException("The regional host-report relay startup timed out.", exception);
            throw;
        }
    }

    internal static void ValidateStoreConfiguration(StreamConfig configuration)
    {
        // The ordering fence must outlive every acceptable report replay and survive one server loss.
        if (configuration.Name != "KV_ORCH_RUNTIME" || configuration.NumReplicas != 3 || configuration.NoAck ||
            configuration.Storage != StreamConfigStorage.File || configuration.Retention != StreamConfigRetention.Limits ||
            (configuration.MaxAge != TimeSpan.Zero && configuration.MaxAge <= MaximumReportAge) ||
            configuration.Discard != StreamConfigDiscard.New || configuration.MaxMsgs != -1 || configuration.AllowMsgTTL ||
            configuration.SubjectDeleteMarkerTTL != TimeSpan.Zero)
            throw new InvalidOperationException("Host report retention must preserve acknowledged R3 ordering beyond the accepted report age.");
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                string? reportKey = null;
                try
                {
                    if (message.Data is not { Length: > 0 and <= StoredHostReport.MaximumBytes } json ||
                        Encoding.UTF8.GetByteCount(json) > StoredHostReport.MaximumBytes)
                    {
                        Interlocked.Increment(ref rejected);
                        continue;
                    }
                    var report = JsonSerializer.Deserialize<HostReportEnvelope>(json, JsonOptions);
                    if (report is null || !TryValidate(report, message.Subject, message.ReplyTo))
                    {
                        Interlocked.Increment(ref rejected);
                        continue;
                    }
                    reportKey = report.Stored.Key;
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(5));
                    var acknowledgement = await StoreAsync(report, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                    await connection.PublishAsync(message.ReplyTo!, JsonSerializer.Serialize(acknowledgement, JsonOptions),
                        cancellationToken: deadline.Token).ConfigureAwait(false);
                    if (acknowledgement.Accepted)
                    {
                        Interlocked.Increment(ref accepted);
                        failedKeys.Remove(reportKey);
                        Volatile.Write(ref retryPending, failureTrackingOverflow || failedKeys.Count > 0 ? 1 : 0);
                    }
                    else if (acknowledgement.Error is "authorization-unavailable" or "report-contention" or "report-store-invalid")
                        RecordFailure(reportKey);
                    else Interlocked.Increment(ref rejected);
                }
                catch (OperationCanceledException) when (!stopping.IsCancellationRequested) { RecordFailure(reportKey); }
                catch (Exception exception) when (exception is NatsException or IOException or TimeoutException) { RecordFailure(reportKey); }
                catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException)
                {
                    Interlocked.Increment(ref rejected);
                }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private bool TryValidate(HostReportEnvelope report, string subject, string? reply)
    {
        if (report is not { SchemaVersion: 2, Proof: not null } ||
            (report.Admission is null) == (report.Runtime is null)) return false;
        var node = report.Admission is { } admissionValue ? admissionValue.Instance : report.Runtime!.Instance;
        var cell = report.Admission is { } admissionCell ? admissionCell.Cell : report.Runtime!.Cell;
        return node is not null && node == report.Proof.Enrollment.NodeId && cell == authority.Cell &&
            node.Split('.')[0] is not ("admission" or "backoff" or "replace") &&
            subject == ReportSubject(authority.Cell, node) && reply == ReplySubject(authority.Cell, node, report.RequestId);
    }

    private async Task<HostReportAcknowledgement> StoreAsync(HostReportEnvelope report, CancellationToken cancellationToken)
    {
        var stored = report.Stored;
        var key = stored.Key;
        var value = JsonSerializer.Serialize(stored, JsonOptions);
        var digest = report.Digest;
        var observedAt = stored.Admission?.ObservedAt ?? stored.Runtime!.ObservedAt;
        HostReportAcknowledgement Deny(string error) => new(2, report.RequestId, digest, false, error);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var authorization = stored.Admission is { } admission
                ? await authority.AuthorizeAdmissionReportAsync(stored.Proof, admission, cancellationToken).ConfigureAwait(false)
                : await authority.AuthorizeRuntimeReportAsync(stored.Proof, stored.Runtime!, cancellationToken).ConfigureAwait(false);
            if (!authorization.Authorized || authorization.ExpiresAt is not { } expiresAt)
                return Deny(authorization.Decision is RegionalHostSessionDecision.InvalidStore or RegionalHostSessionDecision.StoreUnavailable or
                    RegionalHostSessionDecision.Contention ? "authorization-unavailable" : "session-denied");
            ulong revision;
            try
            {
                var current = await runtime.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                current.EnsureSuccess();
                revision = current.Revision;
                if (current.Value != value)
                {
                    if (current.Value is not { Length: > 0 and <= StoredHostReport.MaximumBytes } json ||
                        Encoding.UTF8.GetByteCount(json) > StoredHostReport.MaximumBytes) return Deny("report-store-invalid");
                    var previous = JsonSerializer.Deserialize<StoredHostReport>(json, JsonOptions);
                    if (previous is not { SchemaVersion: 1, Proof: not null } ||
                        (previous.Admission is null) == (previous.Runtime is null) || previous.Key != key)
                        return Deny("report-store-invalid");
                    var previousTime = previous.Admission?.ObservedAt ?? previous.Runtime!.ObservedAt;
                    if (previousTime == default || previousTime.Offset != TimeSpan.Zero) return Deny("report-store-invalid");
                    if (previousTime >= observedAt) return Deny("stale-report");
                }
            }
            catch (NatsKVKeyNotFoundException) { revision = 0; }
            catch (NatsKVKeyDeletedException) { return Deny("report-store-invalid"); }
            catch (JsonException) { return Deny("report-store-invalid"); }
            try
            {
                // Exact retries also CAS: a stale replica must not ACK pre-withdrawal readiness.
                // Revision zero cannot resurrect an explicitly deleted ordering fence.
                await runtime.UpdateAsync(key, value, revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                return expiresAt > authority.Now
                    ? new(2, report.RequestId, digest, true, null)
                    : Deny("session-denied");
            }
            catch (NatsKVWrongLastRevisionException) { }
        }
        return Deny("report-contention");
    }

    private void RecordFailure(string? key)
    {
        Interlocked.Increment(ref failed);
        if (key is not null && !failedKeys.Contains(key))
        {
            if (failedKeys.Count < 512) failedKeys.Add(key);
            else failureTrackingOverflow = true;
        }
        Volatile.Write(ref retryPending, 1);
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try { await loop.ConfigureAwait(false); }
        finally
        {
            await subscription.DisposeAsync().ConfigureAwait(false);
            stopping.Dispose();
        }
    }
}
