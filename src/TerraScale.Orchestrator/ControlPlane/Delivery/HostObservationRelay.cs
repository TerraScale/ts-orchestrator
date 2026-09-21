using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostReportEnvelope(int SchemaVersion, string RequestId,
    HostAdmissionObservation? Admission, HostConvergenceObservation? Runtime);
internal sealed record HostReportAcknowledgement(string RequestId, bool Accepted, ulong Revision, string? Error);
internal sealed record HostReportRelaySnapshot(long Accepted, long Rejected, long Failed, bool RetryPending);

/// <summary>Hosts publish only on their own agent subject and receive controller acknowledgements.</summary>
internal sealed class NatsHostObservationPublisher(INatsConnection connection, string cell, string instance)
{
    internal Task PublishAsync(HostAdmissionObservation report, CancellationToken cancellationToken) =>
        PublishAsync(new HostReportEnvelope(1, Guid.NewGuid().ToString("N"), report, null), cancellationToken);

    internal Task PublishAsync(HostConvergenceObservation report, CancellationToken cancellationToken) =>
        PublishAsync(new HostReportEnvelope(1, Guid.NewGuid().ToString("N"), null, report), cancellationToken);

    private async Task PublishAsync(HostReportEnvelope report, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var reply = HostObservationRelay.ReplySubject(cell, instance, report.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1 }, cancellationToken: deadline.Token).ConfigureAwait(false);
        await connection.PingAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(HostObservationRelay.ReportSubject(cell, instance),
            JsonSerializer.Serialize(report, HostObservationRelay.JsonOptions), replyTo: reply,
            cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        var acknowledgement = JsonSerializer.Deserialize<HostReportAcknowledgement>(
            message.Data ?? string.Empty, HostObservationRelay.JsonOptions);
        if (acknowledgement is not { Accepted: true, Revision: > 0, Error: null } ||
            acknowledgement.RequestId != report.RequestId)
            throw new InvalidOperationException("The controller did not acknowledge the exact host report.");
    }
}

/// <summary>
/// Only controllers write host reports to private KV. NATS maps each enrolled credential to
/// its hashed agent subject; the relay derives the storage key from that exact subject/body
/// binding. Reports are observations, never a substitute for signed enrollment authorization.
/// </summary>
internal sealed class HostObservationRelay : IAsyncDisposable
{
    internal static readonly TimeSpan MaximumReportAge = TimeSpan.FromSeconds(30);
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly INatsConnection connection;
    private readonly INatsKVStore runtime;
    private readonly string cell;
    private readonly TimeProvider clock;
    private readonly INatsSub<string> subscription;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    private long accepted;
    private long rejected;
    private long failed;
    private int retryPending;
    private readonly HashSet<string> failedKeys = new(StringComparer.Ordinal);
    private bool failureTrackingOverflow;

    private HostObservationRelay(INatsConnection connection, INatsKVStore runtime, string cell,
        TimeProvider clock, INatsSub<string> subscription)
    {
        this.connection = connection;
        this.runtime = runtime;
        this.cell = cell;
        this.clock = clock;
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
        INatsKVStore runtime, string cell, CancellationToken cancellationToken, TimeProvider? clock = null)
    {
        // The timestamp ordering fence must outlive every acceptable replay. A report
        // older than this window cannot recreate readiness after its stored withdrawal expires.
        var configuration = (await runtime.GetStatusAsync(cancellationToken).ConfigureAwait(false)).Info.Config;
        if ((configuration.MaxAge != TimeSpan.Zero && configuration.MaxAge <= MaximumReportAge) ||
            configuration.Discard != StreamConfigDiscard.New || configuration.MaxMsgs != -1 || configuration.AllowMsgTTL)
            throw new InvalidOperationException("Host report retention must preserve ordering beyond the accepted report age.");
        var pattern = NatsSubjectTaxonomy.RegionalRoot(cell) + ".agent.*.observation.report";
        var subscription = await connection.SubscribeCoreAsync<string>(pattern, queueGroup: "host-report-relay",
            cancellationToken: cancellationToken).ConfigureAwait(false);
        try
        {
            await connection.PingAsync(cancellationToken).ConfigureAwait(false);
            return new(connection, runtime, cell, clock ?? TimeProvider.System, subscription);
        }
        catch
        {
            await subscription.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var message in subscription.Msgs.ReadAllAsync(stopping.Token).ConfigureAwait(false))
            {
                HostReportEnvelope? report;
                string? reportKey = null;
                try
                {
                    if (message.Data is not { Length: > 0 and <= 16_384 } json || Encoding.UTF8.GetByteCount(json) > 16_384)
                    {
                        Interlocked.Increment(ref rejected);
                        continue;
                    }
                    report = JsonSerializer.Deserialize<HostReportEnvelope>(json, JsonOptions);
                    if (report is null || !TryValidate(report, message.Subject, message.ReplyTo, out var key, out var value, out var observedAt))
                    {
                        Interlocked.Increment(ref rejected);
                        continue;
                    }
                    reportKey = key;
                    var acknowledgement = await StoreAsync(report, key, value, observedAt, stopping.Token).ConfigureAwait(false);
                    await connection.PublishAsync(message.ReplyTo!, JsonSerializer.Serialize(acknowledgement, JsonOptions),
                        cancellationToken: stopping.Token).ConfigureAwait(false);
                    if (acknowledgement.Accepted)
                    {
                        Interlocked.Increment(ref accepted);
                        failedKeys.Remove(key);
                        Volatile.Write(ref retryPending, failureTrackingOverflow || failedKeys.Count > 0 ? 1 : 0);
                    }
                    else Interlocked.Increment(ref rejected);
                }
                catch (NatsException)
                {
                    Interlocked.Increment(ref failed);
                    // Bounded process-local failure tracking: another host's success cannot
                    // clear this host's need to retry. Overflow stays degraded until restart.
                    if (reportKey is not null && !failedKeys.Contains(reportKey))
                    {
                        if (failedKeys.Count < 512) failedKeys.Add(reportKey);
                        else failureTrackingOverflow = true;
                    }
                    Volatile.Write(ref retryPending, 1);
                }
                catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException)
                {
                    // Malformed reports or failed stores receive no success acknowledgement.
                    // The host retries on its next convergence pass; a bad message never kills ingress.
                    Interlocked.Increment(ref rejected);
                }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private bool TryValidate(HostReportEnvelope report, string subject, string? reply,
        out string key, out string value, out DateTimeOffset observedAt)
    {
        key = value = string.Empty;
        observedAt = default;
        if (report.SchemaVersion != 1 || report.RequestId is not { Length: 32 } ||
            report.RequestId.AsSpan().ContainsAnyExcept("0123456789abcdef") ||
            (report.Admission is null) == (report.Runtime is null)) return false;
        var instance = report.Admission?.Instance ?? report.Runtime!.Instance;
        var reportCell = report.Admission?.Cell ?? report.Runtime!.Cell;
        var artifact = report.Admission?.ArtifactKey ?? report.Runtime!.ArtifactKey;
        var digest = report.Admission?.Digest ?? report.Runtime!.Digest;
        observedAt = report.Admission?.ObservedAt ?? report.Runtime!.ObservedAt;
        var now = clock.GetUtcNow();
        if (instance is not { Length: > 0 and <= 512 } || instance.Any(static c =>
                c is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_')) ||
            instance.Split('.')[0] is "admission" or "backoff" or "replace" ||
            reportCell != cell || subject != ReportSubject(cell, instance) ||
            reply != ReplySubject(cell, instance, report.RequestId) ||
            !AdmittedRoleCatalog.All.Any(role => role.ArtifactKey == artifact) ||
            !HostDesiredArtifactReader.ValidDigest(digest) || digest != digest.ToLowerInvariant() ||
            observedAt < now - MaximumReportAge || observedAt > now) return false;
        if (report.Admission is { } admission)
        {
            if (admission.SchemaVersion != HostAdmissionObservation.CurrentSchemaVersion ||
                admission.Environment is not { Length: >= 1 and <= 64 } || admission.Environment.Any(static c =>
                    c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-'))) return false;
            key = HostAdmissionObservation.Key(instance, artifact);
            value = JsonSerializer.Serialize(admission, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation);
        }
        else
        {
            var observation = report.Runtime!;
            observation.Validate();
            if (observation.SchemaVersion != HostConvergenceObservation.CurrentSchemaVersion ||
                observation.State.Length > 64 || observation.Error?.Length > 1024 || observation.UnitName?.Length > 256)
                return false;
            key = $"host.{instance}.{artifact}";
            value = JsonSerializer.Serialize(observation, HostConvergenceJsonContext.Default.HostConvergenceObservation);
        }
        return true;
    }

    private async Task<HostReportAcknowledgement> StoreAsync(HostReportEnvelope report, string key, string value,
        DateTimeOffset observedAt, CancellationToken cancellationToken)
    {
        // Multiple controllers can receive reports over time. CAS prevents an older report
        // from replacing a newer withdrawal/health observation after retries or leadership churn.
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                var current = await runtime.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                current.EnsureSuccess();
                if (current.Value == value) return new(report.RequestId, true, current.Revision, null);
                var previousTime = report.Admission is not null
                    ? JsonSerializer.Deserialize<HostAdmissionObservation>(current.Value!, JsonOptions)?.ObservedAt
                    : JsonSerializer.Deserialize<HostConvergenceObservation>(current.Value!, JsonOptions)?.ObservedAt;
                if (previousTime is null || previousTime >= observedAt)
                    return new(report.RequestId, false, 0, "stale-report");
                var revision = await runtime.UpdateAsync(key, value, current.Revision,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return new(report.RequestId, true, revision, null);
            }
            catch (Exception exception) when (exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException)
            {
                try
                {
                    var revision = await runtime.CreateAsync(key, value, cancellationToken: cancellationToken).ConfigureAwait(false);
                    return new(report.RequestId, true, revision, null);
                }
                catch (NatsKVCreateException) { }
            }
            catch (NatsKVWrongLastRevisionException) { }
        }
        return new(report.RequestId, false, 0, "report-contention");
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
