using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostReportEnvelope(int SchemaVersion, RegionalHostReportProof Proof,
    HostAdmissionObservation? Admission, HostConvergenceObservation? Runtime)
{
    internal string RequestId => Proof.RequestId;
    internal StoredHostReport Stored => new(1, Proof, Admission, Runtime);
    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, RegionalHostSessionAuthority.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > StoredHostReport.MaximumBytes)
            throw new InvalidOperationException("The signed host report exceeds its wire bounds.");
        return json;
    }
    internal string Digest => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Serialize())));
}

internal sealed record HostReportAcknowledgement(int SchemaVersion, string RequestId,
    string ReportDigest, bool Accepted, string? Error);

internal interface IHostObservationPublisher
{
    Task PublishAsync(HostAdmissionObservation report, CancellationToken cancellationToken);
    Task PublishAsync(HostConvergenceObservation report, CancellationToken cancellationToken);
}

/// <summary>Uses only the host's hashed observation/command subjects and the latest accepted signing session.</summary>
internal sealed class NatsHostObservationPublisher(INatsConnection connection, string cell, string instance,
    Func<RegionalHostSessionSigner> currentSigner) : IHostObservationPublisher
{
    public Task PublishAsync(HostAdmissionObservation report, CancellationToken cancellationToken) =>
        PublishAsync(currentSigner().Sign(report), cancellationToken);

    public Task PublishAsync(HostConvergenceObservation report, CancellationToken cancellationToken) =>
        PublishAsync(currentSigner().Sign(report), cancellationToken);

    internal async Task PublishAsync(HostReportEnvelope report, CancellationToken cancellationToken)
    {
        if (report.SchemaVersion != 2 || report.Proof.Enrollment.Region != cell.ToUpperInvariant() ||
            report.Proof.Enrollment.NodeId != instance)
            throw new InvalidOperationException("The report does not match this publisher's regional host identity.");
        var json = report.Serialize();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var reply = HostObservationRelay.ReplySubject(cell, instance, report.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1 }, cancellationToken: deadline.Token).ConfigureAwait(false);
        await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(HostObservationRelay.ReportSubject(cell, instance), json, replyTo: reply,
            cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        if (message.Data is not { Length: > 0 and <= 4096 } response || Encoding.UTF8.GetByteCount(response) > 4096)
            throw new InvalidDataException("The host report acknowledgement exceeds its bounds.");
        var acknowledgement = JsonSerializer.Deserialize<HostReportAcknowledgement>(response, RegionalHostSessionAuthority.JsonOptions);
        if (acknowledgement is not { SchemaVersion: 2, Accepted: true, Error: null } ||
            acknowledgement.RequestId != report.RequestId || acknowledgement.ReportDigest != report.Digest)
            throw new InvalidOperationException("The controller did not acknowledge the exact signed host report.");
    }
}
