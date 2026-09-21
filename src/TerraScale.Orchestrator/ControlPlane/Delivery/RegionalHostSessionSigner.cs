using System.Text.Json;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>An immutable accepted lease snapshot. Renewal replaces the snapshot; signing never renews a lease.</summary>
internal sealed class RegionalHostSessionSigner
{
    private readonly RegionalHostSessionRequest request;
    private readonly RegionalHostSessionResponse lease;
    private readonly NatsAuthenticationFiles authentication;
    private readonly TimeProvider clock;

    internal RegionalHostSessionSigner(RegionalHostSessionRequest request, RegionalHostSessionResponse lease,
        NatsAuthenticationFiles authentication, TimeProvider? clock = null)
    {
        if (!lease.Accepted || lease.SchemaVersion != 2 || lease.RequestId != request.RequestId ||
            lease.RequestDigest != request.RequestDigest || lease.Generation != request.Enrollment.BootstrapGeneration ||
            lease.Epoch == 0 || lease.ExpiresAt != request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime ||
            request.Operation == RegionalHostSessionOperation.Renew && lease.Epoch != request.Epoch ||
            authentication.PublicKey != request.Enrollment.NatsUserPublicKey)
            throw new ArgumentException("Host signing requires the exact accepted session response and enrolled key.");
        this.request = request;
        this.lease = lease;
        this.authentication = authentication;
        this.clock = clock ?? TimeProvider.System;
    }

    internal HostReportEnvelope Sign(HostAdmissionObservation report) =>
        new(2, Sign(report.Cell, report.Instance, report.ArtifactKey, RegionalHostReportKind.Admission,
            JsonSerializer.SerializeToUtf8Bytes(report, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation)), report, null);

    internal HostReportEnvelope Sign(HostConvergenceObservation report) =>
        new(2, Sign(report.Cell, report.Instance, report.ArtifactKey, RegionalHostReportKind.Runtime,
            JsonSerializer.SerializeToUtf8Bytes(report, HostConvergenceJsonContext.Default.HostConvergenceObservation)), null, report);

    internal RegionalHostDesiredRequest SignDesired(AdmittedRole role)
    {
        var now = clock.GetUtcNow();
        if (now < request.IssuedAt || lease.ExpiresAt <= now)
            throw new InvalidOperationException("The desired request is outside this current host session.");
        return RegionalHostDesiredRequest.Sign(request.Enrollment, authentication, request.SessionId, lease.Epoch, role, now);
    }

    internal RegionalHostArtifactRequest SignArtifact(AdmittedRole role, string digest, long offset, int length)
    {
        var now = clock.GetUtcNow();
        if (now < request.IssuedAt || lease.ExpiresAt <= now)
            throw new InvalidOperationException("The artifact request is outside this current host session.");
        return RegionalHostArtifactRequest.Sign(request.Enrollment, authentication, request.SessionId, lease.Epoch, role, digest, offset, length, now);
    }

    private RegionalHostReportProof Sign(string cell, string node, string artifact, RegionalHostReportKind kind, byte[] payload)
    {
        var now = clock.GetUtcNow();
        if (now < request.IssuedAt || lease.ExpiresAt <= now || cell != request.Enrollment.Region.ToLowerInvariant() ||
            node != request.Enrollment.NodeId)
            throw new InvalidOperationException("The host report is outside this current process session.");
        var role = AdmittedRoleCatalog.All.SingleOrDefault(value => value.ArtifactKey == artifact)
            ?? throw new InvalidOperationException("The host report artifact has no admitted workload role.");
        return RegionalHostReportProof.Sign(request.Enrollment, authentication, request.SessionId, lease.Epoch, role.Role, kind, payload, now);
    }
}

