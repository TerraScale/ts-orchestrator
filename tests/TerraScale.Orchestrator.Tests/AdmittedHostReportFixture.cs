using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Controller-side test writer for signed reports; does not simulate host relay ingress.</summary>
internal sealed class AdmittedHostReportFixture : IDisposable
{
    private AdmittedHostReportFixture(INatsKVStore runtime, SessionMaterial material,
        RegionalHostSessionAuthority authority, RegionalHostSessionRequest acquire, ulong epoch, AdmittedRole role)
    {
        Runtime = runtime;
        Material = material;
        Authority = authority;
        Acquire = acquire;
        Epoch = epoch;
        Role = role;
        Reader = new(runtime, authority, material.Clock);
    }

    internal INatsKVStore Runtime { get; }
    internal SessionMaterial Material { get; }
    internal RegionalHostSessionAuthority Authority { get; }
    internal RegionalHostSessionRequest Acquire { get; }
    internal ulong Epoch { get; }
    internal AdmittedRole Role { get; }
    internal SessionAuthorizedHostReportReader Reader { get; }
    internal string Node => Acquire.Enrollment.NodeId;

    internal static async Task<AdmittedHostReportFixture> CreateAsync(NatsClient client, INatsKVStore runtime,
        CancellationToken cancellationToken, string? node = null, AdmittedRole role = AdmittedRole.TerraBaseMember, bool realTime = false)
    {
        var material = new SessionMaterial(node: node, realTime: realTime);
        try
        {
            var sessions = await client.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync("ORCH_NODE_ENROLLMENTS", cancellationToken);
            var authority = new RegionalHostSessionAuthority(sessions, material.Policy(), material.Clock);
            var acquire = material.Request(material.Enroll(1, scope: new("production", [role])));
            var lease = await authority.ProcessAsync(acquire, cancellationToken);
            if (!lease.Accepted) throw new InvalidOperationException($"Test session denied: {lease.Decision}.");
            return new(runtime, material, authority, acquire, lease.Epoch, role);
        }
        catch { material.Dispose(); throw; }
    }

    internal StoredHostReport Sign(HostAdmissionObservation report) => new(1,
        RegionalHostReportProof.Sign(Acquire.Enrollment, Material.Authentication, Acquire.SessionId, Epoch, Role,
            RegionalHostReportKind.Admission,
            JsonSerializer.SerializeToUtf8Bytes(report, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation),
            Material.Clock.GetUtcNow()), report, null);

    internal StoredHostReport Sign(HostConvergenceObservation report) => new(1,
        RegionalHostReportProof.Sign(Acquire.Enrollment, Material.Authentication, Acquire.SessionId, Epoch, Role,
            RegionalHostReportKind.Runtime,
            JsonSerializer.SerializeToUtf8Bytes(report, HostConvergenceJsonContext.Default.HostConvergenceObservation),
            Material.Clock.GetUtcNow()), null, report);

    internal async Task PutAsync(StoredHostReport report, CancellationToken cancellationToken, string? key = null) =>
        _ = await Runtime.PutAsync(key ?? report.Key,
            JsonSerializer.Serialize(report, RegionalHostSessionAuthority.JsonOptions), cancellationToken: cancellationToken);

    public void Dispose() => Material.Dispose();
}
