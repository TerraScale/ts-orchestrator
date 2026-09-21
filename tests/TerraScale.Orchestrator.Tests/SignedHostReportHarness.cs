using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

internal sealed class SignedHostReportHarness : IAsyncDisposable
{
    private SignedHostReportHarness(NatsControlR3L0cFixture cluster) => Cluster = cluster;
    internal NatsControlR3L0cFixture Cluster { get; }
    internal NatsClient Controller { get; private set; } = null!;
    internal INatsKVStore Runtime { get; private set; } = null!;
    internal INatsKVStore Sessions { get; private set; } = null!;
    internal SessionMaterial Material { get; private set; } = null!;
    internal RegionalHostSessionAuthority Authority { get; private set; } = null!;
    internal RegionalHostSessionService SessionService { get; private set; } = null!;
    private HostObservationRelay? relay;
    internal HostObservationRelay Relay => relay ?? throw new InvalidOperationException("The report relay is stopped.");
    internal ReportHost First { get; private set; } = null!;
    internal ReportHost Second { get; private set; } = null!;
    internal SessionAuthorizedHostReportReader Reader => new(Runtime, Authority, Material.Clock);

    internal static async Task<SignedHostReportHarness> StartAsync(CancellationToken cancellationToken, bool realTime = false)
    {
        var harness = new SignedHostReportHarness(await NatsControlR3L0cFixture.StartAsync(cancellationToken));
        try
        {
            await harness.Cluster.ProvisionAsync(cancellationToken);
            harness.Controller = await harness.Cluster.ConnectAsync(harness.Cluster.Controller, cancellationToken: cancellationToken);
            var stores = harness.Controller.CreateJetStreamContext().CreateKeyValueStoreContext();
            harness.Runtime = await stores.GetStoreAsync("ORCH_RUNTIME", cancellationToken);
            harness.Sessions = await stores.GetStoreAsync("ORCH_NODE_ENROLLMENTS", cancellationToken);
            var identity = harness.Cluster.HostAgent;
            var authentication = NatsAuthenticationFiles.FromCredentialsFile(identity.CredentialsFile, "report test");
            harness.Material = new(authentication, identity.AccountPublicKey, "host-1", realTime);
            harness.Authority = new(harness.Sessions, harness.Material.Policy(), harness.Material.Clock);
            harness.SessionService = await RegionalHostSessionService.StartAsync(harness.Controller.Connection, harness.Authority, cancellationToken);
            harness.relay = await HostObservationRelay.StartAsync(harness.Controller.Connection, harness.Runtime, harness.Authority, cancellationToken);
            harness.First = await harness.AdmitAsync(identity, AdmittedRole.TerraBaseMember, cancellationToken);
            harness.Second = await harness.AdmitAsync(harness.Cluster.HostAgentTwo, AdmittedRole.Authentication, cancellationToken);
            return harness;
        }
        catch { await harness.DisposeAsync(); throw; }
    }

    private async Task<ReportHost> AdmitAsync(NatsControlR3L0cFixture.NatsControlR3L0cIdentity identity,
        AdmittedRole role, CancellationToken cancellationToken)
    {
        var authentication = NatsAuthenticationFiles.FromCredentialsFile(identity.CredentialsFile, "report test");
        var client = await Cluster.ConnectAsync(identity, cancellationToken: cancellationToken);
        try
        {
            var enrollment = Material.Enroll(1, authentication: authentication, scope: new("production", [role]), node: identity.Name);
            var request = Material.Request(enrollment, authentication: authentication);
            var lease = await new NatsRegionalHostSessionClient(client.Connection, "gru", identity.Name).SendAsync(request, cancellationToken);
            if (!lease.Accepted) throw new InvalidOperationException($"Test enrollment was denied: {lease.Decision}.");
            return new(client, authentication, request, lease, role, Material.Clock);
        }
        catch { await client.DisposeAsync(); throw; }
    }

    internal async Task UseReportStoreAsync(INatsKVStore store, CancellationToken cancellationToken)
    {
        await StopRelayAsync();
        relay = await HostObservationRelay.StartAsync(Controller.Connection, store, Authority, cancellationToken);
    }

    internal async Task StopRelayAsync()
    {
        var previous = relay;
        relay = null;
        if (previous is not null) await previous.DisposeAsync();
    }

    public async ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        var previous = relay;
        relay = null;
        foreach (var resource in new IAsyncDisposable?[] { previous, SessionService, First?.Client, Second?.Client, Controller })
        {
            try { if (resource is not null) await resource.DisposeAsync(); }
            catch (Exception exception) { failures.Add(exception); }
        }
        try { Material?.Dispose(); }
        finally { await Cluster.DisposeAsync(); }
        if (failures.Count > 0) throw new AggregateException(failures);
    }

    internal sealed class ReportHost
    {
        internal ReportHost(NatsClient client, NatsAuthenticationFiles authentication, RegionalHostSessionRequest request,
            RegionalHostSessionResponse lease, AdmittedRole role, TimeProvider clock)
        {
            Client = client;
            Authentication = authentication;
            Request = request;
            Lease = lease;
            Role = role;
            Signer = new(request, lease, authentication, clock);
            Publisher = new(client.Connection, "gru", request.Enrollment.NodeId, () => Signer);
        }
        internal NatsClient Client { get; }
        internal NatsAuthenticationFiles Authentication { get; }
        internal RegionalHostSessionRequest Request { get; }
        internal RegionalHostSessionResponse Lease { get; }
        internal AdmittedRole Role { get; }
        internal RegionalHostSessionSigner Signer { get; }
        internal NatsHostObservationPublisher Publisher { get; }
        internal string Node => Request.Enrollment.NodeId;
        internal string Artifact => AdmittedRoleCatalog.Get(Role).ArtifactKey;
    }
}
