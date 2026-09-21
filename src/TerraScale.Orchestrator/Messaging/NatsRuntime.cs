using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Client.Services;
using NATS.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Messaging;

public sealed class NatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalRuntimeMembership membership;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly INatsSvcServer service;
    private readonly INatsJSConsumer? cellSpecConsumer;
    private readonly INatsKVStore? delivery;
    private readonly INatsKVStore runtimeStore;
    private readonly INatsObjStore? bundles;
    private readonly NatsTopology topology;
    private readonly DirectDeliveryService? directDelivery;
    private readonly INatsSvcServer? directDeliveryService;
    private readonly CandidateEvidenceHandoffV2AdmissionRuntime? candidateHandoffV2Admission;
    private readonly ServiceEndpointInstrumentation serviceInstrumentation;
    private readonly HostObservationRelay? hostReports;
    private readonly RegionalHostSessionService? hostSessions;
    private readonly RegionalHostDesiredService? hostDesired;
    private readonly ControlPlane.TerraBase.TerraBasePlacementReconcilerRuntime? terrabasePlacement;
    private readonly Nodes.OciMemberHostFleet? memberHostFleet;
    private readonly WorkloadAutoscalerService? workloadAutoscaler;
    private readonly IDisposable? workloadReplicaDriver;
    private readonly OperatorStatusCache operatorStatus;

    private NatsRuntime(
        NatsClient client,
        INatsSvcServer service,
        RegionalRuntimeMembership membership,
        RegionalAuthorityCoordinator authority,
        INatsJSConsumer? cellSpecConsumer,
        INatsKVStore? delivery,
        INatsKVStore runtimeStore,
        INatsObjStore? bundles,
        NatsTopology topology,
        DirectDeliveryService? directDelivery,
        INatsSvcServer? directDeliveryService,
        CandidateEvidenceHandoffV2AdmissionRuntime? candidateHandoffV2Admission,
        ServiceEndpointInstrumentation serviceInstrumentation,
        HostObservationRelay? hostReports,
        ControlPlane.TerraBase.TerraBasePlacementReconcilerRuntime? terrabasePlacement,
        Nodes.OciMemberHostFleet? memberHostFleet,
        WorkloadAutoscalerService? workloadAutoscaler,
        IDisposable? workloadReplicaDriver,
        OperatorStatusCache operatorStatus,
        RegionalHostSessionService? hostSessions,
        RegionalHostDesiredService? hostDesired)
    {
        this.client = client;
        this.service = service;
        this.membership = membership;
        this.authority = authority;
        this.cellSpecConsumer = cellSpecConsumer;
        this.delivery = delivery;
        this.runtimeStore = runtimeStore ?? throw new ArgumentNullException(nameof(runtimeStore));
        this.bundles = bundles;
        this.topology = topology;
        this.directDelivery = directDelivery;
        this.directDeliveryService = directDeliveryService;
        this.candidateHandoffV2Admission = candidateHandoffV2Admission;
        this.serviceInstrumentation = serviceInstrumentation;
        this.hostReports = hostReports;
        this.terrabasePlacement = terrabasePlacement;
        this.memberHostFleet = memberHostFleet;
        this.workloadAutoscaler = workloadAutoscaler;
        this.workloadReplicaDriver = workloadReplicaDriver;
        this.operatorStatus = operatorStatus ?? throw new ArgumentNullException(nameof(operatorStatus));
        this.hostSessions = hostSessions;
        this.hostDesired = hostDesired;
    }

    public Task Completion => Task.WhenAny(new[] { authority.Completion, membership.Completion }
        .Concat(hostReports is null ? [] : new[] { hostReports.Completion })
        .Concat(hostDesired is null ? [] : new[] { hostDesired.Completion })
        .Concat(hostSessions is null ? [] : new[] { hostSessions.Completion })).Unwrap();
    internal RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;
    internal RegionalRuntimeMembershipSnapshot MembershipSnapshot => membership.Snapshot;
    internal RegionalRuntimeMembershipHealth MembershipHealth => membership.Health;
    internal string Cell => topology.Cell;
    internal DirectDeliveryService? DirectDelivery => directDelivery;
    internal CandidateEvidenceHandoffV2AdmissionRuntime? CandidateHandoffV2Admission => candidateHandoffV2Admission;
    internal OperatorStatusDocument? LatestOperatorStatus => operatorStatus.Value;

    private volatile Observability.OrchestratorTelemetry? serviceTelemetry;

    /// <summary>
    /// The live authority lease still owns a delivery's admission. The fencing epoch is the
    /// comparison basis because it identifies the lease TERM: a renewal rewrites the lease
    /// (and its KV revision) every tick without touching the epoch, so a delivery admitted
    /// under a lease must survive its own leader's renewals mid-flight and on replay, while
    /// every superseded leader — a new acquisition, holder, or term — advances the epoch and
    /// still fences. Comparing the raw KV revision here would fence every delivery that
    /// straddles one renewal tick and pin its durable record out forever.
    /// </summary>
    internal static bool AuthorityIsCurrent(RegionalAuthoritySnapshot current, DeliveryRequest request) =>
        current.Ready && current.IsLeader &&
        current.Epoch == request.AuthorityGeneration &&
        current.Epoch == request.WriterEpoch;

    /// <summary>
    /// Only the current authority leader may execute a direct-delivery mutation. The mutation
    /// endpoint is registered WITHOUT a queue group (see <see cref="DirectDeliveryServiceConfig"/>),
    /// so every controller receives each request and the leader answers it; a follower or an
    /// election-window receiver drops the request without replying — it can never execute the
    /// mutation, and replying would race the leader's authoritative receipt (and historically
    /// surfaced as a misleading authorization denial).
    /// </summary>
    internal static bool ServesDirectDeliveryRequests(RegionalAuthoritySnapshot lease) =>
        lease.Ready && lease.IsLeader;

    /// <summary>
    /// The direct-delivery mutation service: deliberately outside the shared controller queue
    /// group. Queue-group delivery would hand each request to one random controller while only
    /// the leader can execute, making success per-attempt luck and every follower hit an
    /// authorization-shaped denial; without a queue group every controller receives the request
    /// and exactly the leader replies.
    /// </summary>
    internal static NatsSvcConfig DirectDeliveryServiceConfig(NatsTopology topology, string instance) => new(
        $"{topology.ServiceName}_direct_delivery",
        "1.0.0")
    {
        Description = "TerraScale direct delivery mutation service",
        Metadata = new Dictionary<string, string>
        {
            ["cell"] = topology.Cell,
            ["instance"] = instance
        },
        UseQueueGroup = false
    };

    /// <summary>
    /// Attaches the process telemetry so service endpoint statistics also flow into
    /// the bounded NATS instruments. Optional: without it the read-only stats
    /// endpoint still serves the same statistics; only OTLP export is absent.
    /// </summary>
    internal void AttachServiceTelemetry(Observability.OrchestratorTelemetry telemetry)
    {
        ArgumentNullException.ThrowIfNull(telemetry);
        serviceTelemetry = telemetry;
        serviceInstrumentation.Telemetry = telemetry;
        if (hostReports is not null) telemetry.ObserveHostReports(() => hostReports.Snapshot);
        if (hostSessions is not null) telemetry.ObserveHostSessions(() => hostSessions.Snapshot);
        if (hostDesired is not null) telemetry.ObserveHostDesired(() => hostDesired.Snapshot);
    }

    /// <summary>
    /// Wraps one service endpoint handler: requests, errors, and latency are
    /// recorded per bounded endpoint name — never per subject, requester, or
    /// payload — and served through the read-only stats endpoint.
    /// </summary>
    private sealed class ServiceEndpointInstrumentation
    {
        internal NatsServiceEndpointStats Stats { get; } = new();

        internal async ValueTask HandleAsync(
            NatsServiceEndpointName endpoint,
            NatsSvcMsg<string> message,
            Func<Task> body)
        {
            var timestamp = Stopwatch.GetTimestamp();
            var result = NatsServiceRequestResult.Ok;
            try
            {
                await body();
            }
            catch
            {
                result = NatsServiceRequestResult.Error;
                throw;
            }
            finally
            {
                var elapsed = Stopwatch.GetElapsedTime(timestamp);
                Stats.Record(endpoint, result, elapsed);
                Telemetry?.RecordNatsServiceRequest(endpoint, result, elapsed.TotalMilliseconds);
            }
        }

        internal Observability.OrchestratorTelemetry? Telemetry { get; set; }
    }

    private sealed class OperatorStatusCache
    {
        private OperatorStatusDocument? value;

        internal OperatorStatusDocument? Value => Volatile.Read(ref value);

        internal void Set(OperatorStatusDocument status) => Volatile.Write(ref value, status);
    }

    internal NativeGitOpsCellNatsConsumer CreateNativeGitOpsConsumer()
    {
        var ledger = new NatsForgejoDeliveryLedger(delivery
            ?? throw new InvalidOperationException("Native GitOps delivery storage is not configured."));
        var objects = new NatsDeliveryObjectStore(bundles
            ?? throw new InvalidOperationException("Native GitOps bundle storage is not configured."));
        return new NativeGitOpsCellNatsConsumer(
            cellSpecConsumer ?? throw new InvalidOperationException("Native GitOps consumer is not configured."),
            new NativeGitOpsCellInbox(new NativeGitOpsCellAcceptanceJournal(ledger, objects)),
            topology);
    }

    internal NativeGitOpsCellConvergenceJournal CreateNativeGitOpsConvergenceJournal() =>
        new(new NatsForgejoDeliveryLedger(delivery
            ?? throw new InvalidOperationException("Native GitOps delivery storage is not configured.")));

    internal NativeGitOpsCellPublisher CreateNativeGitOpsPublisher() =>
        new(new NatsNativeGitOpsCellTransport(client));

    public static async Task<NatsRuntime> StartAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken,
        Protocol.ICommandSignatureVerifier? commandSignatureVerifier = null,
        bool registersDirectDeliveryEndpoint = true,
        DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null,
        Protocol.ICommandSignatureVerifier? ciArtifactSignatures = null,
        CandidateEvidenceHandoffV2AdmissionPolicyCatalog? candidateHandoffV2Policies = null,
        bool autoProvision = true,
        ControlPlane.TerraBase.TerraBaseReconcilerConfiguration? terrabaseConfiguration = null,
        Nodes.OciMemberHostFleetConfigurationFile? memberFleet = null,
        Nodes.OciWorkloadFleetConfigurationFile? workloadFleet = null,
        RegionalHostSessionConfiguration? hostSessions = null)
    {
        if (options.Command is not (OrchestratorCommand.Run or OrchestratorCommand.Check))
            throw new InvalidOperationException("Only controller run/check roles can start the regional controller runtime.");
        hostSessions?.ValidateStartup(options, hasHostRoles: false);
        if (options.Command == OrchestratorCommand.Run && (memberFleet is not null || workloadFleet is not null) && hostSessions is null)
            throw new InvalidOperationException("OCI workload controllers require TS_ORCH_HOST_SESSION_POLICY_FILE before creating hosts.");
        if ((terrabaseConfiguration is null) != (memberFleet is null))
            throw new InvalidOperationException(
                "TS_ORCH_TERRABASE_RECONCILER and TS_ORCH_MEMBER_FLEET_FILE must be configured together: " +
                "the placement reconciler never runs without its member-host fleet.");
        Nodes.OciWorkloadFleetComposition.Validate(terrabaseConfiguration is not null, workloadFleet);
        var natsUrl = OrchestratorOptions.ParseRegionalNatsUrl(options.NatsUrl, "TS_ORCH_NATS_URL");
        var topology = new NatsTopology(options.Cell, options.Replicas, options.Instance);
        var clientOptions = new NatsOpts
        {
            Url = natsUrl.ToString(),
            RetryOnInitialConnect = true,
            RequestTimeout = TimeSpan.FromSeconds(15)
        };
        var authentication = NatsAuthenticationFiles.Resolve(options.NatsNKeyFile, options.NatsCredentialsFile, "TS_ORCH_NATS");
        if (authentication is not null)
        {
            clientOptions = clientOptions with
            {
                AuthOpts = authentication.Options,
                InboxPrefix = TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.ControllerInboxPrefix(
                    options.Cell, authentication.PublicKey)
            };
        }
        if (options.NatsTls is not null)
        {
            clientOptions = clientOptions with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = options.NatsTls.CaFile,
                    CertFile = options.NatsTls.CertificateFile,
                    KeyFile = options.NatsTls.KeyFile
                }
            };
        }
        var client = new NatsClient(clientOptions);

        RegionalRuntimeMembership? membership = null;
        RegionalAuthorityCoordinator? authority = null;
        HostObservationRelay? hostReportRelay = null;
        RegionalHostSessionService? hostSessionService = null;
        RegionalHostDesiredService? hostDesiredService = null;
        IAuthorizedHostReportReader? authorizedHostReports = null;
        ControlPlane.TerraBase.TerraBasePlacementReconcilerRuntime? terrabasePlacementRuntime = null;
        Nodes.OciMemberHostFleet? memberHostFleet = null;
        WorkloadAutoscalerService? workloadAutoscalerRuntime = null;
        Nodes.OciWorkloadReplicaDriver? workloadReplicaDriver = null;
        try
        {
            await client.ConnectAsync().AsTask().WaitAsync(cancellationToken);
            if (authentication is not null || options.NatsTls is not null)
            {
                await VerifyAnonymousDeniedAsync(natsUrl.ToString(), options.NatsTls, cancellationToken);
            }
            if (autoProvision && options.Command == OrchestratorCommand.Run)
            {
                // Auto-forming cells: every controller converges the shared controller topology
                // idempotently before opening it, so the first instance creates the cell and
                // later instances join it with no operator step. CreateOrUpdate makes concurrent
                // bootstraps converge; the infrastructure-only ORCH_OPERATIONS journal is
                // deliberately absent here.
                await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                    client, topology, cancellationToken);
            }
            var nativeGitOpsEnabled = NativeGitOpsRuntime.IsEnabled(
                options.GlobalNats is not null &&
                    GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed(options.Cell),
                options.CommandIdentity?.TrustKeyFiles.Count > 0);
            var state = await OpenStateWithRetryAsync(
                client, topology, nativeGitOpsEnabled, cancellationToken);
            await VerifyProtocolPackageAsync(state.ProtocolPackage, topology, cancellationToken);
            await VerifyDurableMessagingAsync(client, state.StartupConsumer, topology, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartAsync(
                state.Leaders,
                options.Cell,
                options.Instance,
                cancellationToken);

            var startedAt = DateTimeOffset.UtcNow;
            var capabilities = new List<string>
            {
                "authority",
                "authority-election",
                "delivery",
                "messaging",
                "observability",
                "operator-read",
                "provider-ownership",
                "reconciliation",
                "regional-membership",
                "runtime",
                "scheduler",
                "security",
                "service-discovery",
                "storage",
                "terrabase"
            };
            if (authentication is not null)
            {
                capabilities.Add(authentication.CredentialsFile is null ? "nats-nkey-authenticated" : "nats-jwt-authenticated");
            }
            if (options.NatsTls is not null)
            {
                capabilities.Add("nats-mtls");
            }
            if (terrabaseConfiguration is not null)
            {
                capabilities.Add("terrabase-placement");
            }
            if (workloadFleet is not null)
            {
                capabilities.Add("independent-workload-autoscaling");
            }
            capabilities.Sort(StringComparer.Ordinal);
            membership = await RegionalRuntimeMembership.StartAsync(
                state.Runtime,
                topology,
                BuildVersion.Current.DisplayName,
                capabilities,
                startedAt,
                () => authority.Snapshot,
                cancellationToken);

            DirectDeliveryService? directDelivery = null;
            INatsSvcServer? directDeliveryService = null;
            CandidateEvidenceHandoffV2AdmissionRuntime? candidateHandoffV2Admission = null;
            if (state.Delivery is not null)
            {
                var ledger = new NatsForgejoDeliveryLedger(state.Delivery);
                var artifactSignatureVerifier = ciArtifactSignatures as IRepositoryCiArtifactSignatureVerifier;
                // Composition fails closed here without the evidence verifier or the
                // configured admitted-target allow-list, mirroring the signed-command rule.
                // The evidence verifier is the CI artifact role's trust root, supplied
                // explicitly by composition; this runtime performs no fallback of its own.
                var adapters = DirectDeliveryRuntimeAdapterSet.Create(
                    ledger,
                    () => authority.Snapshot.Ready && authority.Snapshot.IsLeader,
                    request => AuthorityIsCurrent(authority.Snapshot, request),
                    admittedDeliveryTargets,
                    artifactSignatureVerifier);
                directDelivery = new DirectDeliveryService(
                    adapters.Authorizer,
                    adapters.Provenance,
                    adapters.TargetResolver,
                    adapters.Journal,
                    adapters.ArtifactBuilder,
                    auditIdFactory: static () => $"audit-{Guid.NewGuid():N}",
                    authorityIsCurrent: request => AuthorityIsCurrent(authority.Snapshot, request));
                candidateHandoffV2Admission = CandidateEvidenceHandoffV2AdmissionRuntime.ComposeProduction(
                    ledger,
                    artifactSignatureVerifier!,
                    candidateHandoffV2Policies ?? CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Empty);
            }

            var services = client.CreateServicesContext();
            var service = await services.AddServiceAsync(
                new NatsSvcConfig(topology.ServiceName, "1.0.0")
                {
                    Description = "TerraScale regional control service",
                    Metadata = new Dictionary<string, string>
                    {
                        ["cell"] = options.Cell,
                        ["instance"] = options.Instance
                    },
                    QueueGroup = topology.ServiceQueueGroup
                },
                cancellationToken);

            // Service endpoint statistics (issue #23): every endpoint handler is
            // wrapped so requests, errors, and latency are recorded per bounded
            // endpoint name — never per subject, requester, or payload — and served
            // back through the read-only stats endpoint.
            var endpointInstrumentation = new ServiceEndpointInstrumentation();
            var operatorStatus = new OperatorStatusCache();
            ValueTask HandleAsync(
                NatsServiceEndpointName endpoint,
                NatsSvcMsg<string> message,
                Func<Task> body) =>
                endpointInstrumentation.HandleAsync(endpoint, message, body);

            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.Health,
                    message,
                    async () => await message.ReplyAsync(
                        authority.Snapshot.Ready ? "ready" : "not-ready",
                        cancellationToken: cancellationToken)),
                name: "health",
                subject: topology.HealthSubject,
                metadata: new Dictionary<string, string> { ["protocol"] = "1" },
                cancellationToken: cancellationToken);

            if (directDelivery is not null)
            {
                // The direct-delivery mutation endpoint is only as strong as its admission seam:
                // fail closed at startup in run mode without a signed-command verifier instead of
                // ever accepting an unsigned production mutation. The startup plan owns the
                // decision (Run-only); this runtime never re-derives it from options.
                if (registersDirectDeliveryEndpoint && commandSignatureVerifier is null)
                    throw new InvalidOperationException(
                        "The direct delivery mutation endpoint requires a configured command identity verifier.");
                if (registersDirectDeliveryEndpoint && commandSignatureVerifier is not null)
                {
                    var handoffDelivery = new TerraScale.Orchestrator.Delivery.DeployHandoff.DeployHandoffDeliveryRuntime(directDelivery);
                    // Registered on its own queue-group-free service (DirectDeliveryServiceConfig),
                    // not the shared controller queue group: only the leader can execute, so
                    // queue-group load balancing would make every attempt a lottery.
                    directDeliveryService = await services.AddServiceAsync(
                        DirectDeliveryServiceConfig(topology, options.Instance),
                        cancellationToken);
                    await directDeliveryService.AddEndpointAsync<string>(
                        message => HandleAsync(
                            NatsServiceEndpointName.DirectDelivery,
                            message,
                            async () =>
                            {
                                // A follower (or an election-window receiver) never executes and
                                // never replies: the current leader receives its own copy of the
                                // same request and answers it.
                                if (!ServesDirectDeliveryRequests(authority.Snapshot))
                                    return;
                                // Three payload kinds share the signed seam. Direct requests and v1
                                // mappings can execute with Orchestrator authority. V2 candidate
                                // evidence stops after admission and keeps every authority field zero.
                                // The lease's fencing epoch stamps BOTH the authority generation and
                                // the writer epoch: it is the stable lease term, so a request signed
                                // against it stays current across the leader's own renewals (which
                                // only advance the KV revision) and is fenced by any new term.
                                var lease = authority.Snapshot;
                                var payload = Encoding.UTF8.GetBytes(message.Data ?? string.Empty);
                                var admission = DirectDeliveryCommandIngress.Decode(
                                    payload,
                                    Flatten(message.Headers),
                                    options.Cell,
                                    DateTimeOffset.UtcNow,
                                    TimeSpan.FromMinutes(5),
                                    commandSignatureVerifier,
                                    lease.Epoch,
                                    lease.Epoch);
                                var response = admission.Kind switch
                                {
                                    DirectDeliveryCommandPayloadKind.DeliveryRequest when admission.Request is { } request =>
                                        DeliveryWireCodec.SerializeReceipt(
                                            await directDelivery.DeliverAsync(request, cancellationToken)
                                                .ConfigureAwait(false)),
                                    DirectDeliveryCommandPayloadKind.DeployHandoffManifest when admission.Handoff is
                                    { IsAdmittedForTargetMutation: true } mapping =>
                                        DeliveryWireCodec.SerializeReceipt(
                                            await handoffDelivery.DeliverMappedAsync(
                                                mapping, lease.Epoch, lease.Epoch, admission.Attempt, cancellationToken)
                                                .ConfigureAwait(false)),
                                    DirectDeliveryCommandPayloadKind.CandidateEvidenceHandoffV2 when
                                        admission.CandidateEvidence is { } identity &&
                                        admission.Error != DirectDeliveryCommandWireError.None =>
                                        CandidateEvidenceHandoffV2AdmissionRuntime.SerializeReceipt(
                                            CandidateEvidenceHandoffV2AdmissionRuntime.RefusedBeforeAdmission(
                                                identity,
                                                new(
                                                    "handoff_v2_outer_envelope_denied",
                                                    "The signed command envelope for candidate admission was rejected.",
                                                    "Use the admitted command identity, cell, operation, and validity window."))),
                                    DirectDeliveryCommandPayloadKind.CandidateEvidenceHandoffV2 when
                                        admission.IsAdmissionOnly && candidateHandoffV2Admission is not null =>
                                        CandidateEvidenceHandoffV2AdmissionRuntime.SerializeReceipt(
                                            await candidateHandoffV2Admission.AdmitAsync(
                                                payload,
                                                DateTimeOffset.UtcNow,
                                                cancellationToken).ConfigureAwait(false)),
                                    _ => DeliveryWireCodec.SerializeReceipt(
                                        DirectDeliveryCommandIngress.RefusalReceipt(admission)),
                                };
                                await message.ReplyAsync(
                                    response,
                                    cancellationToken: cancellationToken).ConfigureAwait(false);
                            }),
                        name: "direct_delivery",
                        subject: topology.DirectDeliverySubject,
                        metadata: new Dictionary<string, string>
                        {
                            ["protocol"] = DeliveryRequest.CurrentSchemaVersion.ToString(),
                            ["candidateEvidenceAdmission"] = CandidateEvidenceHandoffV2Contract.SchemaVersion.ToString(),
                            ["mutation"] = "direct",
                            ["admission"] = "signed-envelope",
                        },
                        cancellationToken: cancellationToken);
                }
            }

            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.InstanceHealth,
                    message,
                    async () => await message.ReplyAsync(
                        authority.Snapshot.Ready ? "ready" : "not-ready",
                        cancellationToken: cancellationToken)),
                name: "instance_health",
                subject: topology.InstanceHealthSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["instance"] = options.Instance
                },
                cancellationToken: cancellationToken);

            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.Status,
                    message,
                    async () =>
                    {
                        var authoritySnapshot = authority.Snapshot;
                        await message.ReplyAsync(
                            JsonSerializer.Serialize(
                                new RegionalControllerStatus(
                                    2,
                                    options.Cell,
                                    options.Instance,
                                    options.Replicas,
                                    authoritySnapshot.Ready,
                                    startedAt,
                                    DateTimeOffset.UtcNow,
                                    BuildVersion.Current.DisplayName,
                                    capabilities,
                                    authoritySnapshot.State,
                                    authoritySnapshot.IsLeader,
                                    authoritySnapshot.Epoch,
                                    authoritySnapshot.KvRevision,
                                    authoritySnapshot.LeaseExpiresAt),
                                RegionalControllerStatusJsonContext.Default.RegionalControllerStatus),
                            cancellationToken: cancellationToken);
                    }),
                name: "status",
                subject: topology.StatusSubject,
                metadata: new Dictionary<string, string> { ["protocol"] = "1", ["readOnly"] = "true" },
                cancellationToken: cancellationToken);

            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.Members,
                    message,
                    async () => await message.ReplyAsync(
                        JsonSerializer.Serialize(
                            membership.Snapshot,
                            RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMembershipSnapshot),
                        cancellationToken: cancellationToken)),
                name: "members",
                subject: topology.MembersSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["readOnly"] = "true",
                    ["source"] = topology.Runtime.Bucket
                },
                cancellationToken: cancellationToken);

            // The read-only service statistics endpoint (issue #23): version, schema
            // metadata, health, and per-endpoint request/error/latency statistics.
            // Its subject stays a query subject with the readOnly marker; it is not a
            // mutation surface and carries no identity, payload, or address material.
            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.Stats,
                    message,
                    async () => await message.ReplyAsync(
                        JsonSerializer.Serialize(
                            NatsServiceStatsDocument.Create(
                                options.Cell,
                                BuildVersion.Current.DisplayName,
                                // Schema metadata: the served status contract generation.
                                2,
                                authority.Snapshot.Ready,
                                DateTimeOffset.UtcNow,
                                endpointInstrumentation.Stats.Snapshot()),
                            NatsServiceEndpointStatsJsonContext.Default.NatsServiceStatsDocument),
                        cancellationToken: cancellationToken)),
                name: "stats",
                subject: topology.StatsSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["readOnly"] = "true",
                    ["schema"] = "aggregated"
                },
                cancellationToken: cancellationToken);

            // Authenticated operator status is a separate read-only query. It projects the
            // replicated desired/runtime state into bounded needs, actions, and per-workload
            // progress without exposing database names, instance ids, payloads, or secrets.
            await service.AddEndpointAsync<string>(
                message => HandleAsync(
                    NatsServiceEndpointName.OperatorStatus,
                    message,
                    async () =>
                    {
                        var status = await BuildOperatorStatusAsync(
                                delivery: state.Delivery,
                                bundles: state.Bundles,
                                runtimeStore: state.Runtime,
                                options,
                                topology,
                                startedAt,
                                cancellationToken,
                                workloadAutoscalerRuntime?.Latest,
                                workloadFleet?.Policies,
                                hostReportRelay?.Snapshot,
                                hostSessionService?.Snapshot, authorizedHostReports, hostDesiredService?.Snapshot)
                            .ConfigureAwait(false);
                        operatorStatus.Set(status);
                        await message.ReplyAsync(
                                JsonSerializer.Serialize(
                                    status,
                                    Operations.OperatorStatusJsonContext.Default.OperatorStatusDocument),
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                    }),
                name: "operator_status",
                subject: topology.OperatorStatusSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["readOnly"] = "true",
                    ["scope"] = "operator",
                    ["contains"] = "needs,actions,progress"
                },
                cancellationToken: cancellationToken);

            await VerifyServiceAsync(client, topology, cancellationToken);
            if (hostSessions is not null)
            {
                var sessionAuthority = new RegionalHostSessionAuthority(state.NodeEnrollments, hostSessions.Policy);
                hostSessionService = await RegionalHostSessionService.StartAsync(client.Connection, sessionAuthority, cancellationToken);
                hostDesiredService = await RegionalHostDesiredService.StartAsync(client.Connection, new(state.Delivery ?? throw new InvalidOperationException("Host sessions require the regional delivery store."), sessionAuthority), cancellationToken);
                hostReportRelay = await HostObservationRelay.StartAsync(client.Connection, state.Runtime, sessionAuthority, cancellationToken);
                authorizedHostReports = new SessionAuthorizedHostReportReader(state.Runtime, sessionAuthority);
            }

            if (terrabaseConfiguration is not null && state.Delivery is not null)
            {
                // The TerraBase placement reconciler: same durable stores and fenced authority
                // lease as the controller, leader-gated to one member action per tick. The OCI
                // fleet is composed here because only here do the live lease, the ORCH_RUNTIME
                // store, and the cell connection it needs all exist; every fleet mutation
                // re-checks the lease through the same gate direct delivery uses.
                var seams = new Nodes.NatsMemberHostSeams(authorizedHostReports ??
                    throw new InvalidOperationException("The OCI member fleet requires authorized host reports."), state.Delivery, client.Connection,
                    options.Cell, memberFleet!.Environment, TimeProvider.System);
                memberHostFleet = new Nodes.OciMemberHostFleet(
                    ControlPlane.Providers.OciMemberHostSdkTransport.CreateForInstancePrincipal(
                        memberFleet!.Endpoint.ToString()),
                    memberFleet.ForCell(options.Cell),
                    () => ServesDirectDeliveryRequests(authority.Snapshot),
                    seams,
                    seams,
                    TimeProvider.System);
                terrabasePlacementRuntime = await ControlPlane.TerraBase.TerraBasePlacementReconcilerRuntime.StartAsync(
                    state.Delivery,
                    state.Runtime,
                    () => authority.Snapshot,
                    new(terrabaseConfiguration, memberHostFleet),
                    options.Cell,
                    cancellationToken);
            }

            if (workloadFleet is not null)
            {
                if (state.Delivery is null || state.Bundles is null)
                    throw new InvalidOperationException(
                        "The OCI workload fleet requires regional delivery and bundle stores.");
                if (!string.Equals(workloadFleet.Region, options.Cell.ToUpperInvariant(), StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        $"The OCI workload fleet region {workloadFleet.Region} does not match cell {options.Cell}.");
                var desiredReader = new NatsWorkloadDesiredStateReader(state.Delivery, state.Bundles, options.Cell);
                workloadReplicaDriver = new Nodes.OciWorkloadReplicaDriver(
                    Nodes.OciWorkloadComputeTransport.CreateForInstancePrincipal(workloadFleet.Endpoint.ToString()),
                    workloadFleet,
                    state.Runtime,
                    desiredReader.ReadAsync,
                    () => ServesDirectDeliveryRequests(authority.Snapshot),
                    options.Cell,
                    authorizedHostReports);
                workloadAutoscalerRuntime = WorkloadAutoscalerService.Start(
                    new IndependentWorkloadAutoscalerRuntime(
                        new IndependentWorkloadAutoscaler(workloadFleet.Policies),
                        workloadReplicaDriver));
                workloadAutoscalerRuntime.DecisionUpdated = decisions =>
                    _ = RefreshOperatorStatusAsync(
                        operatorStatus,
                        state.Delivery,
                        state.Bundles,
                        state.Runtime,
                        options,
                        topology,
                        startedAt,
                        cancellationToken,
                        decisions,
                        workloadFleet.Policies,
                        hostReportRelay?.Snapshot,
                        hostSessionService?.Snapshot, authorizedHostReports, hostDesiredService?.Snapshot);
            }

            // Seed the projection before returning the runtime so workload gauges are useful
            // immediately after startup, without requiring an operator query first.
            operatorStatus.Set(await BuildOperatorStatusAsync(
                    state.Delivery,
                    state.Bundles,
                    state.Runtime,
                    options,
                    topology,
                    startedAt,
                    cancellationToken,
                    workloadAutoscalerRuntime?.Latest,
                    workloadFleet?.Policies,
                    hostReportRelay?.Snapshot,
                    hostSessionService?.Snapshot, authorizedHostReports, hostDesiredService?.Snapshot)
                .ConfigureAwait(false));

            return new(
                client,
                service,
                membership,
                authority,
                state.CellSpecConsumer,
                state.Delivery,
                state.Runtime,
                state.Bundles,
                topology,
                directDelivery,
                directDeliveryService,
                candidateHandoffV2Admission,
                endpointInstrumentation,
                hostReportRelay,
                terrabasePlacementRuntime,
                memberHostFleet,
                workloadAutoscalerRuntime,
                workloadReplicaDriver,
                operatorStatus,
                hostSessionService,
                hostDesiredService);
        }
        catch
        {
            if (authority is not null)
            {
                await authority.DisposeAsync();
            }
            if (membership is not null)
            {
                await membership.DisposeAsync();
            }
            memberHostFleet?.Dispose();
            if (workloadAutoscalerRuntime is not null)
                await workloadAutoscalerRuntime.DisposeAsync();
            workloadReplicaDriver?.Dispose();
            if (hostDesiredService is not null) await hostDesiredService.DisposeAsync();
            if (hostSessionService is not null) await hostSessionService.DisposeAsync();
            if (hostReportRelay is not null) await hostReportRelay.DisposeAsync();
            await client.DisposeAsync();
            throw;
        }
    }

    internal static async Task<OperatorStatusDocument> BuildOperatorStatusAsync(
        INatsKVStore? delivery,
        INatsObjStore? bundles,
        INatsKVStore runtimeStore,
        OrchestratorOptions options,
        NatsTopology topology,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken,
        IReadOnlyList<WorkloadScaleDecision>? scalingDecisions = null,
        IReadOnlyList<WorkloadScalePolicy>? scalingPolicies = null,
        HostReportRelaySnapshot? hostReportSnapshot = null,
        RegionalHostSessionServiceSnapshot? hostSessionSnapshot = null,
        IAuthorizedHostReportReader? authorizedHostReports = null,
        RegionalHostDesiredSnapshot? hostDesiredSnapshot = null)
    {
        const int maximumKeys = 512;
        var desired = new Dictionary<string, (int Replicas, long Generation, string? Digest)>(StringComparer.Ordinal);
        var observed = new Dictionary<string, List<AuthorizedHostReport>>(StringComparer.Ordinal);
        var admittedUntil = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        var needs = new HashSet<string>(StringComparer.Ordinal);
        var actions = new List<OperatorActionStatus>();

        // The accepted CellSpec pointer and its immutable object are the only source of
        // desired replica counts. This keeps ts-auth and TerraBase scaling independent and
        // makes the status view reflect the exact admitted generation.
        if (delivery is not null && bundles is not null)
        {
            var acceptedKeys = new List<string>(maximumKeys);
            try
            {
                await foreach (var key in delivery.GetKeysAsync(
                    ["gitops.cell.>"],
                    new NatsKVWatchOpts { IgnoreDeletes = true },
                    cancellationToken).ConfigureAwait(false))
                {
                    acceptedKeys.Add(key);
                    if (acceptedKeys.Count == maximumKeys) break;
                }
            }
            catch (NatsKVException exception)
            {
                needs.Add($"desired-state-read:{exception.GetType().Name}");
            }

            foreach (var key in acceptedKeys)
            {
                try
                {
                    var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    entry.EnsureSuccess();
                    using var pointer = JsonDocument.Parse(entry.Value ?? string.Empty);
                    var root = pointer.RootElement;
                    if (!root.TryGetProperty("cell", out var cell) || cell.GetString() != topology.Cell ||
                        !root.TryGetProperty("payloadObject", out var payloadObject))
                        continue;
                    var payload = await bundles.GetBytesAsync(payloadObject.GetString() ?? string.Empty, cancellationToken)
                        .ConfigureAwait(false);
                    using var document = JsonDocument.Parse(payload);
                    var generation = document.RootElement.TryGetProperty("generation", out var generationValue) &&
                                     generationValue.TryGetInt64(out var parsedGeneration)
                        ? parsedGeneration
                        : 0;
                    if (!document.RootElement.TryGetProperty("desiredWorkloads", out var workloads) ||
                        workloads.ValueKind != JsonValueKind.Array)
                        continue;
                    foreach (var workload in workloads.EnumerateArray())
                    {
                        if (workload.TryGetProperty("suspended", out var suspended) && suspended.GetBoolean())
                            continue;
                        if (!workload.TryGetProperty("cells", out var cells) ||
                            !cells.EnumerateArray().Any(cellValue => cellValue.GetString() == topology.Cell) ||
                            !workload.TryGetProperty("role", out var roleValue) ||
                            !Enum.TryParse<AdmittedRole>(roleValue.GetString(), ignoreCase: false, out var role) ||
                            !Enum.IsDefined(role))
                            continue;
                        var descriptor = AdmittedRoleCatalog.Get(role);
                        var replicas = workload.TryGetProperty("replicas", out var replicasValue) &&
                                       replicasValue.TryGetInt32(out var parsedReplicas)
                            ? parsedReplicas
                            : descriptor.MinimumReplicas;
                        var current = desired.GetValueOrDefault(descriptor.ArtifactKey);
                        var digest = workload.TryGetProperty("artifactDigest", out var digestValue)
                            ? digestValue.GetString()
                            : null;
                        desired[descriptor.ArtifactKey] = (current.Replicas + replicas,
                            Math.Max(current.Generation, generation),
                            current.Digest ?? digest);
                    }
                }
                catch (Exception exception) when (
                    exception is NatsException or JsonException or InvalidOperationException or ArgumentException)
                {
                    needs.Add("desired-state-read:invalid-record");
                }
            }
        }

        var runtimeKeys = new List<string>(maximumKeys);
        try
        {
            await foreach (var key in runtimeStore.GetKeysAsync(
                ["host.>", $"placement.reconciler.{topology.Cell}"],
                new NatsKVWatchOpts { IgnoreDeletes = true },
                cancellationToken).ConfigureAwait(false))
            {
                runtimeKeys.Add(key);
                if (runtimeKeys.Count == maximumKeys) break;
            }
        }
        catch (NatsKVException exception)
        {
            needs.Add($"runtime-observation-read:{exception.GetType().Name}");
        }

        foreach (var key in runtimeKeys)
        {
            try
            {
                if (key.StartsWith("host.", StringComparison.Ordinal) &&
                    !key.StartsWith("host.replace.", StringComparison.Ordinal) &&
                    !key.StartsWith("host.admission.", StringComparison.Ordinal) &&
                    !key.StartsWith("host.backoff.", StringComparison.Ordinal))
                {
                    if (authorizedHostReports is null)
                    {
                        needs.Add("host-report-authorization-unavailable");
                        continue;
                    }
                    var report = await authorizedHostReports.ReadAsync(key, cancellationToken).ConfigureAwait(false);
                    var observation = report?.Runtime;
                    if (observation is null || report!.ExpiresAt <= DateTimeOffset.UtcNow)
                    {
                        needs.Add("host-report-not-authorized");
                        continue;
                    }
                    if (observation.Cell != topology.Cell || key != $"host.{observation.Instance}.{observation.ArtifactKey}" ||
                        observation.ObservedAt > DateTimeOffset.UtcNow) continue;
                    observation.Validate();
                    var admissionExpiry = await HostReportReadiness.ConfirmAdmissionAsync(authorizedHostReports, report,
                        TimeProvider.System, cancellationToken).ConfigureAwait(false);
                    if (admissionExpiry is { } expiry) admittedUntil[key] = expiry;
                    else needs.Add("host-admission-not-ready");
                    if (!observed.TryGetValue(observation.ArtifactKey, out var list))
                        observed[observation.ArtifactKey] = list = [];
                    if (list.Count < 256) list.Add(report);
                }
                else if (key == $"placement.reconciler.{topology.Cell}")
                {
                    var entry = await runtimeStore.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                    entry.EnsureSuccess();
                    var placement = JsonSerializer.Deserialize(
                        entry.Value ?? string.Empty,
                        ControlPlane.TerraBase.TerraBasePlacementJsonContext.Default.PlacementTickObservation);
                    if (placement is not null)
                    {
                        var progress = placement.State switch
                        {
                            ControlPlane.TerraBase.PlacementTickObservation.StateIdle => 100,
                            ControlPlane.TerraBase.PlacementTickObservation.StateNotLeader => 0,
                            _ => 50
                        };
                        actions.Add(new(
                            "terrabase-placement",
                            placement.State,
                            progress,
                            placement.ObservedAt,
                            placement.Error));
                    }
                }
            }
            catch (Exception exception) when (
                exception is NatsException or JsonException or InvalidOperationException)
            {
                needs.Add("runtime-observation-read:invalid-record");
            }
        }

        var workloadStatuses = new List<OperatorWorkloadStatus>();
        var artifacts = new HashSet<string>(desired.Keys, StringComparer.Ordinal);
        artifacts.UnionWith(observed.Keys);
        // These two roles remain visible even before their first desired-state publication,
        // making an unbootstrapped OCI cell explicit instead of silently empty.
        artifacts.Add(AdmittedRoleCatalog.Get(AdmittedRole.Authentication).ArtifactKey);
        artifacts.Add(AdmittedRoleCatalog.Get(AdmittedRole.TerraBaseMember).ArtifactKey);
        foreach (var artifact in artifacts.Order(StringComparer.Ordinal))
        {
            var descriptor = AdmittedRoleCatalog.All.FirstOrDefault(value => value.ArtifactKey == artifact);
            if (descriptor is null) continue;
            var policy = scalingPolicies?.FirstOrDefault(value => value.WorkloadId == artifact);
            var minimumReplicas = policy?.MinReplicas ?? descriptor.MinimumReplicas;
            var maximumReplicas = policy?.MaxReplicas ?? AutoscalingTokens.MaximumReplicaCount;
            var desiredState = desired.GetValueOrDefault(artifact);
            var requestedReplicas = desiredState.Replicas;
            var desiredReplicas = desiredState.Replicas;
            var now = DateTimeOffset.UtcNow;
            var list = (observed.GetValueOrDefault(artifact) ?? [])
                .Where(item => item.ExpiresAt > now && item.Runtime!.ObservedAt >= now.AddMinutes(-10))
                .Select(item => item.Runtime!).ToList();
            if (desiredState.Digest is { Length: > 0 } desiredDigest)
                list = list.Where(item => string.Equals(
                    item.Digest,
                    desiredDigest.StartsWith("sha256:", StringComparison.Ordinal)
                        ? desiredDigest
                        : "sha256:" + desiredDigest,
                    StringComparison.OrdinalIgnoreCase)).ToList();
            var observedGeneration = desiredState.Generation > 0 && desiredState.Digest is not null && list.Any(item =>
                item.State == "converged" && item.Error is null && admittedUntil.GetValueOrDefault($"host.{item.Instance}.{item.ArtifactKey}") > now)
                ? desiredState.Generation
                : (long?)null;
            var ready = list.Count(item => desiredState.Digest is not null && item.State == "converged" && item.Error is null &&
                admittedUntil.GetValueOrDefault($"host.{item.Instance}.{item.ArtifactKey}") > now &&
                (descriptor.Role != AdmittedRole.TerraBaseMember || item.MemberUp == true));
            var progress = desiredReplicas == 0 ? 0 : Math.Min(100, ready * 100 / desiredReplicas);
            var workloadNeeds = new List<string>();
            if (requestedReplicas == 0)
            {
                desiredReplicas = minimumReplicas;
                workloadNeeds.Add("desired-state-not-published");
            }
            else if (requestedReplicas < minimumReplicas || requestedReplicas > maximumReplicas)
            {
                workloadNeeds.Add("desired-replicas-out-of-policy");
            }
            if (ready < desiredReplicas)
                workloadNeeds.Add($"ready-replicas:{ready}/{desiredReplicas}");
            var state = requestedReplicas == 0
                ? "waiting-for-desired-state"
                : ready >= desiredReplicas ? "ready" : list.Count == 0 ? "pending" : "converging";
            var pendingScaleAction = requestedReplicas == 0 || workloadNeeds.Contains("desired-replicas-out-of-policy")
                ? "blocked"
                : ready < desiredReplicas
                    ? "scale-out"
                    : ready > desiredReplicas && list.Count > desiredReplicas
                        ? "scale-in"
                        : "hold";
            var scalingDecision = scalingDecisions?.FirstOrDefault(value => value.WorkloadId == artifact);
            if (scalingDecision is not null && requestedReplicas > 0 &&
                !workloadNeeds.Contains("desired-replicas-out-of-policy") &&
                scalingDecision.DesiredReplicas == requestedReplicas)
            {
                pendingScaleAction = scalingDecision.Action switch
                {
                    WorkloadScaleAction.ScaleOut => "scale-out",
                    WorkloadScaleAction.ScaleIn => "scale-in",
                    WorkloadScaleAction.Blocked => "blocked",
                    _ => "hold"
                };
                if (scalingDecision.Action is WorkloadScaleAction.ScaleOut or WorkloadScaleAction.ScaleIn or WorkloadScaleAction.Blocked)
                    workloadNeeds.Add($"autoscaler:{scalingDecision.Reason}");
                actions.Add(new(
                    $"autoscale:{artifact}",
                    pendingScaleAction,
                    scalingDecision.ProgressPercent,
                    DateTimeOffset.UtcNow,
                    scalingDecision.Reason));
            }
            workloadStatuses.Add(new(
                artifact,
                descriptor.Role.ToString(),
                desiredReplicas,
                list.Count,
                ready,
                progress,
                state,
                desiredState.Generation,
                observedGeneration,
                list.Count == 0 ? null : list.Max(item => item.ObservedAt),
                workloadNeeds,
                minimumReplicas,
                maximumReplicas,
                pendingScaleAction));
            if (workloadNeeds.Count > 0)
                needs.Add($"{artifact}:{workloadNeeds[0]}");
            actions.Add(new(
                $"workload:{artifact}",
                state,
                progress,
                list.Count == 0 ? startedAt : list.Max(item => item.ObservedAt),
                null));
        }

        if (hostReportSnapshot is { } reportSnapshot)
        {
            actions.Add(new("host-report-relay", reportSnapshot.RetryPending ? "retrying" : "listening",
                reportSnapshot.RetryPending ? 0 : 100, DateTimeOffset.UtcNow,
                reportSnapshot.RetryPending ? "report-persistence-or-acknowledgement-failed" : null));
            if (reportSnapshot.RetryPending) needs.Add("host-report-relay:retry-report");
        }
        if (hostSessionSnapshot is { } sessionSnapshot)
        {
            actions.Add(new("host-session-authority", sessionSnapshot.RetryPending ? "retrying" : "listening",
                sessionSnapshot.RetryPending ? 0 : 100, DateTimeOffset.UtcNow,
                sessionSnapshot.RetryPending ? "session-storage-or-response-failed" : null));
            if (sessionSnapshot.RetryPending) needs.Add("host-session-authority:retry-request");
        }
        if (hostDesiredSnapshot is { } desiredSnapshot)
        {
            actions.Add(new("host-desired", desiredSnapshot.RetryPending ? "retrying" : desiredSnapshot.InFlight ? "reading" : "listening",
                desiredSnapshot.RetryPending || desiredSnapshot.InFlight ? 0 : 100, DateTimeOffset.UtcNow,
                desiredSnapshot.RetryPending ? "desired-storage-or-response-failed" : null));
            if (desiredSnapshot.RetryPending) needs.Add("host-desired:retry-request");
        }
        var healthy = workloadStatuses.All(static workload => workload.State == "ready") && needs.Count == 0;
        var status = new OperatorStatusDocument(
            1,
            options.Cell,
            options.Instance,
            healthy,
            DateTimeOffset.UtcNow,
            workloadStatuses,
            actions.OrderBy(static action => action.Kind, StringComparer.Ordinal).Take(128).ToArray(),
            needs.Order(StringComparer.Ordinal).Take(64).ToArray());
        status.Validate();
        return status;
    }

    private static async Task RefreshOperatorStatusAsync(
        OperatorStatusCache cache,
        INatsKVStore? delivery,
        INatsObjStore? bundles,
        INatsKVStore runtimeStore,
        OrchestratorOptions options,
        NatsTopology topology,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken,
        IReadOnlyList<WorkloadScaleDecision> decisions,
        IReadOnlyList<WorkloadScalePolicy> policies,
        HostReportRelaySnapshot? hostReportSnapshot,
        RegionalHostSessionServiceSnapshot? hostSessionSnapshot,
        IAuthorizedHostReportReader? authorizedHostReports,
        RegionalHostDesiredSnapshot? hostDesiredSnapshot)
    {
        try
        {
            cache.Set(await BuildOperatorStatusAsync(
                    delivery,
                    bundles,
                    runtimeStore,
                    options,
                    topology,
                    startedAt,
                    cancellationToken,
                    decisions,
                    policies,
                    hostReportSnapshot,
                    hostSessionSnapshot, authorizedHostReports, hostDesiredSnapshot)
                .ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Operator status refresh failed ({exception.GetType().Name}); retaining the last projection.");
        }
    }

    private static async Task<RuntimeState> OpenStateWithRetryAsync(
        NatsClient client,
        NatsTopology topology,
        bool nativeGitOpsEnabled,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await OpenStateAsync(client, topology, nativeGitOpsEnabled, cancellationToken);
            }
            catch (Exception exception) when (
                attempt < 5 &&
                exception is NatsJSApiNoResponseException or NatsJSTimeoutException or NatsJSConnectionException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), cancellationToken);
            }
        }
    }

    internal static async Task VerifyAnonymousDeniedAsync(
        string url,
        NatsTlsFiles? tls,
        CancellationToken cancellationToken)
    {
        var natsUrl = OrchestratorOptions.ParseRegionalNatsUrl(url, "NATS URL");
        var options = new NatsOpts
        {
            Url = natsUrl.ToString(),
            RetryOnInitialConnect = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            RequestTimeout = TimeSpan.FromSeconds(3)
        };
        if (tls is not null)
            options = options with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = tls.CaFile,
                    CertFile = tls.CertificateFile,
                    KeyFile = tls.KeyFile,
                },
            };
        await using var anonymous = new NatsClient(options);
        try
        {
            await anonymous.ConnectAsync().AsTask().WaitAsync(cancellationToken);
        }
        catch (NatsServerException exception) when (exception.IsAuthError)
        {
            return;
        }
        catch (Exception exception) when (IsAnonymousAuthenticationDenied(exception))
        {
            return;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                $"Anonymous NATS authentication probe failed for {OrchestratorOptions.SanitizeNatsUrl(url)} " +
                $"({exception.GetType().Name}).",
                exception);
        }
        throw new InvalidOperationException(
            "Control NATS accepted an anonymous client while NKey authentication was required.");
    }

    private static bool IsAnonymousAuthenticationDenied(Exception exception) =>
        exception switch
        {
            NatsServerException { IsAuthError: true } => true,
            { InnerException: { } inner } => IsAnonymousAuthenticationDenied(inner),
            _ => false
        };

    private static async Task VerifyServiceAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await VerifyServiceOnceAsync(client, topology, cancellationToken);
                return;
            }
            catch (Exception exception) when (attempt < 5 &&
                (exception is NatsNoReplyException ||
                 exception is InvalidOperationException { Message: "NATS health service returned an invalid response." }))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100 * attempt), cancellationToken);
            }
        }
    }

    private static async Task VerifyServiceOnceAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var health = await client.RequestAsync<string, string>(
            topology.InstanceHealthSubject,
            "health",
            cancellationToken: cancellationToken);
        if (health.Data is not "ready")
        {
            throw new InvalidOperationException("NATS health service returned an invalid response.");
        }

        var info = await client.RequestAsync<string, string>(
            $"$SRV.INFO.{topology.ServiceName}",
            string.Empty,
            cancellationToken: cancellationToken);
        if (!HasExpectedEndpoint(info.Data, topology))
        {
            throw new InvalidOperationException("NATS service discovery returned invalid endpoint metadata.");
        }

        var statusResponse = await client.RequestAsync<string, string>(
            topology.StatusSubject,
            "status",
            cancellationToken: cancellationToken);
        var status = JsonSerializer.Deserialize(
            statusResponse.Data ?? throw new InvalidOperationException("NATS status service returned no response."),
            RegionalControllerStatusJsonContext.Default.RegionalControllerStatus)
            ?? throw new InvalidOperationException("NATS status service returned no response.");
        status.Validate(topology.Cell);

        var membersResponse = await client.RequestAsync<string, string>(
            topology.MembersSubject,
            "members",
            cancellationToken: cancellationToken);
        var members = JsonSerializer.Deserialize(
            membersResponse.Data ?? throw new InvalidOperationException("NATS membership service returned no response."),
            RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMembershipSnapshot)
            ?? throw new InvalidOperationException("NATS membership service returned no response.");
        members.Validate(topology.Cell);
    }

    private static bool HasExpectedEndpoint(
        string? response,
        NatsTopology topology)
    {
        if (string.IsNullOrWhiteSpace(response))
        {
            return false;
        }

        var root = JsonElement.Parse(response);
        if (!root.TryGetProperty("name", out var name) || name.GetString() != topology.ServiceName ||
            !root.TryGetProperty("endpoints", out var endpoints))
        {
            return false;
        }

        var discovered = endpoints.EnumerateArray().ToArray();
        var hasHealth = discovered.Any(endpoint =>
            endpoint.TryGetProperty("name", out var endpointName) && endpointName.GetString() == "health" &&
            endpoint.TryGetProperty("subject", out var subject) && subject.GetString() == topology.HealthSubject &&
            endpoint.TryGetProperty("queue_group", out var queue) && queue.GetString() == topology.ServiceQueueGroup);
        var hasMembers = discovered.Any(endpoint =>
            endpoint.TryGetProperty("name", out var endpointName) && endpointName.GetString() == "members" &&
            endpoint.TryGetProperty("subject", out var subject) && subject.GetString() == topology.MembersSubject &&
            endpoint.TryGetProperty("queue_group", out var queue) && queue.GetString() == topology.ServiceQueueGroup);
        return hasHealth && hasMembers;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (directDeliveryService is not null) await directDeliveryService.DisposeAsync();
        }
        finally
        {
            try { await service.DisposeAsync(); }
            finally
            {
                try { await authority.DisposeAsync(); }
                finally
                {
                    try { await membership.DisposeAsync(); }
                    finally
                    {
                        try
                        {
                            try { if (hostDesired is not null) await hostDesired.DisposeAsync(); }
                            finally { if (hostSessions is not null) await hostSessions.DisposeAsync(); }
                        }
                        finally
                        {
                            try
                            {
                                if (hostReports is not null) await hostReports.DisposeAsync();
                            }
                            finally
                            {
                                try
                                {
                                    if (terrabasePlacement is not null) await terrabasePlacement.DisposeAsync();
                                }
                                finally
                                {
                                    if (workloadAutoscaler is not null) await workloadAutoscaler.DisposeAsync();
                                    workloadReplicaDriver?.Dispose();
                                    memberHostFleet?.Dispose();
                                    await client.DisposeAsync();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static async Task<RuntimeState> OpenStateAsync(
        NatsClient client,
        NatsTopology topology,
        bool nativeGitOpsEnabled,
        CancellationToken cancellationToken)
    {
        var jetStream = client.CreateJetStreamContext();
        foreach (var expected in topology.Streams)
        {
            if (expected.Name is not { } streamName)
                throw new InvalidOperationException("The infrastructure-provisioned NATS stream has no name.");
            var stream = await jetStream.GetStreamAsync(streamName, cancellationToken: cancellationToken);
            NatsOperationJournalStore.ValidateExactStreamConfiguration(stream.Info.Config, expected);
        }

        var keyValue = jetStream.CreateKeyValueStoreContext();
        var leaders = await OpenKeyValueAsync(keyValue, topology.Leaders, cancellationToken);
        var runtime = await OpenKeyValueAsync(keyValue, topology.Runtime, cancellationToken);
        var nodeEnrollments = await OpenKeyValueAsync(keyValue, topology.NodeEnrollments, cancellationToken);
        var objects = jetStream.CreateObjectStoreContext();
        var protocolPackage = await objects.GetObjectStoreAsync(topology.ProtocolPackage.Bucket, cancellationToken);
        NatsOperationJournalStore.ValidateExactObjectConfiguration(
            (await protocolPackage.GetStatusAsync(cancellationToken)).Info.Config, topology.ProtocolPackage);

        var startupConsumer = await OpenExactConsumerAsync(
            jetStream, "CELL_EVENTS", topology.StartupConsumer, cancellationToken);
        INatsKVStore? delivery = null;
        INatsObjStore? bundles = null;
        INatsJSConsumer? cellSpecConsumer = null;
        INatsObjStore? artifacts = null;
        delivery = await OpenKeyValueAsync(keyValue, topology.Delivery, cancellationToken);
        artifacts = await objects.GetObjectStoreAsync(topology.Artifacts.Bucket, cancellationToken);
        NatsOperationJournalStore.ValidateExactObjectConfiguration(
            (await artifacts.GetStatusAsync(cancellationToken)).Info.Config, topology.Artifacts);
        if (nativeGitOpsEnabled)
        {
            bundles = await objects.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
            NatsOperationJournalStore.ValidateExactObjectConfiguration(
                (await bundles.GetStatusAsync(cancellationToken)).Info.Config, topology.Bundles);
            cellSpecConsumer = await OpenExactConsumerAsync(
                jetStream, "CELL_SPEC", topology.CellSpecConsumer, cancellationToken);
        }
        return new(startupConsumer, cellSpecConsumer, leaders, runtime, nodeEnrollments, delivery, bundles, protocolPackage, artifacts);
    }

    private static async Task<INatsKVStore> OpenKeyValueAsync(
        INatsKVContext keyValue,
        NatsKVConfig expected,
        CancellationToken cancellationToken)
    {
        var store = await keyValue.GetStoreAsync(expected.Bucket, cancellationToken);
        NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(
            (await store.GetStatusAsync(cancellationToken)).Info.Config,
            expected);
        return store;
    }

    private static async Task<INatsJSConsumer> OpenExactConsumerAsync(
        INatsJSContext jetStream,
        string stream,
        NATS.Client.JetStream.Models.ConsumerConfig expected,
        CancellationToken cancellationToken)
    {
        if (expected.Name is not { } consumerName)
            throw new InvalidOperationException("The infrastructure-provisioned NATS consumer has no name.");
        var consumer = await jetStream.GetConsumerAsync(stream, consumerName, cancellationToken);
        await consumer.RefreshAsync(cancellationToken);
        if (!CiRunnerConsumerReconciler.Matches(consumer.Info, expected, stream))
            throw new InvalidOperationException("The infrastructure-provisioned NATS consumer does not match its closed profile.");
        return consumer;
    }

    private static async Task VerifyProtocolPackageAsync(
        INatsObjStore bundles,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var stored = await bundles.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        if (!stored.AsSpan().SequenceEqual(NatsProtocolPackage.Bytes))
        {
            throw new InvalidOperationException("NATS protocol package failed its integrity check.");
        }
    }

    private static async Task VerifyDurableMessagingAsync(
        NatsClient client,
        INatsJSConsumer consumer,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var eventId = Guid.NewGuid().ToString("N");
        var headers = new NatsHeaders
        {
            ["TS-Protocol-Version"] = "1",
            ["TS-Cell"] = topology.Cell,
            ["TS-Correlation-Id"] = eventId
        };
        var jetStream = client.CreateJetStreamContext();
        var acknowledgement = await jetStream.PublishAsync(
            topology.StartupSubject,
            eventId,
            opts: new NatsJSPubOpts
            {
                MsgId = eventId,
                ExpectedStream = "CELL_EVENTS",
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250)
            },
            headers: headers,
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();

        // NextAsync creates a new reply subscription per pull. With an R3 consumer,
        // its leader can deliver before interest for that reply subject has converged
        // to the leader. Keep one subscription and allow its pull loop to recover
        // from that transient reply loss; the five-second verification bound and
        // the acknowledgement and metadata checks remain unchanged.
        using var deliveryTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deliveryTimeout.CancelAfter(TimeSpan.FromSeconds(5));
        await using var deliveries = consumer.ConsumeAsync<string>(
                opts: new NatsJSConsumeOpts
                {
                    MaxMsgs = 1,
                    Expires = TimeSpan.FromSeconds(1)
                },
                cancellationToken: deliveryTimeout.Token)
            .GetAsyncEnumerator(deliveryTimeout.Token);
        INatsJSMsg<string>? message;
        try
        {
            message = await deliveries.MoveNextAsync()
                ? deliveries.Current
                : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            message = null;
        }

        if (message is null)
        {
            throw new InvalidOperationException("Durable NATS startup event was not delivered.");
        }

        // PublishAsync already proved this runtime's event is durable. The canonical
        // consumer is intentionally shared by all controllers, so requiring this
        // pull to return eventId could steal a peer's event and leave both runtimes
        // waiting for redelivery. A self-consistent event for this cell instead
        // proves the shared delivery-and-ack path without changing its ownership.
        if (string.IsNullOrWhiteSpace(message.Data) ||
            !HeaderEquals(message.Headers, "TS-Protocol-Version", "1") ||
            !HeaderEquals(message.Headers, "TS-Cell", topology.Cell) ||
            !HeaderEquals(message.Headers, "TS-Correlation-Id", message.Data))
        {
            throw new InvalidOperationException("Durable NATS startup event metadata was invalid.");
        }

        await message.AckAsync(cancellationToken: cancellationToken);
    }

    private static bool HeaderEquals(NatsHeaders? headers, string name, string expected) =>
        headers is not null &&
        headers.TryGetLastValue(name, out var value) &&
        string.Equals(value, expected, StringComparison.Ordinal);

    private static List<KeyValuePair<string, string>> Flatten(NatsHeaders? headers)
    {
        var flattened = new List<KeyValuePair<string, string>>();
        if (headers is null) return flattened;
        foreach (var (key, values) in headers)
            foreach (var value in values)
                flattened.Add(new KeyValuePair<string, string>(key, value ?? string.Empty));
        return flattened;
    }

    private sealed record RuntimeState(
        INatsJSConsumer StartupConsumer,
        INatsJSConsumer? CellSpecConsumer,
        INatsKVStore Leaders,
        INatsKVStore Runtime,
        INatsKVStore NodeEnrollments,
        INatsKVStore? Delivery,
        INatsObjStore? Bundles,
        INatsObjStore ProtocolPackage,
        INatsObjStore? Artifacts);

}
