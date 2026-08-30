using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Messaging;

internal sealed class GlobalNatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly ForgejoCiEventConsumer ciEvents;
    private readonly RepositoryCiRuntimeObservationNatsConsumer? runtimeProofs;
    private readonly RepositoryCiController? ciController;
    private readonly INatsJSConsumer? cellSpecConsumer;
    private readonly GlobalNatsTopology topology;
    private readonly string cell;
    private readonly DirectDeliveryService directDelivery;

    private GlobalNatsRuntime(
        NatsClient client,
        RegionalAuthorityCoordinator authority,
        ForgejoCiEventConsumer ciEvents,
        RepositoryCiRuntimeObservationNatsConsumer? runtimeProofs,
        RepositoryCiController? ciController,
        CiRunnerConsumerReconciler ciRunners,
        CiRunnerNatsCredentialIssuer? ciRunnerCredentials,
        ForgejoWebhookJournal forgejoWebhooks,
        ForgejoSourceJournal forgejoSources,
        NativeGitOpsSourceJournal nativeGitOpsSources,
        RepositoryCiPipelineJournal pipelines,
        RepositoryCiJobJournal jobs,
        NativeGitOpsGlobalHandoffRuntime? nativeGitOpsHandoffs,
        INatsJSConsumer? cellSpecConsumer,
        GlobalNatsTopology topology,
        string cell,
        DirectDeliveryService directDelivery)
    {
        this.client = client;
        this.authority = authority;
        this.ciEvents = ciEvents;
        this.runtimeProofs = runtimeProofs;
        this.ciController = ciController;
        CiRunners = ciRunners;
        CiRunnerCredentials = ciRunnerCredentials;
        ForgejoWebhooks = forgejoWebhooks;
        ForgejoSources = forgejoSources;
        NativeGitOpsSources = nativeGitOpsSources;
        Pipelines = pipelines;
        Jobs = jobs;
        NativeGitOpsHandoffs = nativeGitOpsHandoffs;
        this.cellSpecConsumer = cellSpecConsumer;
        this.topology = topology;
        this.cell = cell;
        this.directDelivery = directDelivery;
    }

    public Task Completion => Task.WhenAny(
        authority.Completion,
        ciEvents.Completion,
        runtimeProofs?.Completion ?? Task.Delay(Timeout.InfiniteTimeSpan)).Unwrap();
    public ForgejoWebhookJournal ForgejoWebhooks { get; }
    public CiRunnerConsumerReconciler CiRunners { get; }
    public CiRunnerNatsCredentialIssuer? CiRunnerCredentials { get; }
    public ForgejoSourceJournal ForgejoSources { get; }
    public NativeGitOpsSourceJournal NativeGitOpsSources { get; }
    public RepositoryCiPipelineJournal Pipelines { get; }
    public RepositoryCiJobJournal Jobs { get; }
    internal NativeGitOpsGlobalHandoffRuntime? NativeGitOpsHandoffs { get; }
    public RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;
    internal DirectDeliveryService DirectDelivery => directDelivery;
    internal NativeGitOpsGlobalCellNatsConsumer CreateNativeGitOpsConsumer(
        NativeGitOpsCellPublisher regionalPublisher,
        string expectedCell)
    {
        if (!string.Equals(cell, expectedCell, StringComparison.Ordinal))
            throw new InvalidOperationException("The global CellSpec consumer does not match the regional cell.");
        return new NativeGitOpsGlobalCellNatsConsumer(
            cellSpecConsumer ?? throw new InvalidOperationException("Native GitOps global consumer is not configured."),
            new NativeGitOpsGlobalCellRelay(regionalPublisher), topology, cell);
    }

    public static Task<GlobalNatsRuntime> StartAsync(
        GlobalNatsConfiguration configuration,
        string instance,
        string cell,
        INatsAccountJwtSigner? ciRunnerNatsSigner,
        CancellationToken cancellationToken,
        ForgejoSourceConfiguration? ciSource = null,
        ForgejoRepositoryCiSourceGraphConfiguration? ciSourceGraph = null,
        OciCiRunnerPoolConfiguration? ciPool = null,
        IRepositoryCiJobSigner? ciJobSigner = null,
        IRepositoryCiArtifactAttestationSigner? ciArtifactSigner = null,
        IRepositoryCiArtifactSignatureVerifier? ciArtifactSignatures = null,
        IRepositoryCiArtifactSignatureVerifier? ciRuntimeSignatures = null,
        INativeGitOpsCellSpecSigner? nativeGitOpsSigner = null,
        bool nativeGitOpsConsumerEnabled = false,
        bool ciConsumptionEnabled = true,
        DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null) =>
        StartAsync(
            GlobalAuthorityNatsConfiguration.From(configuration, cell),
            instance,
            cell,
            ciRunnerNatsSigner,
            cancellationToken,
            ciSource,
            ciSourceGraph,
            ciPool,
            ciJobSigner,
            ciArtifactSigner,
            ciArtifactSignatures,
            ciRuntimeSignatures,
            nativeGitOpsSigner,
            nativeGitOpsConsumerEnabled,
            ciConsumptionEnabled,
            admittedDeliveryTargets);

    internal static Task<GlobalNatsRuntime> StartAsync(
        GlobalAuthorityNatsConfiguration configuration,
        string instance,
        string cell,
        INatsAccountJwtSigner? ciRunnerNatsSigner,
        CancellationToken cancellationToken,
        ForgejoSourceConfiguration? ciSource = null,
        ForgejoRepositoryCiSourceGraphConfiguration? ciSourceGraph = null,
        OciCiRunnerPoolConfiguration? ciPool = null,
        IRepositoryCiJobSigner? ciJobSigner = null,
        IRepositoryCiArtifactAttestationSigner? ciArtifactSigner = null,
        IRepositoryCiArtifactSignatureVerifier? ciArtifactSignatures = null,
        IRepositoryCiArtifactSignatureVerifier? ciRuntimeSignatures = null,
        INativeGitOpsCellSpecSigner? nativeGitOpsSigner = null,
        bool nativeGitOpsConsumerEnabled = false,
        bool ciConsumptionEnabled = true,
        DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null) =>
        StartCoreAsync(
            configuration,
            instance,
            cell,
            ciRunnerNatsSigner,
            cancellationToken,
            ciSource,
            ciSourceGraph,
            ciPool,
            ciJobSigner,
            ciArtifactSigner,
            ciArtifactSignatures,
            ciRuntimeSignatures,
            nativeGitOpsSigner,
            nativeGitOpsConsumerEnabled,
            ciConsumptionEnabled,
            admittedDeliveryTargets);

    private static async Task<GlobalNatsRuntime> StartCoreAsync(
        GlobalAuthorityNatsConfiguration configuration,
        string instance,
        string cell,
        INatsAccountJwtSigner? ciRunnerNatsSigner,
        CancellationToken cancellationToken,
        ForgejoSourceConfiguration? ciSource = null,
        ForgejoRepositoryCiSourceGraphConfiguration? ciSourceGraph = null,
        OciCiRunnerPoolConfiguration? ciPool = null,
        IRepositoryCiJobSigner? ciJobSigner = null,
        IRepositoryCiArtifactAttestationSigner? ciArtifactSigner = null,
        IRepositoryCiArtifactSignatureVerifier? ciArtifactSignatures = null,
        IRepositoryCiArtifactSignatureVerifier? ciRuntimeSignatures = null,
        INativeGitOpsCellSpecSigner? nativeGitOpsSigner = null,
        bool nativeGitOpsConsumerEnabled = false,
        bool ciConsumptionEnabled = true,
        DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null)
    {
        if (!GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed(cell))
            throw new ArgumentException(
                "GlobalNatsRuntime is a GRU-only global-authority runtime.",
                nameof(cell));
        ArgumentNullException.ThrowIfNull(configuration);
        if (!string.Equals(configuration.Cell, cell, StringComparison.Ordinal))
            throw new ArgumentException(
                "The global authority configuration cell must match the startup cell.",
                nameof(cell));
        var topology = new GlobalNatsTopology(configuration.Replicas);
        var client = new NatsClient(new NatsOpts
        {
            Url = configuration.Url,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = configuration.Authentication.Options,
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = configuration.Tls.CaFile,
                CertFile = configuration.Tls.CertificateFile,
                KeyFile = configuration.Tls.KeyFile,
            },
        });

        RegionalAuthorityCoordinator? authority = null;
        RepositoryCiController? ciController = null;
        try
        {
            await client.ConnectAsync();
            await NatsRuntime.VerifyAnonymousDeniedAsync(configuration.Url, configuration.Tls, cancellationToken);
            var state = await ReconcileStateWithRetryAsync(
                client, topology, cell, nativeGitOpsConsumerEnabled, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartGlobalAsync(
                state.Leaders,
                cell,
                instance,
                cancellationToken);
            if (!authority.Snapshot.Ready)
                throw new InvalidOperationException("Global authority did not reach a ready leader or follower state.");
            var ledger = new NatsForgejoDeliveryLedger(state.Releases);
            var objects = new NatsDeliveryObjectStore(state.Bundles);
            var runnerLedger = new NatsForgejoDeliveryLedger(state.RunnerJobs);
            var runnerObjects = new NatsDeliveryObjectStore(state.RunnerBundles);
            // Composition fails closed here without the evidence verifier or the configured
            // admitted-target allow-list, mirroring the signed-command rule at the endpoint.
            // The evidence verifier is exactly the CI artifact role's trust root — the role
            // that signs delivery evidence. There is deliberately NO cross-role fallback: the
            // runtime-observation verifier must never serve as a public-seam evidence
            // verifier, and a composition without the artifact role fails closed
            // in DirectDeliveryRuntimeAdapterSet.Create instead of degrading.
            var (authorizer, provenance, targetResolver, deliveryJournal, artifactBuilder) =
                DirectDeliveryRuntimeAdapterSet.Create(
                    ledger,
                    () => authority.Snapshot.Ready && authority.Snapshot.IsLeader,
                    request =>
                    {
                        var current = authority.Snapshot;
                        return current.Ready && current.IsLeader &&
                            current.KvRevision == request.AuthorityGeneration &&
                            current.Epoch == request.WriterEpoch;
                    },
                    admittedDeliveryTargets,
                    ciArtifactSignatures);
            var directDelivery = new DirectDeliveryService(
                authorizer,
                provenance,
                targetResolver,
                deliveryJournal,
                artifactBuilder,
                auditIdFactory: static () => $"audit-{Guid.NewGuid():N}",
                authorityIsCurrent: request =>
                {
                    var current = authority.Snapshot;
                    return current.Ready && current.IsLeader &&
                        current.KvRevision == request.AuthorityGeneration &&
                        current.Epoch == request.WriterEpoch;
                });
            var triggerJournal = new ForgejoCiTriggerJournal(ledger);
            var pipelines = new RepositoryCiPipelineJournal(ledger, objects);
            var jobs = new RepositoryCiJobJournal(ledger);
            var nativeGitOpsSources = new NativeGitOpsSourceJournal(ledger, objects);
            var nativeGitOpsHandoffs = nativeGitOpsSigner is null
                ? null
                : new NativeGitOpsGlobalHandoffRuntime(
                    new NativeGitOpsGlobalHandoffCoordinator(
                        nativeGitOpsSources,
                        new(ledger, objects),
                        new(
                            new(ledger),
                            new(new NatsNativeGitOpsGlobalHandoffTransport(client)))),
                    nativeGitOpsSigner,
                    () => authority.Snapshot);
            var runnerConsumers = new CiRunnerConsumerReconciler(client.CreateJetStreamContext(), topology);
            if (ciPool is not null)
            {
                if (ciSource is null || ciJobSigner is null)
                    throw new ArgumentException("OCI CI requires Forgejo source access and a command signer.");
                // The build-profile acknowledge gate needs the full artifact-signing triple; a
                // pool without it can never acknowledge trusted-build work, so startup fails
                // closed instead of silently dropping deliveries after MaxDeliver.
                if (ciArtifactSigner is null || ciArtifactSignatures is null || ciRuntimeSignatures is null)
                    throw new ArgumentException(
                        "The OCI CI runner pool requires the artifact attestation signer and both proof verifiers " +
                        "(command identity trust must be configured).");
                var graphConfiguration = ciSourceGraph ?? ForgejoRepositoryCiSourceGraphConfiguration.Load(null, ciSource)
                    ?? throw new InvalidOperationException(
                        "The repository CI source graph configuration is unavailable.");
                var sourceGraph = ForgejoRepositoryCiSourceGraph.Create(ciSource, graphConfiguration);
                if (sourceGraph.RootClient is not { } source)
                    throw new InvalidOperationException("The repository CI source graph has no root client.");
                IOciCiRunnerCapacityAdapter? capacity = null;
                try
                {
                    capacity = OciCiRunnerComputeAdapter.CreateForInstancePrincipal(ciPool.Endpoint.ToString());
                    var coordinator = new RepositoryCiPipelineCoordinator(
                        triggerJournal,
                        pipelines,
                        source.ReadChangedPathsAsync,
                        sourceGraph.ResolvePipelineAsync);
                    var dispatcher = new RepositoryCiJobDispatchCoordinator(
                        jobs,
                        new(runnerObjects),
                        new(jobs, new(new NatsRepositoryCiJobTransport(client), ciJobSigner)),
                        sourceGraph.ReadArchiveAsync,
                        (job, runner, token) =>
                        {
                            token.ThrowIfCancellationRequested();
                            var slot = ciPool.Slots.SingleOrDefault(value =>
                                value.Demand.Runner == runner.Runner.Value &&
                                value.Demand.Sequence == runner.Sequence)
                                ?? throw new InvalidDataException(
                                    "The selected CI runner is outside its configured OCI pool.");
                            return Task.FromResult(slot.Isolation(job));
                        });
                    var availability = new OciCiRunnerAvailability();
                    Func<RepositoryCiPipelinePlan, CancellationToken, Task<ForgejoCiEventProcessDisposition>>? attestArtifacts = null;
                    if (ciArtifactSigner is not null && ciArtifactSignatures is not null &&
                        ciRuntimeSignatures is not null)
                    {
                        var executions = new RepositoryCiJobExecutionJournal(runnerLedger);
                        var attestations = new RepositoryCiArtifactAttestationJournal(
                            runnerLedger,
                            runnerObjects);
                        var gate = new RepositoryCiArtifactAttestationGate(
                            jobs.ReadAsync,
                            (job, innerToken) => executions.ReadAsync(
                                job.RunnerId,
                                job.Document.PipelineDigest,
                                job.Job.Request.Job.Value,
                                innerToken),
                            new CiRunnerDurableEvidenceVerifier(runnerObjects),
                            attestations,
                            ciArtifactSigner,
                            ciArtifactSignatures,
                            ciRuntimeSignatures,
                            // Published artifacts record their source binding on the delivery
                            // ledger — the same ledger production provenance verifies against —
                            // so an attested publication is deliverable, not inert.
                            new DirectDeliveryArtifactEvidenceJournal(ledger));
                        attestArtifacts = async (pipeline, token) =>
                        {
                            var lease = authority.Snapshot;
                            if (!lease.Ready || !lease.IsLeader || lease.Epoch <= 0 || lease.KvRevision <= 0)
                                return ForgejoCiEventProcessDisposition.Retry;
                            bool StillValid() => RepositoryCiController.SameAuthority(lease, authority.Snapshot);
                            RepositoryCiArtifactAttestationGateReceipt receipt;
                            try
                            {
                                receipt = await gate.RecordAsync(
                                    pipeline,
                                    lease.Epoch,
                                    lease.KvRevision,
                                    StillValid,
                                    token);
                            }
                            catch (RepositoryCiArtifactProofAuthorityLostException)
                            {
                                return ForgejoCiEventProcessDisposition.Retry;
                            }
                            catch (InvalidDataException exception) when (exception.Message.Contains(
                                "retired schema 2", StringComparison.Ordinal))
                            {
                                // A candidate-era pipeline record can never attest: the controller
                                // reports the commit failed and the delivery is terminated.
                                return ForgejoCiEventProcessDisposition.Terminal;
                            }
                            return receipt.Disposition switch
                            {
                                RepositoryCiArtifactAttestationGateDisposition.Attested =>
                                    ForgejoCiEventProcessDisposition.Handled,
                                // Retryable: the runtime-proof consumer, a later authority
                                // epoch, or an unreachable delivery-evidence journal makes
                                // progress; redeliver with a delay.
                                RepositoryCiArtifactAttestationGateDisposition.AuthorityLost or
                                RepositoryCiArtifactAttestationGateDisposition.PipelineActive or
                                RepositoryCiArtifactAttestationGateDisposition.ProofNotYetConsumed or
                                RepositoryCiArtifactAttestationGateDisposition.DeliveryEvidenceJournalUnavailable =>
                                    ForgejoCiEventProcessDisposition.Retry,
                                // Permanent: the durable evidence cannot match this subject.
                                RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch or
                                RepositoryCiArtifactAttestationGateDisposition.PipelineFailed =>
                                    ForgejoCiEventProcessDisposition.Terminal,
                                _ => throw new InvalidDataException(
                                    $"Repository CI artifact attestation failed closed: {receipt.Disposition}."),
                            };
                        };
                    }
                    ciController = new(
                        pipelines,
                        coordinator,
                        jobs,
                        new(
                            jobs,
                            dispatcher,
                            new(jobs, new(runnerLedger), new CiRunnerDurableEvidenceVerifier(runnerObjects)),
                            availability.ReadAsync),
                        availability,
                        async (zone, runner, token) =>
                        {
                            _ = await runnerConsumers.ReconcileAsync(zone, runner, token);
                        },
                        source.ReportCommitStatusAsync,
                        ciPool,
                        capacity,
                        () => authority.Snapshot,
                        instance,
                        ownedSource: sourceGraph,
                        attestArtifacts: attestArtifacts);
                }
                catch
                {
                    if (ciController is not null)
                    {
                        await ciController.DisposeAsync();
                        ciController = null;
                    }
                    else
                    {
                        capacity?.Dispose();
                        await sourceGraph.DisposeAsync();
                    }
                    throw;
                }
            }
            var ciEvents = ForgejoCiEventConsumer.Start(
                state.CiConsumer,
                new(triggerJournal, () => authority.Snapshot),
                () => authority.Snapshot,
                ciController is null
                    ? null
                    : (trigger, token) => ciController.RunToCompletionAsync(trigger, token),
                topology.CiConsumer,
                enabled: ciConsumptionEnabled);
            var runtimeProofs = ciRuntimeSignatures is null
                ? null
                : RepositoryCiRuntimeObservationNatsConsumer.Start(
                    state.CiRuntimeProofConsumer,
                    new(new(runnerLedger, runnerObjects), ciRuntimeSignatures),
                    () => authority.Snapshot,
                    topology,
                    enabled: ciConsumptionEnabled);
            return new(
                client,
                authority,
                ciEvents,
                runtimeProofs,
                ciController,
                runnerConsumers,
                ciRunnerNatsSigner is null ? null : new(topology, ciRunnerNatsSigner),
                new(ledger, new NatsForgejoEventPublisher(client)),
                new(ledger),
                nativeGitOpsSources,
                new(ledger, objects),
                new(ledger),
                nativeGitOpsHandoffs,
                state.CellSpecConsumer,
                topology,
                cell,
                directDelivery);
        }
        catch
        {
            if (ciController is not null) await ciController.DisposeAsync();
            if (authority is not null) await authority.DisposeAsync();
            await client.DisposeAsync();
            throw;
        }
    }

    private static async Task<GlobalState> ReconcileStateWithRetryAsync(
        NatsClient client,
        GlobalNatsTopology topology,
        string cell,
        bool nativeGitOpsConsumerEnabled,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var jetStream = client.CreateJetStreamContext();
                foreach (var stream in topology.Streams)
                    await jetStream.CreateOrUpdateStreamAsync(stream, cancellationToken);
                var keyValue = jetStream.CreateKeyValueStoreContext();
                var leaders = await keyValue.CreateOrUpdateStoreAsync(topology.Leaders, cancellationToken);
                var releases = await keyValue.CreateOrUpdateStoreAsync(topology.Releases, cancellationToken);
                var runnerJobs = await keyValue.CreateOrUpdateStoreAsync(topology.RunnerJobs, cancellationToken);
                var objectStore = jetStream.CreateObjectStoreContext();
                var bundles = await GetOrCreateAsync(objectStore, topology.Bundles, cancellationToken);
                var runnerBundles = await GetOrCreateAsync(objectStore, topology.RunnerBundles, cancellationToken);
                var ciConsumer = await jetStream.CreateOrUpdateConsumerAsync(
                    GlobalNatsTopology.CiStream,
                    topology.CiConsumer,
                    cancellationToken);
                var ciRuntimeProofConsumer = await jetStream.CreateOrUpdateConsumerAsync(
                    GlobalNatsTopology.CiStream,
                    topology.CiRuntimeProofConsumer,
                    cancellationToken);
                INatsJSConsumer? cellSpecConsumer = null;
                if (nativeGitOpsConsumerEnabled)
                {
                    // The established global topology reconciler is the reachable bootstrap
                    // authority for this global durable consumer, matching CI consumers.
                    var expectedCellSpecConsumer = topology.CellSpecConsumer(cell);
                    cellSpecConsumer = await jetStream.CreateOrUpdateConsumerAsync(
                        GlobalNatsTopology.CellSpecStream, expectedCellSpecConsumer, cancellationToken);
                    await cellSpecConsumer.RefreshAsync(cancellationToken);
                    if (!CiRunnerConsumerReconciler.Matches(
                            cellSpecConsumer.Info, expectedCellSpecConsumer, GlobalNatsTopology.CellSpecStream))
                        throw new InvalidOperationException(
                            "The reconciled global CellSpec consumer does not match its closed profile.");
                }
                return new(
                    leaders,
                    releases,
                    runnerJobs,
                    bundles,
                    runnerBundles,
                    ciConsumer,
                    ciRuntimeProofConsumer,
                    cellSpecConsumer);
            }
            catch (Exception exception) when (
                attempt < 5 &&
                exception is NatsJSApiNoResponseException or NatsJSTimeoutException or NatsJSConnectionException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), cancellationToken);
            }
        }
    }

    private static async Task<INatsObjStore> GetOrCreateAsync(
        INatsObjContext context,
        NatsObjConfig configuration,
        CancellationToken cancellationToken)
    {
        try
        {
            return await context.GetObjectStoreAsync(configuration.Bucket, cancellationToken);
        }
        catch (NatsJSApiException exception) when (exception.Error.Code == 404)
        {
            return await context.CreateObjectStoreAsync(configuration, cancellationToken);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (runtimeProofs is not null) await runtimeProofs.DisposeAsync();
        }
        finally
        {
            try
            {
                await ciEvents.DisposeAsync();
            }
            finally
            {
                try
                {
                    if (ciController is not null) await ciController.DisposeAsync();
                }
                finally
                {
                    try
                    {
                        await authority.DisposeAsync();
                    }
                    finally
                    {
                        await client.DisposeAsync();
                    }
                }
            }
        }
    }

    private sealed record GlobalState(
        INatsKVStore Leaders,
        INatsKVStore Releases,
        INatsKVStore RunnerJobs,
        INatsObjStore Bundles,
        INatsObjStore RunnerBundles,
        INatsJSConsumer CiConsumer,
        INatsJSConsumer CiRuntimeProofConsumer,
        INatsJSConsumer? CellSpecConsumer);
}
