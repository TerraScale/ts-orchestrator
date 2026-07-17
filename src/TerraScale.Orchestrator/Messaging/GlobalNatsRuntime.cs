using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Messaging;

internal sealed class GlobalNatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly ForgejoCiEventConsumer ciEvents;
    private readonly RepositoryCiController? ciController;

    private GlobalNatsRuntime(
        NatsClient client,
        RegionalAuthorityCoordinator authority,
        ForgejoCiEventConsumer ciEvents,
        RepositoryCiController? ciController,
        CiRunnerConsumerReconciler ciRunners,
        CiRunnerNatsCredentialIssuer? ciRunnerCredentials,
        ForgejoWebhookJournal forgejoWebhooks,
        ForgejoSourceJournal forgejoSources,
        NativeGitOpsSourceJournal nativeGitOpsSources,
        RepositoryCiPipelineJournal pipelines,
        RepositoryCiJobJournal jobs,
        RepositoryCiPromotionJournal promotions,
        RepositoryCiCandidateJournal candidates)
    {
        this.client = client;
        this.authority = authority;
        this.ciEvents = ciEvents;
        this.ciController = ciController;
        CiRunners = ciRunners;
        CiRunnerCredentials = ciRunnerCredentials;
        ForgejoWebhooks = forgejoWebhooks;
        ForgejoSources = forgejoSources;
        NativeGitOpsSources = nativeGitOpsSources;
        Pipelines = pipelines;
        Jobs = jobs;
        Promotions = promotions;
        Candidates = candidates;
    }

    public Task Completion => Task.WhenAny(authority.Completion, ciEvents.Completion).Unwrap();
    public ForgejoWebhookJournal ForgejoWebhooks { get; }
    public CiRunnerConsumerReconciler CiRunners { get; }
    public CiRunnerNatsCredentialIssuer? CiRunnerCredentials { get; }
    public ForgejoSourceJournal ForgejoSources { get; }
    public NativeGitOpsSourceJournal NativeGitOpsSources { get; }
    public RepositoryCiPipelineJournal Pipelines { get; }
    public RepositoryCiJobJournal Jobs { get; }
    public RepositoryCiPromotionJournal Promotions { get; }
    public RepositoryCiCandidateJournal Candidates { get; }
    public RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;

    public static async Task<GlobalNatsRuntime> StartAsync(
        GlobalNatsConfiguration configuration,
        string instance,
        INatsAccountJwtSigner? ciRunnerNatsSigner,
        CancellationToken cancellationToken,
        ForgejoSourceConfiguration? ciSource = null,
        OciCiRunnerPoolConfiguration? ciPool = null,
        IRepositoryCiJobSigner? ciJobSigner = null,
        IRepositoryCiArtifactSignatureVerifier? ciArtifactSignatures = null,
        IRepositoryCiArtifactSignatureVerifier? ciRuntimeSignatures = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if ((ciArtifactSignatures is null) != (ciRuntimeSignatures is null))
            throw new ArgumentException("OCI CI artifact and runtime signature verifiers must be configured together.");
        var topology = new GlobalNatsTopology(3);
        var client = new NatsClient(new NatsOpts
        {
            Url = configuration.Url,
            RetryOnInitialConnect = true,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = new NatsAuthOpts { NKeyFile = configuration.NKeyFile },
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
            var state = await ReconcileStateWithRetryAsync(client, topology, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartGlobalAsync(
                state.Leaders,
                instance,
                cancellationToken);
            if (!authority.Snapshot.Ready)
                throw new InvalidOperationException("Global authority did not reach a ready leader or follower state.");
            var ledger = new NatsForgejoDeliveryLedger(state.Releases);
            var objects = new NatsDeliveryObjectStore(state.Bundles);
            var runnerLedger = new NatsForgejoDeliveryLedger(state.RunnerJobs);
            var runnerObjects = new NatsDeliveryObjectStore(state.RunnerBundles);
            var triggerJournal = new ForgejoCiTriggerJournal(ledger);
            var pipelines = new RepositoryCiPipelineJournal(ledger, objects);
            var jobs = new RepositoryCiJobJournal(ledger);
            var candidates = new RepositoryCiCandidateJournal(ledger, objects);
            var runnerConsumers = new CiRunnerConsumerReconciler(client.CreateJetStreamContext(), topology);
            RepositoryCiQualificationController? qualificationController = null;
            if (ciPool is not null)
            {
                if (ciSource is null || ciJobSigner is null)
                    throw new ArgumentException("OCI CI requires Forgejo source access and a command signer.");
                var source = ForgejoSourceClient.Create(ciSource);
                var capacity = OciCiRunnerComputeAdapter.CreateForInstancePrincipal(ciPool.Endpoint.ToString());
                try
                {
                    var coordinator = new RepositoryCiPipelineCoordinator(
                        triggerJournal,
                        pipelines,
                        source.ReadChangedPathsAsync,
                        async (trigger, token) =>
                        {
                            var revision = await source.ResolveAsync(trigger.Envelope.Revision, token);
                            var descriptor = await source.ReadFileAsync(
                                revision.Commit,
                                RepositoryCiImpactPlanner.DescriptorPath,
                                ForgejoSourceClient.MaximumFileBytes,
                                token);
                            return new([descriptor], [revision]);
                        });
                    var dispatcher = new RepositoryCiJobDispatchCoordinator(
                        jobs,
                        new(runnerObjects),
                        new(jobs, new(new NatsRepositoryCiJobTransport(client), ciJobSigner)),
                        source.ReadArchiveAsync,
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
                    Func<RepositoryCiPipelinePlan, CancellationToken, Task<bool>>? recordCandidate = null;
                    if (ciArtifactSignatures is not null && ciRuntimeSignatures is not null)
                    {
                        var executions = new RepositoryCiJobExecutionJournal(runnerLedger);
                        var attestations = new RepositoryCiArtifactAttestationJournal(
                            runnerLedger,
                            runnerObjects);
                        var artifacts = new RepositoryCiCandidateArtifactReader(
                            (job, token) => executions.ReadAsync(
                                job.RunnerId,
                                job.Document.PipelineDigest,
                                job.Job.Request.Job.Value,
                                token),
                            new(runnerObjects),
                            new RepositoryCiSignedArtifactAttestationVerifier(
                                attestations.ReadArtifactAsync,
                                attestations.ReadRuntimeAsync,
                                ciArtifactSignatures,
                                ciRuntimeSignatures));
                        var candidateCoordinator = new RepositoryCiCandidateCoordinator(
                            candidates,
                            jobs.ReadAsync,
                            artifacts.ReadAsync);
                        recordCandidate = async (pipeline, token) =>
                        {
                            var lease = authority.Snapshot;
                            if (!lease.Ready || !lease.IsLeader || lease.Epoch <= 0 || lease.KvRevision <= 0)
                                return false;
                            bool StillValid() => RepositoryCiController.SameAuthority(lease, authority.Snapshot);
                            var receipt = await candidateCoordinator.CoordinateAsync(
                                pipeline,
                                lease.Epoch,
                                lease.KvRevision,
                                StillValid,
                                token);
                            if (receipt.IsRecorded) return true;
                            if (receipt.Disposition == RepositoryCiCandidateCoordinationDisposition.AuthorityLost)
                                return false;
                            throw new InvalidDataException(
                                $"Repository CI candidate recording failed closed: {receipt.Disposition}.");
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
                        ownedSource: source,
                        recordCandidate: recordCandidate);
                    var qualificationCoordinator = new RepositoryCiQualificationCoordinator(
                        triggerJournal,
                        candidates,
                        async (trigger, token) =>
                        {
                            var observation = await source.PollBranchAsync("main", token);
                            if (observation.Revision.Repository != trigger.Envelope.Repository)
                                throw new InvalidDataException(
                                    "The protected-main source does not match the qualification trigger.");
                            return [observation];
                        });
                    qualificationController = new(
                        qualificationCoordinator.CoordinateAsync,
                        () => authority.Snapshot,
                        source.ReportCommitStatusAsync);
                }
                catch
                {
                    capacity.Dispose();
                    await source.DisposeAsync();
                    throw;
                }
            }
            var ciEvents = ForgejoCiEventConsumer.Start(
                state.CiConsumer,
                new(triggerJournal, () => authority.Snapshot),
                () => authority.Snapshot,
                ciController is null || qualificationController is null
                    ? null
                    : (trigger, token) => trigger.RequiresQualifiedCandidate
                        ? qualificationController.RunToCompletionAsync(trigger, token)
                        : ciController.RunToCompletionAsync(trigger, token));
            return new(
                client,
                authority,
                ciEvents,
                ciController,
                runnerConsumers,
                ciRunnerNatsSigner is null ? null : new(topology, ciRunnerNatsSigner),
                new(ledger, new NatsForgejoEventPublisher(client)),
                new(ledger),
                new(ledger, objects),
                new(ledger, objects),
                new(ledger),
                new(ledger),
                candidates);
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
                return new(leaders, releases, runnerJobs, bundles, runnerBundles, ciConsumer);
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

    private sealed record GlobalState(
        INatsKVStore Leaders,
        INatsKVStore Releases,
        INatsKVStore RunnerJobs,
        INatsObjStore Bundles,
        INatsObjStore RunnerBundles,
        INatsJSConsumer CiConsumer);
}
