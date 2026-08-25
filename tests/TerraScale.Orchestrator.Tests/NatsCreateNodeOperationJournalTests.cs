using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.Runtime;
using TerraScale.Orchestrator.Messaging;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.Tests;

// These integration tests each own one or more NATS servers. Running them alongside
// other tests in this module makes startup verification contend for the same bounded
// validation resources and intermittently time out during pre-deployment attestation.
[NotInParallel]
public sealed class NatsCreateNodeOperationJournalTests
{
    [Test]
    public async Task RealJetStreamConvergesThreeCellsAndRestartResumesTheDurableAdvertisement()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var store = await server.OpenAsync(new NatsKVConfig("GLOBAL_CELLS")
        {
            History = 16,
            MaxAge = TimeSpan.FromDays(30),
            MaxValueSize = 64 * 1024,
            MaxBytes = 64 * 1024 * 1024,
            NumberOfReplicas = 1,
        });
        var gruAuthority = Authority(7, 11);
        var sfoAuthority = Authority(8, 13);
        var fraAuthority = Authority(9, 17);
        await using (var checkOnly = GlobalCellDirectoryRuntime.Start(
                         store, "iad", () => Membership("iad"), () => Authority(10, 19), publishEnabled: false))
        {
            await Task.Delay(100);
            await Assert.That(async () =>
                    _ = await store.GetEntryAsync<string>(GlobalNatsTopology.CellAdvertisementKey("iad")))
                .Throws<NatsKVKeyNotFoundException>();
        }
        await using var gru = GlobalCellDirectoryRuntime.Start(
            store, "gru", () => Membership("gru"), () => gruAuthority);
        await using var sfo = GlobalCellDirectoryRuntime.Start(
            store, "sfo", () => Membership("sfo"), () => sfoAuthority);
        var fra = GlobalCellDirectoryRuntime.Start(
            store, "fra", () => Membership("fra"), () => fraAuthority);
        try
        {
            var converged = await WaitForDirectoryAsync(gru, 3, TimeSpan.FromSeconds(5));
            await Assert.That(converged.Cells.Select(static cell => cell.Cell))
                .IsEquivalentTo(["fra", "gru", "sfo"]);

            await fra.DisposeAsync();
            await Task.Delay(GlobalCellDirectoryRuntime.AdvertisementLease + TimeSpan.FromSeconds(1));
            var partitioned = gru.Snapshot;
            await Assert.That(partitioned.ActiveCells).IsEqualTo(2);
            await Assert.That(partitioned.StaleCells).IsEqualTo(1);
            await Assert.That(partitioned.Cells.Single(cell => cell.Cell == "fra").IsStale).IsTrue();
            await Assert.That(partitioned.Cells.Single(cell => cell.Cell == "sfo").IsStale).IsFalse();

            var restartedAuthority = Authority(9, 18);
            var recovery = Stopwatch.StartNew();
            await using var restartedFra = GlobalCellDirectoryRuntime.Start(
                store, "fra", () => Membership("fra"), () => restartedAuthority);
            var recovered = await WaitForDirectoryAsync(
                gru,
                3,
                TimeSpan.FromSeconds(5),
                snapshot => snapshot.Cells.Single(cell => cell.Cell == "fra").AuthorityRevision == 18);
            await Assert.That(recovered.Cells.Count).IsEqualTo(3);
            await Assert.That(recovered.Cells.Single(cell => cell.Cell == "fra").Sequence).IsEqualTo(1);
            await Assert.That(recovery.Elapsed).IsLessThan(TimeSpan.FromSeconds(3));
        }
        finally
        {
            await fra.DisposeAsync();
        }
    }

    [Test]
    public async Task RuntimeLifecycleBridgeRejectsRf1StoresBeforeConsumingItsProof()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var topology = new NatsTopology("journal", 1);
        await using var writer = await server.ConnectAsAsync(port => new NatsOpts { Url = $"nats://127.0.0.1:{port}" });
        await using var controller = await server.ConnectAsAsync(port => new NatsOpts { Url = $"nats://127.0.0.1:{port}" });
        var writerKeyValue = writer.CreateJetStreamContext().CreateKeyValueStoreContext();
        var store = await writerKeyValue.CreateOrUpdateStoreAsync(Rf1Operations());
        var proofs = await writerKeyValue.CreateOrUpdateStoreAsync(Rf1ProofConsumptions());
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var controllerIdentity = "controller";
        await using var service = await NatsOperationJournalMutationService.StartAsync(
            writer, store, proofs, topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
            new HashSet<string>(StringComparer.Ordinal) { controllerIdentity },
            CreateReplySigner(replyKey.ExportPkcs8PrivateKey()), default, enableRuntimeLifecycleProtocol: true);
        var proposed = RuntimeLifecycleCheckpoint.Proposed(RuntimeRequest("journal"));
        var signer = new NatsOperationJournalMutationAuthoritySigner(controllerIdentity, authorityKey);
        var requestId = Guid.NewGuid().ToString("N");
        var key = RuntimeLifecycleNatsProtocol.Key(proposed.OperationKey);
        var request = new NatsRuntimeLifecycleJournalReadRequest(
            RuntimeLifecycleNatsProtocol.SchemaVersion,
            topology.Cell,
            key,
            requestId,
            signer.Issue(
                topology.Cell,
                RuntimeLifecycleNatsProtocol.ReadAction,
                key,
                0,
                RuntimeLifecycleNatsProtocol.ProofBinding(
                    RuntimeLifecycleNatsProtocol.ReadAction,
                    RuntimeLifecycleNatsProtocol.SchemaVersion,
                    topology.Cell,
                    key,
                    0,
                    0,
                    requestId,
                    null)));

        var response = await RequestRuntimePrivateAsync(
            controller,
            topology.Cell,
            controllerIdentity,
            RuntimeLifecycleNatsProtocol.Subject(topology.Cell, "read"),
            request);
        await Assert.That(response.Status).IsEqualTo((int)RuntimeLifecycleJournalReadStatus.Unavailable);
        await Assert.That(await NatsOperationJournalMutationProofConsumption.ConsumeAsync(proofs, request.Authority, default))
            .IsEqualTo(NatsOperationJournalMutationProofConsumptionResult.Consumed);
    }

    [Test]
    public async Task AuthenticatedR3JournalWriterComposesRuntimeEndpointsRestartsAndRejectsDrift()
    {
        if (!OperatingSystem.IsLinux()) return;

        var securityDirectory = Path.Combine(Path.GetTempPath(), $"ts-orch-runtime-journal-r3-{Guid.NewGuid():N}");
        try
        {
            var development = DevelopmentTopology.CreateRegional();
            var cell = development.Cells.Single(candidate => candidate.Cell == "gru");
            var security = DevelopmentNatsSecurity.Create(development, securityDirectory).Cell(cell.Cell);
            var serverTls = security.Tls.Control.Servers[cell.OfKind(DevelopmentResourceKind.ControlNats).Single().Name].Client;
            var controllerTls = security.Tls.Control.Clients[cell.OfKind(DevelopmentResourceKind.ControllerAgent).Single().Name];
            await using var server = await ThreeNodeJetStream.StartAsync(
                NatsDevelopmentCluster.ControlAuthorization(cell, security),
                security.Infrastructure.SeedFile,
                port => SecureNatsOptions(port, security.Infrastructure, controllerTls),
                NatsDevelopmentCluster.TlsConfiguration(serverTls),
                [securityDirectory]);
            var topology = new NatsTopology(cell.Cell, 3, "controller-1");
            await using var infrastructure = await server.ConnectAsAsync(
                port => SecureNatsOptions(port, security.Infrastructure, controllerTls));
            await EventuallyAsync(() => NatsOperationJournalProvisioner.ProvisionTopologyAsync(
                infrastructure, topology, default));

            using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var reply = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var replyKeyFile = Path.Combine(securityDirectory, "runtime-journal-reply.pem");
            await File.WriteAllTextAsync(replyKeyFile, reply.ExportPkcs8PrivateKeyPem());
            File.SetUnixFileMode(replyKeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var options = new OrchestratorOptions(
                OrchestratorCommand.JournalWriter,
                cell.Cell,
                $"tls://127.0.0.1:{server.Port}",
                3,
                Instance: "journal-writer",
                AuthoritativeJournal: new NatsAuthoritativeJournalConfiguration(
                    security.JournalWriter.SeedFile,
                    new NatsTlsFiles(
                        controllerTls.CaFile,
                        controllerTls.CertificateFile,
                        controllerTls.KeyFile),
                    authority.ExportSubjectPublicKeyInfo(),
                    replyKeyFile,
                    reply.ExportSubjectPublicKeyInfo(),
                    new HashSet<string>(StringComparer.Ordinal) { security.Controllers[1].PublicKey }));
            await using var controller = await server.ConnectAsAsync(
                port => SecureNatsOptions(port, security.Controllers[1], controllerTls));
            var journal = new NatsRuntimeLifecycleJournal(
                new(cell.Cell),
                new NatsOperationJournalMutationClient(
                    controller,
                    topology,
                    new NatsOperationJournalMutationAuthoritySigner(security.Controllers[1].PublicKey, authority),
                    new NatsOperationJournalMutationReplyVerifier(reply.ExportSubjectPublicKeyInfo())));
            var checkpoint = RuntimeLifecycleCheckpoint.Proposed(RuntimeRequest(cell.Cell));
            var writer = await NatsJournalWriterRuntime.StartAsync(options, default);
            try
            {
                await Assert.That((await journal.ReadAsync(checkpoint.OperationKey, default)).Status)
                    .IsEqualTo(RuntimeLifecycleJournalReadStatus.Missing);
                var created = await journal.CompareExchangeAsync(checkpoint.OperationKey, null, checkpoint, default);
                await Assert.That(created.Status).IsEqualTo(RuntimeLifecycleJournalWriteStatus.Applied);
                await Assert.That((await journal.ReadAsync(checkpoint.OperationKey, default)).Status)
                    .IsEqualTo(RuntimeLifecycleJournalReadStatus.Found);
                await Assert.That(async () => _ = await controller.RequestAsync<string, string>(
                        "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                        "{}"))
                    .Throws<NatsException>();

                await writer.DisposeAsync();
                writer = await NatsJournalWriterRuntime.StartAsync(options, default);
                await Assert.That((await journal.ReadAsync(checkpoint.OperationKey, default)).Status)
                    .IsEqualTo(RuntimeLifecycleJournalReadStatus.Found);

                var drifted = NatsOperationJournalStore.CanonicalStream(topology.Operations);
                drifted.AllowDirect = false;
                await infrastructure.CreateJetStreamContext().CreateOrUpdateStreamAsync(drifted);
                var requestId = Guid.NewGuid().ToString("N");
                var key = RuntimeLifecycleNatsProtocol.Key(checkpoint.OperationKey);
                var request = new NatsRuntimeLifecycleJournalReadRequest(
                    RuntimeLifecycleNatsProtocol.SchemaVersion,
                    topology.Cell,
                    key,
                    requestId,
                    new NatsOperationJournalMutationAuthoritySigner(security.Controllers[1].PublicKey, authority).Issue(
                        topology.Cell,
                        RuntimeLifecycleNatsProtocol.ReadAction,
                        key,
                        0,
                        RuntimeLifecycleNatsProtocol.ProofBinding(
                            RuntimeLifecycleNatsProtocol.ReadAction,
                            RuntimeLifecycleNatsProtocol.SchemaVersion,
                            topology.Cell,
                            key,
                            0,
                            0,
                            requestId,
                            null)));
                var unavailable = await RequestRuntimePrivateAsync(
                    controller,
                    topology.Cell,
                    security.Controllers[1].PublicKey,
                    RuntimeLifecycleNatsProtocol.Subject(topology.Cell, "read"),
                    request);
                await Assert.That(unavailable.Status).IsEqualTo((int)RuntimeLifecycleJournalReadStatus.Unavailable);
            }
            finally
            {
                await writer.DisposeAsync();
            }
        }
        finally
        {
            if (Directory.Exists(securityDirectory)) Directory.Delete(securityDirectory, recursive: true);
        }
    }

    [Test]
    public async Task LocalNatsServerLeaseWaitsForReleaseAndIsIdempotent()
    {
        var first = await LocalNatsServerLease.AcquireAsync();
        using var canceledWait = new CancellationTokenSource();
        var canceled = LocalNatsServerLease.AcquireAsync(canceledWait.Token).AsTask();
        canceledWait.Cancel();
        await Assert.That(canceled).Throws<OperationCanceledException>();
        var contenderStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var contender = Task.Run(async () =>
        {
            contenderStarted.SetResult();
            await using var second = await LocalNatsServerLease.AcquireAsync();
            return true;
        });

        await contenderStarted.Task;
        await Task.Yield();
        await Assert.That(contender.IsCompleted).IsFalse();
        await first.DisposeAsync();
        await first.DisposeAsync();
        await Assert.That(await contender).IsTrue();
    }

    [Test]
    public async Task LocalNatsServerCleanupAttemptsEveryStepBeforeReportingFailures()
    {
        var cleanup = new LocalNatsServerLease.Cleanup();
        var steps = new List<int>();
        cleanup.Attempt(() =>
        {
            steps.Add(1);
            throw new InvalidOperationException("first");
        });
        await cleanup.AttemptAsync(() =>
        {
            steps.Add(2);
            return Task.CompletedTask;
        });
        cleanup.Attempt(() =>
        {
            steps.Add(3);
            throw new IOException("third");
        });

        await Assert.That(steps.Count).IsEqualTo(3);
        await Assert.That(steps[0]).IsEqualTo(1);
        await Assert.That(steps[1]).IsEqualTo(2);
        await Assert.That(steps[2]).IsEqualTo(3);
        await Assert.That(() => cleanup.ThrowIfFailed()).Throws<AggregateException>();
    }

    [Test]
    public async Task LocalNatsServerLeaseRetainsQuarantineUntilCleanupCanBeRetried()
    {
        var retained = await LocalNatsServerLease.AcquireAsync();
        var owner = new RetriableLeaseOwner(retained);
        LocalNatsServerLease.Retain(owner);

        var contenderStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var contender = Task.Run(async () =>
        {
            contenderStarted.SetResult();
            await using var acquired = await LocalNatsServerLease.AcquireAsync();
            return true;
        });
        await contenderStarted.Task;
        await Task.Yield();
        await Assert.That(contender.IsCompleted).IsFalse();

        Func<Task> firstRecovery = () => LocalNatsServerLease.RetryRetainedAsync().AsTask();
        await Assert.That(firstRecovery).Throws<IOException>();
        await Assert.That(contender.IsCompleted).IsFalse();
        await LocalNatsServerLease.RetryRetainedAsync();
        await Assert.That(await contender).IsTrue();
    }

    [Test]
    public async Task OneNodeJetStreamPersistsCasButRejectsJournalMutationWhenRf1IsNotR3()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var topology = new NatsTopology("journal", 1);
        var rf1Operations = Rf1Operations();
        var store = await server.OpenAsync(rf1Operations);
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var status = await store.GetStatusAsync();
        await Assert.That(status.Info.Config.NumReplicas).IsEqualTo(1);
        await Assert.That(status.Info.Config.MaxAge).IsEqualTo(TimeSpan.Zero);
        var key = "operation.cas-journal";
        var revision = await store.CreateAsync(key, "ProviderCallStarted");
        await Assert.That(await TryUpdateAsync(store, key, "ProviderCallStarted;first", revision)).IsTrue();
        await Assert.That(await TryUpdateAsync(store, key, "ProviderCallStarted;second", revision)).IsFalse();

        var beforeRestart = await store.GetEntryAsync<string>(key);
        beforeRestart.EnsureSuccess();

        await server.RestartAsync();
        store = await server.OpenAsync(rf1Operations);
        var reloaded = await store.GetEntryAsync<string>(key);
        reloaded.EnsureSuccess();
        await Assert.That(reloaded.Value).IsEqualTo("ProviderCallStarted;first");
        await Assert.That(reloaded.Revision).IsEqualTo(beforeRestart.Revision);

        Func<Task> openAuthoritative = async () => { await server.OpenAuthoritativeAsync(topology.Operations); };
        await Assert.That(openAuthoritative).Throws<InvalidOperationException>();
        var afterRejectedOpen = await store.GetEntryAsync<string>(key);
        afterRejectedOpen.EnsureSuccess();
        await Assert.That(afterRejectedOpen.Revision).IsEqualTo(reloaded.Revision);

        var journal = new NatsCreateNodeOperationJournal(store, topology,
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = RandomNumberGenerator.GetBytes(32) }), signer);
        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MutationRequiresActualR3ConfigurationAndHealthyInjectedKeyService()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var store = await server.OpenAsync(Rf1Operations());
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var key = RandomNumberGenerator.GetBytes(32);

        var healthy = false;
        var journal = new NatsCreateNodeOperationJournal(store, new NatsTopology("journal", 1),
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = key }, () => healthy), signer);
        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CrossCellPrepareIsRejectedBeforeJournalMutation()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var store = await server.OpenAsync(Rf1Operations("sfo"));
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var journal = new NatsCreateNodeOperationJournal(
            store,
            new NatsTopology("sfo", 1),
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = RandomNumberGenerator.GetBytes(32) }),
            new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey));

        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DedicatedOperationKvNeverExpiresTombstonesAndIsR3Configured()
    {
        var operations = new NatsTopology("gru", 3).Operations;

        await Assert.That(new NatsTopology("gru", 1).Operations.NumberOfReplicas).IsEqualTo(3);

        await Assert.That(operations.Bucket).IsEqualTo("ORCH_OPERATIONS");
        await Assert.That(operations.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(operations.History).IsEqualTo(2);
        await Assert.That(operations.MaxAge).IsEqualTo(TimeSpan.Zero);
        await Assert.That(operations.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(operations.MaxBytes).IsEqualTo(256 * 1024 * 1024);
        var proofs = new NatsTopology("gru", 1).OperationProofConsumptions;
        await Assert.That(proofs.Bucket).IsEqualTo("ORCH_OPERATION_PROOFS");
        await Assert.That(proofs.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(proofs.History).IsEqualTo(1);
        await Assert.That(proofs.MaxAge).IsEqualTo(TimeSpan.FromMinutes(5));
        await Assert.That(proofs.MaxValueSize).IsEqualTo(256);
        await Assert.That(proofs.MaxBytes).IsEqualTo(8 * 1024 * 1024);
    }

    [Test]
    public async Task ProvisioningUsesTheCompleteImmutableKvStreamConfiguration()
    {
        var stream = NatsOperationJournalStore.CanonicalStream(new NatsTopology("gru", 3).Operations);

        await Assert.That(stream.Name).IsEqualTo("KV_ORCH_OPERATIONS");
        await Assert.That(stream.Subjects).IsEquivalentTo(["$KV.ORCH_OPERATIONS.>"]);
        await Assert.That(stream.SubjectTransform).IsNull();
        await Assert.That(stream.Retention).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigRetention.Limits);
        await Assert.That(stream.MaxConsumers).IsEqualTo(-1);
        await Assert.That(stream.MaxMsgs).IsEqualTo(-1);
        await Assert.That(stream.MaxMsgsPerSubject).IsEqualTo(2);
        await Assert.That(stream.MaxBytes).IsEqualTo(256 * 1024 * 1024);
        await Assert.That(stream.MaxAge).IsEqualTo(TimeSpan.Zero);
        await Assert.That(stream.MaxMsgSize).IsEqualTo(16 * 1024);
        await Assert.That(stream.Storage).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigStorage.File);
        await Assert.That(stream.Compression).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigCompression.None);
        await Assert.That(stream.NumReplicas).IsEqualTo(3);
        await Assert.That(stream.NoAck).IsFalse();
        await Assert.That(stream.TemplateOwner).IsNull();
        await Assert.That(stream.Discard).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigDiscard.New);
        await Assert.That(stream.DuplicateWindow).IsEqualTo(TimeSpan.FromMinutes(2));
        await Assert.That(stream.Placement).IsNull();
        await Assert.That(stream.Sealed).IsFalse();
        await Assert.That(stream.DenyDelete).IsTrue();
        await Assert.That(stream.DenyPurge).IsTrue();
        await Assert.That(stream.AllowRollupHdrs).IsFalse();
        await Assert.That(stream.AllowDirect).IsTrue();
        await Assert.That(stream.Mirror).IsNull();
        await Assert.That(stream.Sources).IsNull();
        await Assert.That(stream.MirrorDirect).IsFalse();
        await Assert.That(stream.Republish).IsNull();
        await Assert.That(stream.DiscardNewPerSubject).IsFalse();
        await Assert.That(stream.AllowMsgTTL).IsFalse();
        await Assert.That(stream.SubjectDeleteMarkerTTL).IsEqualTo(TimeSpan.Zero);
        await Assert.That(stream.AllowMsgCounter).IsFalse();
        await Assert.That(stream.AllowMsgSchedules).IsFalse();
        await Assert.That(stream.AllowAtomicPublish).IsFalse();
        await Assert.That(stream.PersistMode).IsNull();
        await Assert.That(stream.Metadata).IsNull();
    }

    [Test]
    public async Task ProofConsumptionIsAtomicAcrossWritersAndSurvivesRestart()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var proofStore = await server.OpenAsync(Rf1ProofConsumptions());
        await using var secondWriter = await server.ConnectAsAsync(port => new NatsOpts
        {
            Url = $"nats://127.0.0.1:{port}",
            RequestTimeout = TimeSpan.FromSeconds(1),
        });
        var secondProofStore = await secondWriter.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync("ORCH_OPERATION_PROOFS");
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = new NatsOperationJournalMutationAuthoritySigner("controller", authority).Issue(
            "journal", "create", "operation." + new string('a', 64), 0, "ciphertext");

        var results = await Task.WhenAll(
            NatsOperationJournalMutationProofConsumption.ConsumeAsync(proofStore, proof, default).AsTask(),
            NatsOperationJournalMutationProofConsumption.ConsumeAsync(secondProofStore, proof, default).AsTask());
        await Assert.That(results.Count(static result => result == NatsOperationJournalMutationProofConsumptionResult.Consumed)).IsEqualTo(1);
        await Assert.That(results.Count(static result => result == NatsOperationJournalMutationProofConsumptionResult.AlreadyConsumed)).IsEqualTo(1);
        await server.RestartAsync();
        var afterRestart = await server.OpenAsync(Rf1ProofConsumptions());
        await Assert.That(await NatsOperationJournalMutationProofConsumption.ConsumeAsync(afterRestart, proof, default))
            .IsEqualTo(NatsOperationJournalMutationProofConsumptionResult.AlreadyConsumed);
    }

    [Test]
    public async Task ProofConsumptionKeyUsesFixedBigEndianLengthFraming()
    {
        var proof = new NatsOperationJournalMutationAuthorityProof(
            "gru", "UABC", "create", "operation." + new string('a', 64), 0, "digest", "lease-1",
            DateTimeOffset.UnixEpoch, "nonce-1", "signature");

        await Assert.That(NatsOperationJournalMutationProofConsumption.Key(proof))
            .IsEqualTo("proof.2fdbaac398c661e3f4d4157ab02eaab163880552274115dceaae5a4ebdb5d529");
    }

    [Test]
    public async Task ConfiguredCellValidationAcceptsOnlyItsExactR3Configuration()
    {
        var gru = new NatsTopology("gru", 3).Operations;
        var sfo = new NatsTopology("sfo", 3).Operations;
        var rf1 = Rf1Operations("gru");
        var proofConsumptions = new NatsTopology("gru", 3).OperationProofConsumptions;

        NatsOperationJournalStore.ValidateConfiguration(NatsOperationJournalStore.CanonicalStream(gru), gru);
        await Assert.That(() => NatsOperationJournalStore.ValidateConfiguration(
                NatsOperationJournalStore.CanonicalStream(sfo), gru))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NatsOperationJournalStore.ValidateConfiguration(
                NatsOperationJournalStore.CanonicalStream(rf1), gru))
            .Throws<InvalidOperationException>();
        var r5 = new NatsTopology("gru", 5).Operations;
        NatsOperationJournalStore.ValidateConfiguration(NatsOperationJournalStore.CanonicalStream(r5), r5);
        await Assert.That(() => NatsOperationJournalStore.ValidateConfiguration(
                NatsOperationJournalStore.CanonicalStream(sfo), r5))
            .Throws<InvalidOperationException>();
        NatsOperationJournalStore.ValidateConfiguration(
            NatsOperationJournalStore.CanonicalStream(proofConsumptions), proofConsumptions);
        await Assert.That(() => NatsOperationJournalStore.ValidateConfiguration(
                NatsOperationJournalStore.CanonicalStream(Rf1ProofConsumptions("gru")), proofConsumptions))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task BatchPublishMustRemainDisabledInTheJetStreamWireConfiguration()
    {
        using var currentDisabled = JsonDocument.Parse("""{"config":{"allow_batched":false}}""");
        NatsOperationJournalStore.ValidateBatchPublish(currentDisabled.RootElement);

        using var legacyDisabled = JsonDocument.Parse("""{"config":{"allow_batch_publish":false}}""");
        NatsOperationJournalStore.ValidateBatchPublish(legacyDisabled.RootElement);

        using var drifted = JsonDocument.Parse("""{"config":{"allow_batched":true}}""");
        await Assert.That(() => NatsOperationJournalStore.ValidateBatchPublish(drifted.RootElement))
            .Throws<InvalidOperationException>();

        using var omitted = JsonDocument.Parse("""{"config":{}}""");
        NatsOperationJournalStore.ValidateBatchPublish(omitted.RootElement);

        using var malformed = JsonDocument.Parse("""{"config":{"allow_batched":"false"}}""");
        await Assert.That(() => NatsOperationJournalStore.ValidateBatchPublish(malformed.RootElement))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CredentialedControllerReceivesImmediateRejectionsAndStopsBothWritersBeforeFixtureTeardown()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var securityDirectory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-security-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateRegional();
            var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
            var security = DevelopmentNatsSecurity.Create(topology, securityDirectory);
            var primaryCellSecurity = security.Cell(cell.Cell);
            var secondController = DevelopmentNatsSecurity.EnsureNKey(Path.Combine(securityDirectory, "controller-2.nk"));
            var cellSecurity = primaryCellSecurity with
            {
                Controllers = new Dictionary<int, DevelopmentNKeyIdentity>(primaryCellSecurity.Controllers)
                {
                    [2] = secondController
                }
            };
            await using var server = await OneNodeJetStream.StartAsync(
                NatsDevelopmentCluster.ControlAuthorization(cell, cellSecurity),
                port => new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                    RequestTimeout = TimeSpan.FromSeconds(1),
                    AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.Infrastructure.SeedFile },
                });
            await using var infrastructure = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.Infrastructure.SeedFile },
            });
            await infrastructure.CreateJetStreamContext().CreateOrUpdateStreamAsync(
                NatsOperationJournalStore.CanonicalStream(Rf1Operations(cell.Cell)));
            await infrastructure.CreateJetStreamContext().CreateOrUpdateStreamAsync(
                NatsOperationJournalStore.CanonicalStream(Rf1ProofConsumptions(cell.Cell)));

            await using var writer = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.JournalWriter.SeedFile },
            });
            var writerStore = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync("ORCH_OPERATIONS");
            var writerProofs = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync("ORCH_OPERATION_PROOFS");
            var key = "operation." + new string('a', 64);

            await using var controller = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.Controllers[1].SeedFile },
            });
            await using var controllerTwo = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.Controllers[2].SeedFile },
            });
            await using var writerTwo = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = cellSecurity.JournalWriter.SeedFile },
            });
            var writerStoreTwo = await writerTwo.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync("ORCH_OPERATIONS");
            var writerProofsTwo = await writerTwo.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync("ORCH_OPERATION_PROOFS");
            var journalTopology = new NatsTopology(cell.Cell, 1);
            var controllerIdentity = cellSecurity.Controllers[1].PublicKey;
            var secondControllerIdentity = cellSecurity.Controllers[2].PublicKey;
            using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var authoritySigner = new NatsOperationJournalMutationAuthoritySigner(controllerIdentity, authorityKey);
            var secondAuthoritySigner = new NatsOperationJournalMutationAuthoritySigner(secondControllerIdentity, authorityKey);
            using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var replyPrivateKey = replyKey.ExportPkcs8PrivateKey();
            var replyPublicKey = replyKey.ExportSubjectPublicKeyInfo();
            await using var mutations = await NatsOperationJournalMutationService.StartAsync(
                writer,
                writerStore,
                writerProofs,
                journalTopology,
                new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
                new HashSet<string>(StringComparer.Ordinal) { controllerIdentity, secondControllerIdentity },
                CreateReplySigner(replyPrivateKey),
                default);
            await using var mutationsTwo = await NatsOperationJournalMutationService.StartAsync(
                writerTwo,
                writerStoreTwo,
                writerProofsTwo,
                journalTopology,
                new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
                new HashSet<string>(StringComparer.Ordinal) { controllerIdentity, secondControllerIdentity },
                CreateReplySigner(replyPrivateKey),
                default);
            var mutationClient = new NatsOperationJournalMutationClient(
                controller,
                journalTopology,
                authoritySigner,
                new NatsOperationJournalMutationReplyVerifier(replyPublicKey));
            var mutationClientTwo = new NatsOperationJournalMutationClient(
                controllerTwo,
                journalTopology,
                secondAuthoritySigner,
                new NatsOperationJournalMutationReplyVerifier(replyPublicKey));
            var immediateRejections = await Task.WhenAll(Enumerable.Range(0, 8)
                .Select(_ => mutationClient.CreateAsync("operation.invalid", "invalid")));
            await Assert.That(immediateRejections.All(result => !result.Succeeded)).IsTrue();
            var create = await mutationClient.CreateAsync(key, "ProviderCallStarted");
            await Assert.That(create.Succeeded).IsTrue();
            var update = await mutationClient.UpdateAsync(key, "ProviderCallStarted;CAS", create.Revision);
            await Assert.That(update.Succeeded).IsTrue();
            await Assert.That((await mutationClient.CreateAsync(key, "reprepared")).Succeeded).IsFalse();
            var firstControllerKey = "operation." + new string('f', 64);
            var secondControllerKey = "operation." + new string('0', 64);
            var parallel = await Task.WhenAll(
                mutationClient.CreateAsync(firstControllerKey, "controller-one"),
                mutationClientTwo.CreateAsync(secondControllerKey, "controller-two"));
            await Assert.That(parallel.All(result => result.Succeeded)).IsTrue();

            var forgedKey = "operation." + new string('9', 64);
            var forgedRequest = new NatsOperationJournalCreateRequest(forgedKey, "forged-reply",
                authoritySigner.Issue(cell.Cell, "create", forgedKey, 0, "forged-reply"));
            var forgedReplySubject = journalTopology.OperationJournalReplySubject(controllerIdentity, Guid.NewGuid().ToString("N"));
            await using var forgedReplies = controller.SubscribeAsync<NatsOperationJournalMutationReply>(
                forgedReplySubject,
                opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(2) }).GetAsyncEnumerator();
            var forgedDigest = NatsOperationJournalMutationRequestDigest.Create(forgedRequest.Authority);
            var receiveForgedReply = forgedReplies.MoveNextAsync().AsTask();
            await writer.PublishAsync(forgedReplySubject, new NatsOperationJournalMutationReply(true, 999, forgedDigest, "syntactically-valid"));
            await controller.PublishAsync(journalTopology.OperationJournalCreateSubject, forgedRequest, replyTo: forgedReplySubject);
            await Assert.That(await receiveForgedReply).IsTrue();
            await Assert.That(new NatsOperationJournalMutationReplyVerifier(replyPublicKey)
                    .Verify(forgedReplies.Current.Data, forgedDigest))
                .IsFalse();

            var poisonedValue = "poisoned";
            var crossCellProof = authoritySigner.Issue("sfo", "create", "operation." + new string('b', 64), 0, poisonedValue);
            var crossCell = await RequestPrivateAsync(
                controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject,
                new NatsOperationJournalCreateRequest("operation." + new string('b', 64), poisonedValue, crossCellProof));
            await Assert.That(crossCell.Succeeded).IsFalse();

            var digestMismatchProof = authoritySigner.Issue(cell.Cell, "create", "operation." + new string('c', 64), 0, "signed-value");
            var digestMismatch = await RequestPrivateAsync(
                controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject,
                new NatsOperationJournalCreateRequest("operation." + new string('c', 64), poisonedValue, digestMismatchProof));
            await Assert.That(digestMismatch.Succeeded).IsFalse();

            var wrongCallerSigner = new NatsOperationJournalMutationAuthoritySigner("other-controller", authorityKey);
            var wrongCallerKey = "operation." + new string('e', 64);
            var wrongCaller = await RequestPrivateAsync(
                controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject,
                new NatsOperationJournalCreateRequest(wrongCallerKey, poisonedValue,
                    wrongCallerSigner.Issue(cell.Cell, "create", wrongCallerKey, 0, poisonedValue)));
            await Assert.That(wrongCaller.Succeeded).IsFalse();

            var replayKey = "operation." + new string('d', 64);
            var replayValue = "replay-protected";
            var replayRequest = new NatsOperationJournalCreateRequest(replayKey, replayValue,
                authoritySigner.Issue(cell.Cell, "create", replayKey, 0, replayValue));
            var firstReplay = await RequestPrivateAsync(controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject, replayRequest);
            await Assert.That(firstReplay.Succeeded).IsTrue();
            var secondReplay = await RequestPrivateAsync(controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject, replayRequest);
            await Assert.That(secondReplay.Succeeded).IsFalse();

            var consumedKey = "operation." + new string('7', 64);
            var consumedProof = authoritySigner.Issue(cell.Cell, "create", consumedKey, 0, "must-not-mutate");
            await writerProofs.CreateAsync(NatsOperationJournalMutationProofConsumption.Key(consumedProof), "consumed");
            var consumedBeforeMutation = await RequestPrivateAsync(
                controller, journalTopology, controllerIdentity,
                journalTopology.OperationJournalCreateSubject,
                new NatsOperationJournalCreateRequest(consumedKey, "must-not-mutate", consumedProof));
            await Assert.That(consumedBeforeMutation.Succeeded).IsFalse();
            Func<Task> readUnmutated = async () => _ = await writerStore.GetEntryAsync<string>(consumedKey);
            await Assert.That(readUnmutated).Throws<NatsKVKeyNotFoundException>();

            foreach (var (subject, headers) in new[]
                     {
                         ("$KV.ORCH_OPERATIONS.operation.delete", new NatsHeaders { ["KV-Operation"] = "DEL" }),
                         ("$KV.ORCH_OPERATIONS.operation.purge", new NatsHeaders { ["KV-Operation"] = "PURGE" }),
                         ("$KV.ORCH_OPERATIONS.operation.rollup", new NatsHeaders { ["Nats-Rollup"] = "sub" }),
                         ("$JS.API.STREAM.MSG.DELETE.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.STREAM.PURGE.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.STREAM.LIST", new NatsHeaders()),
                         ("$JS.API.STREAM.NAMES", new NatsHeaders()),
                         ("$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.API.STREAM.RESTORE.KV_ORCH_OPERATIONS", new NatsHeaders()),
                         ("$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATIONS.snapshot", new NatsHeaders()),
                         ("$JS.SNAPSHOT.ACK.KV_ORCH_OPERATIONS.snapshot", new NatsHeaders()),
                         ("$JS.API.DIRECT.GET.KV_ORCH_OPERATION_PROOFS", new NatsHeaders()),
                         ("$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATION_PROOFS", new NatsHeaders()),
                         ("$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS", new NatsHeaders()),
                         ("$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATION_PROOFS", new NatsHeaders()),
                         ("$JS.API.STREAM.RESTORE.KV_ORCH_OPERATION_PROOFS", new NatsHeaders()),
                         ("$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATION_PROOFS.snapshot", new NatsHeaders()),
                         ("$JS.SNAPSHOT.ACK.KV_ORCH_OPERATION_PROOFS.snapshot", new NatsHeaders()),
                         ("$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATIONS.controller-push", new NatsHeaders()),
                         ("$JS.API.CONSUMER.MSG.NEXT.KV_ORCH_OPERATIONS.controller-pull", new NatsHeaders()),
                         ("$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATION_PROOFS.controller-push", new NatsHeaders()),
                         ("$JS.API.CONSUMER.MSG.NEXT.KV_ORCH_OPERATION_PROOFS.controller-pull", new NatsHeaders()),
                     })
            {
                Func<Task> publish = async () =>
                    _ = await controller.RequestAsync<string, string>(subject, "{}", headers: headers);
                await Assert.That(publish).Throws<NatsException>();
            }
            foreach (var subject in new[]
                     {
                         "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                         "$JS.API.STREAM.LIST",
                         "$JS.API.STREAM.NAMES",
                         "$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATIONS",
                         "$JS.API.STREAM.RESTORE.KV_ORCH_OPERATIONS",
                         "$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATIONS.>",
                         "$JS.SNAPSHOT.ACK.KV_ORCH_OPERATIONS.>",
                         "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS",
                         "$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATION_PROOFS",
                         "$JS.API.STREAM.RESTORE.KV_ORCH_OPERATION_PROOFS",
                         "$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATION_PROOFS.>",
                         "$JS.SNAPSHOT.ACK.KV_ORCH_OPERATION_PROOFS.>",
                     })
            {
                var permissionError = await SubscribeDeniedAsync(
                    server.Port, cellSecurity.Controllers[2].SeedFile, subject);
                await Assert.That(permissionError).Contains("Permissions Violation for Subscription");
            }
            Func<Task> genericMutation = async () =>
                _ = await controller.RequestAsync<string, string>(
                    $"ts.orch.v1.{cell.Cell}.internal.operation-journal.mutate",
                    "{}");
            await Assert.That(genericMutation).Throws<NatsException>();

            Func<Task> writerRollup = async () =>
                (await writer.CreateJetStreamContext().PublishAsync(
                    "$KV.ORCH_OPERATIONS.operation.writer-rollup",
                    "{}",
                    headers: new NatsHeaders { ["Nats-Rollup"] = "sub" })).EnsureSuccess();
            await Assert.That(writerRollup).Throws<NatsException>();

            var persisted = await writerStore.GetEntryAsync<string>(key);
            persisted.EnsureSuccess();
            await Assert.That(persisted.Value).IsEqualTo("ProviderCallStarted;CAS");
            await Assert.That(persisted.Revision).IsEqualTo(update.Revision);
            await Task.WhenAll(mutations.DisposeAsync().AsTask(), mutationsTwo.DisposeAsync().AsTask())
                .WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally
        {
            if (Directory.Exists(securityDirectory)) Directory.Delete(securityDirectory, recursive: true);
        }
    }

    [Test]
    [NotInParallel("NatsR3")]
    public async Task InfrastructureProvisionerRejectsAndDoesNotReplaceACorruptExistingProtocolPackage()
    {
        if (!OperatingSystem.IsLinux()) return;

        var securityDirectory = Path.Combine(Path.GetTempPath(), $"ts-orch-r3-protocol-{Guid.NewGuid():N}");
        try
        {
            var cell = DevelopmentTopology.CreateRegional().Cells.Single(candidate => candidate.Cell == "gru");
            var security = DevelopmentNatsSecurity.Create(DevelopmentTopology.CreateRegional(), securityDirectory).Cell(cell.Cell);
            await using var server = await ThreeNodeJetStream.StartAsync(
                NatsDevelopmentCluster.ControlAuthorization(cell, security), security.Controllers[1].SeedFile);
            await using var infrastructure = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = security.Infrastructure.SeedFile },
            });
            var topology = new NatsTopology(cell.Cell, 3, "controller-1");
            var objects = infrastructure.CreateJetStreamContext().CreateObjectStoreContext();
            NATS.Client.ObjectStore.INatsObjStore? bundles = null;
            await EventuallyAsync(async () => bundles = await objects.CreateObjectStoreAsync(topology.ProtocolPackage));
            var corrupt = "corrupt"u8.ToArray();
            await bundles!.PutAsync(topology.ProtocolObject, corrupt);

            await Assert.That(async () => await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                    infrastructure, topology, default))
                .Throws<InvalidOperationException>();
            await Assert.That(await bundles.GetBytesAsync(topology.ProtocolObject)).IsEquivalentTo(corrupt);
        }
        finally
        {
            if (Directory.Exists(securityDirectory)) Directory.Delete(securityDirectory, recursive: true);
        }
    }

    [Test]
    [NotInParallel("NatsR3")]
    public async Task CredentialedR3ControllersConcurrentlyStartWithOneCanonicalConsumerWhileProtectedJournalApisRemainDenied()
    {
        if (!OperatingSystem.IsLinux()) return;

        var securityDirectory = Path.Combine(Path.GetTempPath(), $"ts-orch-r3-controller-{Guid.NewGuid():N}");
        try
        {
            var cell = DevelopmentTopology.CreateRegional().Cells.Single(candidate => candidate.Cell == "gru");
            var primarySecurity = DevelopmentNatsSecurity.Create(DevelopmentTopology.CreateRegional(), securityDirectory).Cell(cell.Cell);
            var security = primarySecurity with
            {
                Controllers = new Dictionary<int, DevelopmentNKeyIdentity>(primarySecurity.Controllers)
                {
                    [2] = DevelopmentNatsSecurity.EnsureNKey(Path.Combine(securityDirectory, "controller-2.nk")),
                },
            };
            await using var server = await ThreeNodeJetStream.StartAsync(
                NatsDevelopmentCluster.ControlAuthorization(cell, security), security.Controllers[1].SeedFile);
            await using var infrastructure = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = security.Infrastructure.SeedFile },
            });
            var journalTopology = new NatsTopology(cell.Cell, 3, "controller-1");
            await EventuallyAsync(() => NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                infrastructure, journalTopology, default));
            var jetStream = infrastructure.CreateJetStreamContext();
            var bundles = await jetStream.CreateObjectStoreContext().GetObjectStoreAsync(journalTopology.ProtocolPackage.Bucket);
            await Assert.That(await bundles.GetBytesAsync(journalTopology.ProtocolObject))
                .IsEquivalentTo(NatsProtocolPackage.Bytes);
            await EventuallyAsync(async () => _ = await jetStream.CreateOrUpdateStreamAsync(
                NatsOperationJournalStore.CanonicalStream(journalTopology.Operations)));
            await EventuallyAsync(async () => _ = await jetStream.CreateOrUpdateStreamAsync(
                NatsOperationJournalStore.CanonicalStream(journalTopology.OperationProofConsumptions)));
            var provisionedOperations = await jetStream.GetStreamAsync("KV_ORCH_OPERATIONS");
            await Assert.That(provisionedOperations.Info.Config.NumReplicas).IsEqualTo(3);
            await Assert.That((await jetStream.GetStreamAsync("CELL_EVENTS")).Info.Config.NumReplicas).IsEqualTo(3);

            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            // Check mode never registers the direct-delivery mutation endpoint: the startup
            // plan decision is passed explicitly (no verifier is configured here by design).
            var firstRuntime = NatsRuntime.StartAsync(new OrchestratorOptions(
                OrchestratorCommand.Check,
                cell.Cell,
                $"nats://127.0.0.1:{server.Port}",
                3,
                Instance: "controller-1",
                NatsNKeyFile: security.Controllers[1].SeedFile), startup.Token,
                registersDirectDeliveryEndpoint: false);
            var secondRuntime = NatsRuntime.StartAsync(new OrchestratorOptions(
                OrchestratorCommand.Check,
                cell.Cell,
                $"nats://127.0.0.1:{server.Port}",
                3,
                Instance: "controller-2",
                NatsNKeyFile: security.Controllers[2].SeedFile), startup.Token,
                registersDirectDeliveryEndpoint: false);
            var runtimes = await Task.WhenAll(firstRuntime, secondRuntime);
            await using var runtime = runtimes[0];
            await using var runtimeTwo = runtimes[1];
            await Assert.That(runtime.AuthoritySnapshot.Ready).IsTrue();
            await Assert.That(runtimeTwo.AuthoritySnapshot.Ready).IsTrue();
            RegionalRuntimeMembershipSnapshot membership = runtime.MembershipSnapshot;
            for (var attempt = 0; attempt < 50 && membership.Members.Count != 2; attempt++)
            {
                await Task.Delay(100, startup.Token);
                membership = runtime.MembershipSnapshot;
            }
            membership.Validate(cell.Cell);
            await Assert.That(membership.Members.Select(static member => member.Instance))
                .IsEquivalentTo(["controller-1", "controller-2"]);
            await Assert.That(membership.Members.All(static member =>
                member.Cluster == "orchestrator-control-gru" &&
                member.Capabilities.Contains("regional-membership", StringComparer.Ordinal) &&
                member.Capabilities.Contains("service-discovery", StringComparer.Ordinal))).IsTrue();

            // The infrastructure identity intentionally cannot inspect consumers; using it
            // here produced request timeouts after the authorization profile was tightened.
            await using var controllerInspector = await server.ConnectAsAsync(port => new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                RequestTimeout = TimeSpan.FromSeconds(1),
                AuthOpts = new NatsAuthOpts { NKeyFile = security.Controllers[1].SeedFile },
            });
            var controllerJetStream = controllerInspector.CreateJetStreamContext();
            var runtimeStore = await controllerJetStream.CreateKeyValueStoreContext()
                .GetStoreAsync(journalTopology.Runtime.Bucket);
            var injectedAt = DateTimeOffset.UtcNow;
            var injected = new RegionalRuntimeMember(
                1,
                cell.Cell,
                $"orchestrator-control-{cell.Cell}",
                "controller-3",
                Guid.NewGuid().ToString("N"),
                "failure-injection",
                ["authority", "regional-membership", "service-discovery"],
                injectedAt,
                injectedAt,
                injectedAt.AddSeconds(1),
                "follower",
                false,
                runtime.AuthoritySnapshot.Epoch,
                runtime.AuthoritySnapshot.KvRevision);
            var injectedValue = JsonSerializer.Serialize(
                injected,
                RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember);
            var injectedRevision = await runtimeStore.CreateAsync("controller.controller-3", injectedValue);
            try
            {
                var failureDetection = Stopwatch.StartNew();
                var complete = await WaitForMembershipAsync(
                    runtime,
                    static health => health.ActiveControllers == 3 &&
                                     health.Condition == RegionalRuntimeMembershipCondition.Healthy,
                    TimeSpan.FromSeconds(3),
                    startup.Token);
                await Assert.That(complete.MissingControllers).IsEqualTo(0);

                var degraded = await WaitForMembershipAsync(
                    runtime,
                    static health => health.ActiveControllers == 2 &&
                                     health.StaleControllers == 1 &&
                                     health.MissingControllers == 1 &&
                                     health.QuorumAvailable,
                    TimeSpan.FromSeconds(4),
                    startup.Token);
                failureDetection.Stop();
                await Assert.That(degraded.Condition).IsEqualTo(RegionalRuntimeMembershipCondition.Degraded);
                await Assert.That(failureDetection.Elapsed).IsLessThan(TimeSpan.FromSeconds(4));

                var recoveredAt = DateTimeOffset.UtcNow;
                var recovered = injected with
                {
                    SessionId = Guid.NewGuid().ToString("N"),
                    ObservedAt = recoveredAt,
                    LeaseExpiresAt = recoveredAt.Add(RegionalRuntimeMembership.LeaseDuration)
                };
                var recovery = Stopwatch.StartNew();
                injectedRevision = await runtimeStore.UpdateAsync(
                    "controller.controller-3",
                    JsonSerializer.Serialize(
                        recovered,
                        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMember),
                    injectedRevision);
                var restored = await WaitForMembershipAsync(
                    runtime,
                    static health => health.ActiveControllers == 3 &&
                                     health.StaleControllers == 0 &&
                                     health.Condition == RegionalRuntimeMembershipCondition.Healthy,
                    TimeSpan.FromSeconds(3),
                    startup.Token);
                recovery.Stop();
                await Assert.That(restored.QuorumAvailable).IsTrue();
                await Assert.That(recovery.Elapsed).IsLessThan(TimeSpan.FromSeconds(3));
            }
            finally
            {
                await runtimeStore.DeleteAsync(
                    "controller.controller-3",
                    new NatsKVDeleteOpts { Revision = injectedRevision });
            }
            NATS.Client.JetStream.INatsJSConsumer? startupConsumer = null;
            await EventuallyAsync(async () =>
            {
                startupConsumer = await controllerJetStream.GetConsumerAsync("CELL_EVENTS", "runtime_startup");
                await startupConsumer.RefreshAsync();
            });
            await Assert.That(CiRunnerConsumerReconciler.Matches(
                startupConsumer!.Info, journalTopology.StartupConsumer, "CELL_EVENTS")).IsTrue();

            foreach (var subject in new[]
                     {
                         "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                         "$JS.API.CONSUMER.LIST.KV_ORCH_OPERATIONS",
                         "$JS.API.CONSUMER.INFO.KV_ORCH_OPERATIONS.exfiltration",
                         "$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATIONS.exfiltration",
                         "$JS.API.CONSUMER.CREATE.CELL_EVENTS.exfiltration.denied",
                         "$JS.API.CONSUMER.DURABLE.CREATE.CELL_EVENTS.exfiltration.denied",
                         "$JS.API.STREAM.CREATE.journal_exfiltration",
                     })
            {
                await Assert.That(await PublishDeniedAsync(
                    server.Port, security.Controllers[1].SeedFile, subject, "{}"))
                    .Contains("Permissions Violation for Publish");
            }
            var cellEventsBefore = System.Text.Json.JsonSerializer.Serialize(
                (await jetStream.GetStreamAsync("CELL_EVENTS")).Info.Config);
            await Assert.That(await PublishDeniedAsync(
                server.Port,
                security.Controllers[1].SeedFile,
                "$JS.API.STREAM.UPDATE.CELL_EVENTS",
                "{\"name\":\"CELL_EVENTS\",\"sources\":[{\"name\":\"KV_ORCH_OPERATIONS\"}],\"mirror\":{\"name\":\"KV_ORCH_OPERATIONS\"}}"))
                .Contains("Permissions Violation for Publish");
            await Assert.That(System.Text.Json.JsonSerializer.Serialize(
                (await jetStream.GetStreamAsync("CELL_EVENTS")).Info.Config)).IsEqualTo(cellEventsBefore);
            var protocol = await bundles.GetInfoAsync(journalTopology.ProtocolObject);
            foreach (var subject in new[]
                     {
                         "$O.ORCH_PROTOCOL_PACKAGE.M.orchestrator-protocol-v1",
                         $"$O.ORCH_PROTOCOL_PACKAGE.C.{protocol.Nuid}",
                         "$O.OTHER_BUCKET.C.denied",
                     })
            {
                await Assert.That(await PublishDeniedAsync(
                    server.Port, security.Controllers[1].SeedFile, subject, "denied"))
                    .Contains("Permissions Violation for Publish");
            }
            await Assert.That(await SubscribeDeniedAsync(
                server.Port, security.Controllers[1].SeedFile, "$O.OTHER_BUCKET.C.denied"))
                .Contains("Permissions Violation");
        }
        finally
        {
            if (Directory.Exists(securityDirectory)) Directory.Delete(securityDirectory, recursive: true);
        }
    }

    [Test]
    public async Task MutationServiceCancellationBeforeRegistrationDisposesItsReplySigner()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        await using var writer = await server.ConnectAsAsync(port => new NatsOpts
        {
            Url = $"nats://127.0.0.1:{port}",
            RequestTimeout = TimeSpan.FromSeconds(1),
        });
        var topology = new NatsTopology("cleanup", 1);
        var operations = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .CreateOrUpdateStoreAsync(Rf1Operations(topology.Cell));
        var proofs = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .CreateOrUpdateStoreAsync(Rf1ProofConsumptions(topology.Cell));
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var replies = new NatsOperationJournalMutationReplySigner(replyKey);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Func<Task> start = async () => _ = await NatsOperationJournalMutationService.StartAsync(
            writer,
            operations,
            proofs,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
            new HashSet<string>(StringComparer.Ordinal) { "controller" },
            replies,
            cancellation.Token);
        await Assert.That(start).Throws<OperationCanceledException>();
        await Assert.That(() => replies.ExportPublicKey()).Throws<ObjectDisposedException>();

        Func<Task> ping = async () => _ = await writer.RequestAsync<string, string>(
            $"$SRV.PING.terrascale_orchestrator_journal_writer_{topology.Cell}", string.Empty);
        await Assert.That(ping).Throws<NatsNoRespondersException>();
    }

    [Test]
    public async Task JournalWriterStartupCancellationDisposesItsRetryingUnavailableClient()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-writer-cancel-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        try
        {
            var nkey = Path.Combine(directory, "writer.nk");
            await File.WriteAllTextAsync(nkey, NATS.Client.Core.NKeys.CreateUserSeed());
            var options = new OrchestratorOptions(
                OrchestratorCommand.JournalWriter,
                "cleanup",
                $"nats://127.0.0.1:{port}",
                3,
                AuthoritativeJournal: new NatsAuthoritativeJournalConfiguration(
                    nkey,
                    new NatsTlsFiles("unused-ca.pem", "unused-cert.pem", "unused-key.pem"),
                    Array.Empty<byte>(),
                    "unused-reply.pem",
                    Array.Empty<byte>(),
                    new HashSet<string>(StringComparer.Ordinal) { "controller" }));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            var startup = NatsJournalWriterRuntime.StartAsync(options, cancellation.Token);

            await Assert.That(async () => await startup.WaitAsync(TimeSpan.FromSeconds(2)))
                .Throws<OperationCanceledException>();
            await Assert.That(startup.IsCompleted).IsTrue();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static CreateNodeOperationJournalEntry Entry()
    {
        var now = DateTimeOffset.UtcNow;
        var binding = new CreateNodeReceiptBinding("operation-1", "tenant-1", "node-request-1", "idempotency-1", "create-1",
            "gru", "compartment-1", 1, 1, "template-1", "placement-1", "bootstrap-1", 1, "authorization-1", "provider-1");
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var recoveryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new(0, "fingerprint-1", binding,
            new CreateNodeHandoffReceiptSigner("receipt", receiptKey).Sign(binding, now, now.AddMinutes(5)),
            new CreateNodeRecoveryLookupSigner("recovery", recoveryKey).Sign(binding, now, now.AddDays(1)),
            CreateNodeJournalStage.Prepared, null, 0, null);
    }

    private static RuntimeLifecycleOperationRequest RuntimeRequest(string cell)
    {
        var plan = HostRuntimePlan.Create(HostRole.Platform, HostRuntimeDriver.OciContainer,
            new TerraScale.Orchestrator.Runtime.RuntimeAllocationId("platform-a"),
            new TerraScale.Orchestrator.Runtime.ArtifactDigest(RuntimeLifecycleFingerprint.Hash("artifact")), HostArchitecture.Arm64);
        return new(new(cell), new("node-a"), new(7), new(RuntimeLifecycleFingerprint.Hash("convergence")), plan,
            LifecycleAction.Converge, new(7), new(RuntimeLifecycleFingerprint.Hash("authorization")),
            new(new(RuntimeLifecycleFingerprint.Hash("deadline")), 9));
    }

    private static async Task<bool> TryUpdateAsync(INatsKVStore store, string key, string value, ulong revision)
    {
        try
        {
            await store.UpdateAsync(key, value, revision);
            return true;
        }
        catch (NatsKVWrongLastRevisionException)
        {
            return false;
        }
    }

    private static async Task<NatsOperationJournalMutationReply> RequestPrivateAsync<TRequest>(
        NatsClient client,
        NatsTopology topology,
        string callerIdentity,
        string subject,
        TRequest request)
    {
        var reply = topology.OperationJournalReplySubject(callerIdentity, Guid.NewGuid().ToString("N"));
        using var responseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsOperationJournalMutationReply>(
            reply,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(2) },
            cancellationToken: responseTimeout.Token);
        await client.PingAsync(responseTimeout.Token);
        await client.PublishAsync(subject, request, replyTo: reply, cancellationToken: responseTimeout.Token);
        return (await subscription.Msgs.ReadAsync(responseTimeout.Token)).Data
            ?? throw new InvalidOperationException("Private journal response was empty.");
    }

    private static async Task<NatsRuntimeLifecycleJournalReply> RequestRuntimePrivateAsync<TRequest>(
        NatsClient client,
        string cell,
        string callerIdentity,
        string subject,
        TRequest request)
        where TRequest : INatsOperationJournalMutationRequest
    {
        var reply = RuntimeLifecycleNatsProtocol.ReplySubject(cell, callerIdentity, Guid.NewGuid().ToString("N"));
        using var responseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsRuntimeLifecycleJournalReply>(
            reply,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(2) },
            cancellationToken: responseTimeout.Token);
        await client.PingAsync(responseTimeout.Token);
        await client.PublishAsync(subject, request, replyTo: reply, cancellationToken: responseTimeout.Token);
        return (await subscription.Msgs.ReadAsync(responseTimeout.Token)).Data
            ?? throw new InvalidOperationException("Private runtime journal response was empty.");
    }

    private static NatsOpts SecureNatsOptions(
        int port,
        DevelopmentNKeyIdentity identity,
        DevelopmentTlsIdentity tls) => new()
    {
        Url = $"tls://127.0.0.1:{port}",
        ConnectTimeout = TimeSpan.FromSeconds(2),
        RequestTimeout = TimeSpan.FromSeconds(3),
        AuthOpts = new NatsAuthOpts { NKeyFile = identity.SeedFile },
        TlsOpts = new NatsTlsOpts
        {
            Mode = TlsMode.Require,
            CaFile = tls.CaFile,
            CertFile = tls.CertificateFile,
            KeyFile = tls.KeyFile,
        },
    };

    private sealed class RetriableLeaseOwner(LocalNatsServerLease.Handle lease) : IAsyncDisposable
    {
        private int attempts;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Increment(ref attempts) == 1)
                throw new IOException("private root remains");
            await lease.ReleaseIfCleanAsync(new LocalNatsServerLease.Cleanup());
            LocalNatsServerLease.CompleteRetention(this);
        }
    }

    private static async Task<string> SubscribeDeniedAsync(int port, string seedFile, string subject)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var stream = tcp.GetStream();
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false), leaveOpen: true)
        {
            NewLine = "\r\n",
            AutoFlush = true,
        };
        var info = await reader.ReadLineAsync(timeout.Token)
            ?? throw new InvalidOperationException("NATS server did not send its connection info.");
        using var infoDocument = JsonDocument.Parse(info["INFO ".Length..]);
        var nonce = infoDocument.RootElement.GetProperty("nonce").GetString()
            ?? throw new InvalidOperationException("NATS server did not provide an NKey nonce.");
        var seed = File.ReadLines(seedFile).First(line => !string.IsNullOrWhiteSpace(line)).Trim();
        using var pair = NATS.Client.Core.NKeys.FromSeed(seed);
        var connect = JsonSerializer.Serialize(new
        {
            nkey = NATS.Client.Core.NKeys.PublicKeyFromSeed(seed),
            sig = Convert.ToBase64String(pair.Sign(System.Text.Encoding.UTF8.GetBytes(nonce))),
        });
        await writer.WriteLineAsync($"CONNECT {connect}");
        await writer.WriteLineAsync($"SUB {subject} 1");

        while (true)
        {
            var response = await reader.ReadLineAsync(timeout.Token)
                ?? throw new InvalidOperationException("NATS server closed before reporting the subscription result.");
            if (!response.StartsWith("+OK", StringComparison.Ordinal))
            {
                return response;
            }
        }
    }

    private static async Task<string> PublishDeniedAsync(int port, string seedFile, string subject, string payload)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var stream = tcp.GetStream();
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false), leaveOpen: true)
        {
            NewLine = "\r\n",
            AutoFlush = true,
        };
        var info = await reader.ReadLineAsync(timeout.Token)
            ?? throw new InvalidOperationException("NATS server did not send its connection info.");
        using var infoDocument = JsonDocument.Parse(info["INFO ".Length..]);
        var nonce = infoDocument.RootElement.GetProperty("nonce").GetString()
            ?? throw new InvalidOperationException("NATS server did not provide an NKey nonce.");
        var seed = File.ReadLines(seedFile).First(line => !string.IsNullOrWhiteSpace(line)).Trim();
        using var pair = NATS.Client.Core.NKeys.FromSeed(seed);
        await writer.WriteLineAsync($"CONNECT {JsonSerializer.Serialize(new { nkey = NATS.Client.Core.NKeys.PublicKeyFromSeed(seed), sig = Convert.ToBase64String(pair.Sign(System.Text.Encoding.UTF8.GetBytes(nonce))) })}");
        await writer.WriteLineAsync($"PUB {subject} {System.Text.Encoding.UTF8.GetByteCount(payload)}\r\n{payload}");
        while (true)
        {
            var response = await reader.ReadLineAsync(timeout.Token)
                ?? throw new InvalidOperationException("NATS server closed before reporting the publish result.");
            if (response.StartsWith("-ERR", StringComparison.Ordinal)) return response;
        }
    }

    private static NatsOperationJournalMutationReplySigner CreateReplySigner(byte[] privateKey)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new(key);
    }

    private static async Task EventuallyAsync(Func<Task> action)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await action();
                return;
            }
            catch (NatsJSApiException) when (attempt < 49)
            {
                await Task.Delay(100);
            }
            catch (NatsJSApiNoResponseException) when (attempt < 49)
            {
                await Task.Delay(100);
            }
        }
    }

    private static async Task<RegionalRuntimeMembershipHealth> WaitForMembershipAsync(
        NatsRuntime runtime,
        Func<RegionalRuntimeMembershipHealth, bool> predicate,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            var health = runtime.MembershipHealth;
            if (predicate(health)) return health;
            if (elapsed.Elapsed >= timeout)
                throw new TimeoutException("Regional runtime membership did not reach the expected health state.");
            await Task.Delay(50, cancellationToken);
        }
    }

    private static NatsKVConfig Rf1Operations(string cell = "journal") => new("ORCH_OPERATIONS")
    {
        Description = $"Authoritative encrypted regional operation journal for {cell}",
        History = 2,
        MaxValueSize = 16 * 1024,
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = 1,
    };

    private static NatsKVConfig Rf1ProofConsumptions(string cell = "journal") => new("ORCH_OPERATION_PROOFS")
    {
        Description = $"Expiry-bounded single-use operation journal authority proofs for {cell}",
        History = 1,
        MaxAge = TimeSpan.FromMinutes(5),
        MaxValueSize = 256,
        MaxBytes = 8 * 1024 * 1024,
        NumberOfReplicas = 1,
    };

    private static RegionalAuthoritySnapshot Authority(long epoch, long revision)
    {
        var now = DateTimeOffset.UtcNow;
        return new("leader", true, epoch, revision, now.AddSeconds(15), now, null);
    }

    private static RegionalRuntimeMembershipSnapshot Membership(string cell)
    {
        var now = DateTimeOffset.UtcNow;
        var member = new RegionalRuntimeMember(
            1,
            cell,
            $"orchestrator-control-{cell}",
            "controller-1",
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            now.AddMinutes(-1),
            now,
            now.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            7,
            11);
        var health = RegionalRuntimeMembershipHealth.Evaluate(cell, 3, [member], 0, now);
        return new(2, cell, now, health, [member]);
    }

    private static async Task<GlobalCellDirectorySnapshot> WaitForDirectoryAsync(
        GlobalCellDirectoryRuntime runtime,
        int activeCells,
        TimeSpan timeout,
        Func<GlobalCellDirectorySnapshot, bool>? predicate = null)
    {
        var started = Stopwatch.StartNew();
        while (started.Elapsed < timeout)
        {
            var snapshot = runtime.Snapshot;
            if (snapshot.ActiveCells == activeCells && (predicate?.Invoke(snapshot) ?? true))
                return snapshot;
            await Task.Delay(50);
        }
        throw new TimeoutException($"The global cell directory did not converge to {activeCells} active cells.");
    }

    private sealed class OneNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private readonly Func<int, NatsOpts>? clientOptions;
        private readonly ContainerizedNatsCluster containerCluster;
        private readonly LocalNatsServerLease.Handle lease;
        private Process? process;
        private NatsClient? client;
        private Task? processOutput;
        private int disposed;

        public int Port => port;

        private OneNodeJetStream(
            string directory,
            string configuration,
            int port,
            Func<int, NatsOpts>? clientOptions,
            ContainerizedNatsCluster containerCluster,
            LocalNatsServerLease.Handle lease)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
            this.clientOptions = clientOptions;
            this.containerCluster = containerCluster;
            this.lease = lease;
        }

        public static async Task<OneNodeJetStream> StartAsync(
            string? authorization = null,
            Func<int, NatsOpts>? clientOptions = null)
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-create-node-journal-{Guid.NewGuid():N}");
            OneNodeJetStream? server = null;
            try
            {
                Directory.CreateDirectory(directory);
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                var configuration = Path.Combine(directory, "nats.conf");
                await File.WriteAllTextAsync(configuration, $"port: {port}\n{authorization}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
                var containerCluster = await ContainerizedNatsCluster.CreateAsync(directory, [port]);
                server = new OneNodeJetStream(directory, configuration, port, clientOptions, containerCluster, lease);
                await server.ConnectAsync();
                return server;
            }
            catch (Exception startupFailure)
            {
                if (server is not null)
                {
                    try
                    {
                        await server.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                else
                {
                    var owner = new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease);
                    try
                    {
                        await owner.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                throw;
            }
        }

        public async Task<INatsKVStore> OpenAsync(NatsKVConfig configuration)
        {
            var jetStream = client!.CreateJetStreamContext();
            return await jetStream.CreateKeyValueStoreContext().CreateOrUpdateStoreAsync(configuration);
        }

        public async ValueTask<INatsKVStore> OpenAuthoritativeAsync(NatsKVConfig configuration) =>
            await NatsOperationJournalStore.OpenAsync(
                client!.CreateJetStreamContext().CreateKeyValueStoreContext(),
                configuration,
                default);

        public async Task RequestAsync(string subject, string payload) =>
            _ = await client!.RequestAsync<string, string>(subject, payload);

        public async Task<NatsClient> ConnectAsAsync(Func<int, NatsOpts> options)
        {
            var additional = new NatsClient(options(port));
            try
            {
                await additional.ConnectAsync();
                return additional;
            }
            catch
            {
                await additional.DisposeAsync();
                throw;
            }
        }

        public async Task RestartAsync()
        {
            if (client is not null) await client.DisposeAsync();
            client = null;
            if (process is not null)
            {
                await containerCluster.StopAsync(process);
                process.Dispose();
                process = null;
            }
            if (processOutput is not null)
            {
                await processOutput.WaitAsync(TimeSpan.FromSeconds(1));
                processOutput = null;
            }
            await ConnectAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
            var cleanup = new LocalNatsServerLease.Cleanup();
            try
            {
                if (client is not null &&
                    await cleanup.AttemptAsync(() => client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5))))
                    client = null;
                if (process is not null)
                {
                    if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                        cleanup.Attempt(process.Dispose))
                        process = null;
                }
                if (processOutput is not null &&
                    await cleanup.AttemptAsync(() => processOutput.WaitAsync(TimeSpan.FromSeconds(1))))
                    processOutput = null;
                await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
                if (await lease.ReleaseIfCleanAsync(cleanup))
                {
                    Volatile.Write(ref disposed, 2);
                    LocalNatsServerLease.CompleteRetention(this);
                }
                cleanup.ThrowIfFailed();
            }
            finally
            {
                if (Volatile.Read(ref disposed) == 1)
                {
                    LocalNatsServerLease.Retain(this);
                    Volatile.Write(ref disposed, 0);
                }
            }
        }

        private async Task ConnectAsync()
        {
            process = containerCluster.Start(configuration);
            processOutput = Task.WhenAll(
                process.StandardOutput.ReadToEndAsync(),
                process.StandardError.ReadToEndAsync());
            for (var attempt = 0; attempt < 50; attempt++)
            {
                client = new NatsClient(clientOptions?.Invoke(port) ?? new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                });
                try
                {
                    await client.ConnectAsync();
                    return;
                }
                catch (NatsException) when (attempt < 49)
                {
                    await client.DisposeAsync();
                    client = null;
                    await Task.Delay(50);
                }
            }
            throw new InvalidOperationException("The containerized NATS server did not accept a local JetStream connection.");
        }
    }

    private sealed class ThreeNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly int[] ports;
        private readonly Process?[] processes;
        private readonly Task?[] processOutput;
        private readonly ContainerizedNatsCluster containerCluster;
        private readonly LocalNatsServerLease.Handle lease;
        private int disposed;

        private ThreeNodeJetStream(
            string directory,
            int[] ports,
            Process?[] processes,
            Task?[] processOutput,
            ContainerizedNatsCluster containerCluster,
            LocalNatsServerLease.Handle lease)
        {
            this.directory = directory;
            this.ports = ports;
            this.processes = processes;
            this.processOutput = processOutput;
            this.containerCluster = containerCluster;
            this.lease = lease;
        }

        public int Port => ports[0];

        public static async Task<ThreeNodeJetStream> StartAsync(
            string authorization,
            string readinessNkeyFile,
            Func<int, NatsOpts>? readinessOptions = null,
            string? transportConfiguration = null,
            IEnumerable<string>? readOnlyRoots = null)
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-r3-journal-{Guid.NewGuid():N}");
            ThreeNodeJetStream? server = null;
            var processes = new Process?[3];
            var processOutput = new Task?[3];
            try
            {
                Directory.CreateDirectory(directory);
                var clientPorts = Enumerable.Range(0, 3).Select(_ => FreePort()).ToArray();
                var routePorts = Enumerable.Range(0, 3).Select(_ => FreePort()).ToArray();
                var configurations = clientPorts.Select((port, index) => Path.Combine(directory, $"nats-{index}.conf")).ToArray();
                for (var index = 0; index < 3; index++)
                {
                    var routes = string.Join(", ", routePorts.Where((_, candidate) => candidate != index)
                        .Select(route => $"\"nats-route://127.0.0.1:{route}\""));
                    await File.WriteAllTextAsync(configurations[index], $$"""
                        server_name: "journal-{{index}}"
                        port: {{clientPorts[index]}}
                        {{authorization}}
                        {{transportConfiguration}}
                        jetstream { store_dir: "{{Path.Combine(directory, $"store-{index}")}}" }
                        cluster {
                          name: "journal-r3"
                          host: "127.0.0.1"
                          port: {{routePorts[index]}}
                          routes: [{{routes}}]
                        }
                        """);
                }

                var containerCluster = await ContainerizedNatsCluster.CreateAsync(
                    directory,
                    clientPorts.Concat(routePorts),
                    readOnlyRoots);
                server = new ThreeNodeJetStream(directory, clientPorts, processes, processOutput, containerCluster, lease);
                for (var index = 0; index < configurations.Length; index++)
                {
                    processes[index] = containerCluster.Start(configurations[index]);
                    processOutput[index] = Task.WhenAll(
                        processes[index]!.StandardOutput.ReadToEndAsync(),
                        processes[index]!.StandardError.ReadToEndAsync());
                }
                // Rootless Podman must create the pod network and start three TLS
                // servers before the first connection can complete. Keep this
                // bounded, but allow materially more time than a host process.
                for (var attempt = 0; attempt < 150; attempt++)
                {
                    try
                    {
                        await using var client = await server.ConnectAsAsync(readinessOptions ?? (port => new NatsOpts
                        {
                            Url = $"nats://127.0.0.1:{port}",
                            ConnectTimeout = TimeSpan.FromSeconds(1),
                            AuthOpts = new NatsAuthOpts { NKeyFile = readinessNkeyFile },
                        }));
                        return server;
                    }
                    catch (NatsException) when (attempt < 149)
                    {
                        await Task.Delay(100);
                    }
                }
                throw new InvalidOperationException("The three-node containerized NATS cluster did not accept a local JetStream connection.");
            }
            catch (Exception startupFailure)
            {
                if (server is not null)
                {
                    try
                    {
                        await server.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                else
                {
                    var owner = new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease);
                    try
                    {
                        await owner.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                throw;
            }
        }

        public async Task<NatsClient> ConnectAsAsync(Func<int, NatsOpts> options)
        {
            var client = new NatsClient(options(Port));
            try
            {
                await client.ConnectAsync();
                return client;
            }
            catch
            {
                await client.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
            var cleanup = new LocalNatsServerLease.Cleanup();
            try
            {
                for (var index = 0; index < processes.Length; index++)
                {
                    var process = processes[index];
                    if (process is null) continue;
                    if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                        cleanup.Attempt(process.Dispose))
                        processes[index] = null;
                }
                for (var index = 0; index < processOutput.Length; index++)
                {
                    var output = processOutput[index];
                    if (output is not null &&
                        await cleanup.AttemptAsync(() => output.WaitAsync(TimeSpan.FromSeconds(1))))
                        processOutput[index] = null;
                }
                await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
                if (await lease.ReleaseIfCleanAsync(cleanup))
                {
                    Volatile.Write(ref disposed, 2);
                    LocalNatsServerLease.CompleteRetention(this);
                }
                cleanup.ThrowIfFailed();
            }
            finally
            {
                if (Volatile.Read(ref disposed) == 1)
                {
                    LocalNatsServerLease.Retain(this);
                    Volatile.Write(ref disposed, 0);
                }
            }
        }

        private static int FreePort()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
    }
}
