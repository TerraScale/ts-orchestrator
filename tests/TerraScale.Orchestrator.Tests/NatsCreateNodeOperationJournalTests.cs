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
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsCreateNodeOperationJournalTests
{
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
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofStore, proof, default).AsTask(),
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(secondProofStore, proof, default).AsTask());
        await Assert.That(results.Count(static result => result)).IsEqualTo(1);
        await server.RestartAsync();
        var afterRestart = await server.OpenAsync(Rf1ProofConsumptions());
        await Assert.That(await NatsOperationJournalMutationProofConsumption.TryConsumeAsync(afterRestart, proof, default)).IsFalse();
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
        using var disabled = JsonDocument.Parse("""{"config":{"allow_batch_publish":false}}""");
        NatsOperationJournalStore.ValidateBatchPublish(disabled.RootElement);

        using var drifted = JsonDocument.Parse("""{"config":{"allow_batch_publish":true}}""");
        await Assert.That(() => NatsOperationJournalStore.ValidateBatchPublish(drifted.RootElement))
            .Throws<InvalidOperationException>();

        using var omitted = JsonDocument.Parse("""{"config":{}}""");
        await Assert.That(() => NatsOperationJournalStore.ValidateBatchPublish(omitted.RootElement))
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

    private static NatsOperationJournalMutationReplySigner CreateReplySigner(byte[] privateKey)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new(key);
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

    private sealed class OneNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private readonly Func<int, NatsOpts>? clientOptions;
        private Process? process;
        private NatsClient? client;

        public int Port => port;

        private OneNodeJetStream(
            string directory,
            string configuration,
            int port,
            Func<int, NatsOpts>? clientOptions)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
            this.clientOptions = clientOptions;
        }

        public static async Task<OneNodeJetStream> StartAsync(
            string? authorization = null,
            Func<int, NatsOpts>? clientOptions = null)
        {
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-create-node-journal-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var configuration = Path.Combine(directory, "nats.conf");
            await File.WriteAllTextAsync(configuration, $"port: {port}\n{authorization}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
            var server = new OneNodeJetStream(directory, configuration, port, clientOptions);
            await server.ConnectAsync();
            return server;
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
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                process.Dispose();
                process = null;
            }
            await ConnectAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (client is not null) await client.DisposeAsync();
            if (process is not null)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                process.Dispose();
            }
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }

        private async Task ConnectAsync()
        {
            process = Process.Start(new ProcessStartInfo("nats-server", $"-c {configuration}")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            }) ?? throw new InvalidOperationException("nats-server did not start.");
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
            throw new InvalidOperationException("nats-server did not accept a local JetStream connection.");
        }
    }
}
