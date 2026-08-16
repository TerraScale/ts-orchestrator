using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

// Each test owns three nats-server processes, three JetStream stores, and an
// ephemeral mTLS/JWT identity tree. Keep this lane serial with every R3 test.
[NotInParallel("NatsR3")]
public sealed class NatsControlR3L0cTests
{
    [Test]
    public async Task FixtureDisposesEveryServerProcessAndPrivateRoot()
    {
        if (!OperatingSystem.IsLinux()) return;

        var fixture = await NatsControlR3L0cFixture.StartAsync();
        var root = fixture.DirectoryPath;
        var processIds = fixture.ProcessIds.ToArray();
        await fixture.DisposeAsync();

        await Assert.That(fixture.ProcessIds).IsEmpty();
        await Assert.That(Directory.Exists(root)).IsFalse();
        foreach (var processId in processIds)
            await Assert.That(IsProcessRunning(processId)).IsFalse();
    }

    [Test]
    public async Task TlsJwtNkeyR3TopologyAndLeastPrivilegeBoundariesAreEnforced()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var topology = fixture.Topology;
        var root = $"ts.orch.v1.{topology.Cell}";

        await using var infrastructure = await fixture.ConnectAsync(fixture.Infrastructure);
        var jetStream = infrastructure.CreateJetStreamContext();
        foreach (var expected in topology.Streams)
        {
            var actual = (await jetStream.GetStreamAsync(expected.Name!)).Info.Config;
            await Assert.That(actual.NumReplicas).IsEqualTo(3);
            await Assert.That(actual.Subjects).IsEquivalentTo(expected.Subjects ?? []);
            await Assert.That(actual.Storage).IsEqualTo(StreamConfigStorage.File);
        }

        var operations = await jetStream.GetStreamAsync("KV_ORCH_OPERATIONS");
        await Assert.That(operations.Info.Config.NumReplicas).IsEqualTo(3);
        await Assert.That(operations.Info.Config.DenyDelete).IsTrue();
        await Assert.That(operations.Info.Config.DenyPurge).IsTrue();
        await Assert.That(operations.Info.Config.AllowDirect).IsTrue();
        await Assert.That(operations.Info.Config.Subjects)
            .IsEquivalentTo(["$KV.ORCH_OPERATIONS.>"]);

        var proofs = await jetStream.GetStreamAsync("KV_ORCH_OPERATION_PROOFS");
        await Assert.That(proofs.Info.Config.NumReplicas).IsEqualTo(3);
        await Assert.That(proofs.Info.Config.MaxAge).IsEqualTo(TimeSpan.FromMinutes(5));
        await Assert.That(proofs.Info.Config.DenyDelete).IsTrue();
        await Assert.That(proofs.Info.Config.DenyPurge).IsTrue();

        foreach (var identity in new[]
                     {
                         fixture.Controller,
                         fixture.ControllerTwo,
                         fixture.Infrastructure,
                         fixture.JournalWriter,
                         fixture.Operator,
                         fixture.WrongAccount,
                     })
        {
            using var certificate = X509Certificate2.CreateFromPemFile(
                identity.CertificateFile,
                identity.KeyFile);
            await Assert.That(certificate.HasPrivateKey).IsTrue();
            await Assert.That(certificate.Extensions["2.5.29.17"]!.Format(false))
                .Contains(identity.SpiffeId);
            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
            await Assert.That(eku.EnhancedKeyUsages.Cast<Oid>().Select(static oid => oid.Value!))
                .Contains("1.3.6.1.5.5.7.3.2");
            await Assert.That(File.GetUnixFileMode(identity.KeyFile))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await using var controller = await fixture.ConnectAsync(fixture.Controller);
        await using var writer = await fixture.ConnectAsync(fixture.JournalWriter);
        await using var operatorRead = await fixture.ConnectAsync(fixture.Operator);
        await using var wrongAccount = await fixture.ConnectAsync(fixture.WrongAccount);

        await Assert.That(async () =>
        {
            await using var anonymous = await fixture.ConnectAsync(
                fixture.Operator,
                authenticate: false);
        }).Throws<NatsException>();

        await Assert.That(async () => _ = await controller.RequestAsync<string, string>(
                $"{root}.forbidden.mutation", "{}"))
            .Throws<NatsException>();
        foreach (var subject in new[]
                 {
                     "$KV.ORCH_OPERATIONS.operation.denied",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.CREATE.unauthorized",
                     "$JS.API.STREAM.UPDATE.CELL_EVENTS",
                 })
        {
            await Assert.That(async () => _ = await controller.RequestAsync<string, string>(subject, "{}"))
                .Throws<NatsException>();
        }

        await Assert.That(async () => _ = await infrastructure.RequestAsync<string, string>(
                "$KV.ORCH_OPERATIONS.operation.denied", "{}"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await operatorRead.RequestAsync<string, string>(
                "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS", "{}"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await wrongAccount.CreateJetStreamContext()
                .GetStreamAsync("KV_ORCH_OPERATIONS"))
            .Throws<NatsJSApiException>();
        await Assert.That(async () => _ = await wrongAccount.RequestAsync<string, string>(
                $"{root}.query.status", "{}"))
            .Throws<NatsException>();

        var writerStore = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync(topology.Operations.Bucket);
        var writerKey = "operation." + new string('e', 64);
        var writerRevision = await writerStore.CreateAsync(writerKey, "writer-authorized");
        var writerEntry = await writerStore.GetEntryAsync<string>(writerKey);
        writerEntry.EnsureSuccess();
        await Assert.That(writerEntry.Revision).IsEqualTo(writerRevision);
        await Assert.That(writerEntry.Value).IsEqualTo("writer-authorized");
    }

    [Test]
    public async Task ProofLedgerAndJournalCasSurviveMemberLossRestartAndStaleWriterFence()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var topology = fixture.Topology;
        await using var writer = await fixture.ConnectAsync(fixture.JournalWriter, member: 0);
        await using var writerTwo = await fixture.ConnectAsync(fixture.JournalWriter, member: 1);
        await using var controller = await fixture.ConnectAsync(fixture.Controller, member: 0);
        await using var controllerTwo = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1);

        var writerStore = await OpenStoreAsync(writer, topology.Operations.Bucket);
        var writerStoreTwo = await OpenStoreAsync(writerTwo, topology.Operations.Bucket);
        var proofStore = await OpenStoreAsync(writer, topology.OperationProofConsumptions.Bucket);
        var proofStoreTwo = await OpenStoreAsync(writerTwo, topology.OperationProofConsumptions.Bucket);
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authorityPublicKey = authorityKey.ExportSubjectPublicKeyInfo();
        var replyPublicKey = replyKey.ExportSubjectPublicKeyInfo();
        var replyPrivateKey = replyKey.ExportPkcs8PrivateKey();
        var controllerSigner = new NatsOperationJournalMutationAuthoritySigner(
            fixture.Controller.PublicKey,
            authorityKey);
        var controllerTwoSigner = new NatsOperationJournalMutationAuthoritySigner(
            fixture.ControllerTwo.PublicKey,
            authorityKey);
        await using var writerService = await NatsOperationJournalMutationService.StartAsync(
            writer,
            writerStore,
            proofStore,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            new HashSet<string>(StringComparer.Ordinal)
            {
                fixture.Controller.PublicKey,
                fixture.ControllerTwo.PublicKey,
            },
            CreateReplySigner(replyPrivateKey),
            default);
        await using var writerServiceTwo = await NatsOperationJournalMutationService.StartAsync(
            writerTwo,
            writerStoreTwo,
            proofStoreTwo,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            new HashSet<string>(StringComparer.Ordinal)
            {
                fixture.Controller.PublicKey,
                fixture.ControllerTwo.PublicKey,
            },
            CreateReplySigner(replyPrivateKey),
            default);
        var mutationClient = new NatsOperationJournalMutationClient(
            controller,
            topology,
            controllerSigner,
            new NatsOperationJournalMutationReplyVerifier(replyPublicKey));
        var mutationClientTwo = new NatsOperationJournalMutationClient(
            controllerTwo,
            topology,
            controllerTwoSigner,
            new NatsOperationJournalMutationReplyVerifier(replyPublicKey));

        var firstKey = "operation." + new string('a', 64);
        var secondKey = "operation." + new string('b', 64);
        var concurrent = await Task.WhenAll(
            mutationClient.CreateAsync(firstKey, "first"),
            mutationClientTwo.CreateAsync(secondKey, "second"));
        await Assert.That(concurrent.All(static reply => reply.Succeeded)).IsTrue();

        var first = concurrent[0];
        var beforeLoss = await writerStore.GetEntryAsync<string>(firstKey);
        beforeLoss.EnsureSuccess();
        await Assert.That(beforeLoss.Revision).IsEqualTo(first.Revision);

        var proof = controllerSigner.Issue(
            topology.Cell,
            "create",
            "operation." + new string('c', 64),
            0,
            "single-use-proof");
        var consumed = await Task.WhenAll(
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofStore, proof, default).AsTask(),
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofStoreTwo, proof, default).AsTask());
        await Assert.That(consumed.Count(static value => value)).IsEqualTo(1);

        await fixture.KillMemberAsync(2);
        var afterLoss = writerStore;
        var afterLossRevision = await UpdateWithQuorumRetryAsync(
            afterLoss,
            firstKey,
            "after-member-loss",
            beforeLoss.Revision);
        await Assert.That(afterLossRevision).IsGreaterThan(beforeLoss.Revision);

        await fixture.RestartMemberAsync(2);
        await fixture.WaitForMemberAsync(2);
        await using var restartedWriter = await fixture.ConnectAsync(fixture.JournalWriter, member: 2);
        var restartedStore = await OpenStoreAsync(restartedWriter, topology.Operations.Bucket);
        var reloaded = await restartedStore.GetEntryAsync<string>(firstKey);
        reloaded.EnsureSuccess();
        await Assert.That(reloaded.Value).IsEqualTo("after-member-loss");
        await Assert.That(reloaded.Revision).IsEqualTo(afterLossRevision);

        await Assert.That(async () => await restartedStore.UpdateAsync(
                firstKey,
                "stale-writer",
                beforeLoss.Revision))
            .Throws<NatsKVWrongLastRevisionException>();
        var restartedProofStore = await OpenStoreAsync(
            restartedWriter,
            topology.OperationProofConsumptions.Bucket);
        await Assert.That(await NatsOperationJournalMutationProofConsumption.TryConsumeAsync(
                restartedProofStore,
                proof,
                default))
            .IsFalse();
        var r3 = await fixture.ConnectAsync(fixture.Infrastructure, member: 2);
        await using (r3)
        {
            var stream = await r3.CreateJetStreamContext().GetStreamAsync("KV_ORCH_OPERATIONS");
            await Assert.That(stream.Info.Config.NumReplicas).IsEqualTo(3);
            await Assert.That(stream.Info.Config.DenyDelete).IsTrue();
            await Assert.That(stream.Info.Config.DenyPurge).IsTrue();
        }
    }

    private static async Task<INatsKVStore> OpenStoreAsync(
        NatsClient client,
        string bucket)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                return await client.CreateJetStreamContext()
                    .CreateKeyValueStoreContext()
                    .GetStoreAsync(bucket);
            }
            catch (NatsException) when (attempt < 7)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }
        }
        throw new TimeoutException("The R3 JetStream store did not become readable.");
    }

    private static async Task<ulong> UpdateWithQuorumRetryAsync(
        INatsKVStore store,
        string key,
        string value,
        ulong expectedRevision)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                return await store.UpdateAsync(key, value, expectedRevision);
            }
            catch (NatsException) when (attempt < 7)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }
        }
        throw new TimeoutException("The R3 operation journal did not regain quorum for CAS update.");
    }

    private static NatsOperationJournalMutationReplySigner CreateReplySigner(byte[] privateKey)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new(key);
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
