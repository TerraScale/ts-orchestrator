using System.Security.Cryptography;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsOperationJournalAuthorityDigestTests
{
    [Test]
    public async Task JsonRoundTripPreservesTheExactAuthorityDigest()
    {
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new NatsOperationJournalMutationAuthoritySigner("controller-a", authorityKey);
        var original = new NatsOperationJournalCreateRequest(
            "operation." + new string('a', 64),
            "candidate-bound-value",
            signer.Issue(
                "gru",
                "create",
                "operation." + new string('a', 64),
                0,
                "candidate-bound-value"));

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(original);
        var roundTripped = JsonSerializer.Deserialize<NatsOperationJournalCreateRequest>(json)
            ?? throw new InvalidOperationException("The authority request did not deserialize.");

        await Assert.That(NatsOperationJournalMutationRequestDigest.Create(roundTripped.Authority))
            .IsEqualTo(NatsOperationJournalMutationRequestDigest.Create(original.Authority));
        await Assert.That(roundTripped.Authority.Payload()).IsEqualTo(original.Authority.Payload());
        await Assert.That(roundTripped.Authority.Signature).IsEqualTo(original.Authority.Signature);
    }

    [Test]
    [NotInParallel("NatsR3")]
    public async Task OneWriterReplyBindsTheExactTransportedAuthority()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        NatsTopology topology = fixture.Topology;
        await using NatsClient writer = await fixture.ConnectAsync(fixture.JournalWriter);
        await using NatsClient controller = await fixture.ConnectAsync(fixture.Controller);
        INatsKVContext stores = writer.CreateJetStreamContext().CreateKeyValueStoreContext();
        INatsKVStore journal = await stores.GetStoreAsync(topology.Operations.Bucket);
        INatsKVStore proofConsumptions = await stores.GetStoreAsync(topology.OperationProofConsumptions.Bucket);
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] replyPublicKey = replyKey.ExportSubjectPublicKeyInfo();
        var authority = new NatsOperationJournalMutationAuthoritySigner(
            fixture.Controller.PublicKey,
            authorityKey);
        await using var service = await NatsOperationJournalMutationService.StartAsync(
            writer,
            journal,
            proofConsumptions,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
            new HashSet<string>(StringComparer.Ordinal) { fixture.Controller.PublicKey },
            new NatsOperationJournalMutationReplySigner(replyKey),
            default);
        var client = new NatsOperationJournalMutationClient(
            controller,
            topology,
            authority,
            new NatsOperationJournalMutationReplyVerifier(replyPublicKey));

        NatsOperationJournalMutationReply reply = await client.CreateAsync(
            "operation." + new string('b', 64),
            "single-writer-value");

        await Assert.That(reply.Succeeded).IsTrue();
        await Assert.That(reply.Revision).IsGreaterThan(0UL);
    }

    [Test]
    [NotInParallel("NatsR3")]
    public async Task ConcurrentWritersReturnOnlyTheirCallersExactAuthorityDigest()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        NatsTopology topology = fixture.Topology;
        await using NatsClient writerOne = await fixture.ConnectAsync(fixture.JournalWriter);
        await using NatsClient writerTwo = await fixture.ConnectAsync(fixture.JournalWriter, member: 1);
        await using NatsClient controllerOne = await fixture.ConnectAsync(fixture.Controller);
        await using NatsClient controllerTwo = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1);
        INatsKVContext storesOne = writerOne.CreateJetStreamContext().CreateKeyValueStoreContext();
        INatsKVContext storesTwo = writerTwo.CreateJetStreamContext().CreateKeyValueStoreContext();
        INatsKVStore journalOne = await storesOne.GetStoreAsync(topology.Operations.Bucket);
        INatsKVStore journalTwo = await storesTwo.GetStoreAsync(topology.Operations.Bucket);
        INatsKVStore proofsOne = await storesOne.GetStoreAsync(topology.OperationProofConsumptions.Bucket);
        INatsKVStore proofsTwo = await storesTwo.GetStoreAsync(topology.OperationProofConsumptions.Bucket);
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] replyPrivateKey = replyKey.ExportPkcs8PrivateKey();
        byte[] authorityPublicKey = authorityKey.ExportSubjectPublicKeyInfo();
        var identities = new HashSet<string>(StringComparer.Ordinal)
        {
            fixture.Controller.PublicKey,
            fixture.ControllerTwo.PublicKey
        };
        await using var serviceOne = await NatsOperationJournalMutationService.StartAsync(
            writerOne,
            journalOne,
            proofsOne,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            identities,
            ImportReplySigner(replyPrivateKey),
            default);
        await using var serviceTwo = await NatsOperationJournalMutationService.StartAsync(
            writerTwo,
            journalTwo,
            proofsTwo,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            identities,
            ImportReplySigner(replyPrivateKey),
            default);
        var signerOne = new NatsOperationJournalMutationAuthoritySigner(fixture.Controller.PublicKey, authorityKey);
        var signerTwo = new NatsOperationJournalMutationAuthoritySigner(fixture.ControllerTwo.PublicKey, authorityKey);
        var requestOne = CreateRequest(signerOne, 'c', "controller-one");
        var requestTwo = CreateRequest(signerTwo, 'd', "controller-two");
        string digestOne = NatsOperationJournalMutationRequestDigest.Create(requestOne.Authority);
        string digestTwo = NatsOperationJournalMutationRequestDigest.Create(requestTwo.Authority);

        NatsOperationJournalMutationReply[] replies = await Task.WhenAll(
            RequestAsync(controllerOne, topology, requestOne),
            RequestAsync(controllerTwo, topology, requestTwo));

        await Assert.That(replies[0].RequestDigest).IsEqualTo(digestOne);
        await Assert.That(replies[0].RequestDigest).IsNotEqualTo(digestTwo);
        await Assert.That(replies[1].RequestDigest).IsEqualTo(digestTwo);
        await Assert.That(replies[1].RequestDigest).IsNotEqualTo(digestOne);
    }

    private static NatsOperationJournalCreateRequest CreateRequest(
        NatsOperationJournalMutationAuthoritySigner signer,
        char keyCharacter,
        string value)
    {
        string key = "operation." + new string(keyCharacter, 64);
        return new NatsOperationJournalCreateRequest(
            key,
            value,
            signer.Issue("gru", "create", key, 0, value));
    }

    private static async Task<NatsOperationJournalMutationReply> RequestAsync(
        NatsClient client,
        NatsTopology topology,
        NatsOperationJournalCreateRequest request)
    {
        string replySubject = topology.OperationJournalReplySubject(
            request.Authority.CallerIdentity,
            Guid.NewGuid().ToString("N"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsOperationJournalMutationReply>(
            replySubject,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(15) },
            cancellationToken: timeout.Token);
        await client.PingAsync(timeout.Token);
        await client.PublishAsync(
            topology.OperationJournalCreateSubject,
            request,
            replyTo: replySubject,
            cancellationToken: timeout.Token);
        return (await subscription.Msgs.ReadAsync(timeout.Token)).Data
            ?? throw new InvalidOperationException("The private journal mutation service returned no reply.");
    }

    private static NatsOperationJournalMutationReplySigner ImportReplySigner(byte[] privateKey)
    {
        ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new NatsOperationJournalMutationReplySigner(key);
    }
}

