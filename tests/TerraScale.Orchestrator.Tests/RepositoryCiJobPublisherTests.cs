using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobPublisherTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly TestSigner Signer = new([1, 2, 3]);

    [Test]
    public async Task DurablePublishAdvancesTheExactPreparedAttempt()
    {
        var clock = new AdjustableTimeProvider(Now);
        var prepared = await PreparedAsync(clock);
        var transport = new TestTransport(new(GlobalNatsTopology.CiStream, 41, Duplicate: false));
        var receipt = await new RepositoryCiJobDispatcher(
                prepared.Journal,
                new RepositoryCiJobPublisher(transport, Signer, clock))
            .DispatchAsync(prepared.Pipeline, prepared.Receipt.Job!, static () => true);
        var published = transport.Messages.Single();
        var decoded = RepositoryCiJobWireCodec.Decode(
            published.Message.Payload,
            published.Message.Headers);
        var document = decoded.Document;
        var current = (await prepared.Journal.ReadAsync(prepared.Pipeline)).Jobs
            .Single(job => job.Job.Request.Job == prepared.Job.Request.Job);

        await Assert.That(receipt.IsDispatched).IsTrue();
        await Assert.That(receipt.Publication.Disposition).IsEqualTo(RepositoryCiJobPublishDisposition.Published);
        await Assert.That(receipt.Publication.StreamSequence).IsEqualTo(41UL);
        await Assert.That(published.Subject).StartsWith(
            $"{GlobalNatsTopology.CiJobSubjectPrefix}.untrusted-product.");
        await Assert.That(published.MessageId).EndsWith(":1:1");
        await Assert.That(document.PipelineDigest).IsEqualTo(prepared.Pipeline.Digest);
        await Assert.That(document.ImpactDigest).IsEqualTo(prepared.Pipeline.ImpactDigest);
        await Assert.That(document.Job).IsEqualTo(prepared.Job.Request.Job.Value);
        await Assert.That(document.JobDigest).IsEqualTo(prepared.Receipt.Job!.Document.JobDigest);
        await Assert.That(document.Runner).IsEqualTo(prepared.Receipt.Job!.RunnerId);
        await Assert.That(document.FencingToken).IsEqualTo(1);
        await Assert.That(document.ExpiresAtUnixMilliseconds - document.IssuedAtUnixMilliseconds)
            .IsEqualTo(7_200_000L);
        await Assert.That(decoded.Envelope.Signature.Bytes.ToArray()).IsEquivalentTo(new byte[] { 1, 2, 3 });
        await Assert.That(current.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
        await Assert.That(current.EvidenceDigest).IsEqualTo(published.Message.PayloadDigest);
        await Assert.That(current.DispatchStreamSequence).IsEqualTo(41UL);
        await Assert.That(current.LegacyDispatchWithoutAcknowledgement).IsFalse();
    }

    [Test]
    public async Task AuthorityLossAfterPublishRecoversWithTheSameDeduplicatedBytes()
    {
        var clock = new AdjustableTimeProvider(Now);
        var prepared = await PreparedAsync(clock);
        var transport = new TestTransport(new(GlobalNatsTopology.CiStream, 51, Duplicate: false));
        var dispatcher = new RepositoryCiJobDispatcher(
            prepared.Journal,
            new RepositoryCiJobPublisher(transport, Signer, clock));
        var checks = 0;

        var lost = await dispatcher.DispatchAsync(prepared.Pipeline, prepared.Receipt.Job!, () => ++checks < 3);
        transport.Acknowledgement = new(GlobalNatsTopology.CiStream, 51, Duplicate: true);
        var recovered = await dispatcher.DispatchAsync(prepared.Pipeline, prepared.Receipt.Job!, static () => true);

        await Assert.That(lost.Publication.Disposition)
            .IsEqualTo(RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish);
        await Assert.That(lost.Publication.IsDurable).IsTrue();
        await Assert.That(lost.Transition).IsNull();
        await Assert.That(recovered.Publication.Disposition).IsEqualTo(RepositoryCiJobPublishDisposition.Duplicate);
        await Assert.That(recovered.IsDispatched).IsTrue();
        await Assert.That(transport.Messages.Count).IsEqualTo(2);
        await Assert.That(transport.Messages[0].Subject).IsEqualTo(transport.Messages[1].Subject);
        await Assert.That(transport.Messages[0].MessageId).IsEqualTo(transport.Messages[1].MessageId);
        await Assert.That(transport.Messages[0].Message.Payload.Span.SequenceEqual(
            transport.Messages[1].Message.Payload.Span)).IsTrue();
        await Assert.That(transport.Messages[0].Message.Headers)
            .IsEquivalentTo(transport.Messages[1].Message.Headers);
    }

    [Test]
    public async Task ExpiredAuthorityLossAndInvalidAcknowledgementsNeverDispatch()
    {
        var clock = new AdjustableTimeProvider(Now);
        var expiredPrepared = await PreparedAsync(clock);
        var expiredTransport = new TestTransport(new(GlobalNatsTopology.CiStream, 61, Duplicate: false));
        clock.Advance(TimeSpan.FromHours(2));
        var expired = await new RepositoryCiJobDispatcher(
                expiredPrepared.Journal,
                new RepositoryCiJobPublisher(expiredTransport, Signer, clock))
            .DispatchAsync(expiredPrepared.Pipeline, expiredPrepared.Receipt.Job!, static () => true);

        var authorityPrepared = await PreparedAsync(new(Now));
        var authorityTransport = new TestTransport(new(GlobalNatsTopology.CiStream, 62, Duplicate: false));
        var authority = await new RepositoryCiJobDispatcher(
                authorityPrepared.Journal,
                new RepositoryCiJobPublisher(authorityTransport, Signer, new AdjustableTimeProvider(Now)))
            .DispatchAsync(authorityPrepared.Pipeline, authorityPrepared.Receipt.Job!, static () => false);

        var invalidPrepared = await PreparedAsync(new(Now));
        await Assert.That(async () => await new RepositoryCiJobPublisher(
                new TestTransport(new("GLOBAL_SPEC", 1, Duplicate: false)),
                Signer,
                new AdjustableTimeProvider(Now))
            .PublishAsync(invalidPrepared.Pipeline, invalidPrepared.Receipt.Job!, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new RepositoryCiJobPublisher(
                new TestTransport(new(GlobalNatsTopology.CiStream, 0, Duplicate: false)),
                Signer,
                new AdjustableTimeProvider(Now))
            .PublishAsync(invalidPrepared.Pipeline, invalidPrepared.Receipt.Job!, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new RepositoryCiJobPublisher(
                new TestTransport(new(GlobalNatsTopology.CiStream, 1, Duplicate: false)),
                new TestSigner([]),
                new AdjustableTimeProvider(Now))
            .PublishAsync(invalidPrepared.Pipeline, invalidPrepared.Receipt.Job!, static () => true))
            .Throws<InvalidDataException>();

        await Assert.That(expired.Publication.Disposition).IsEqualTo(RepositoryCiJobPublishDisposition.Expired);
        await Assert.That(expired.IsDispatched).IsFalse();
        await Assert.That(expiredTransport.Messages).IsEmpty();
        await Assert.That(authority.Publication.Disposition)
            .IsEqualTo(RepositoryCiJobPublishDisposition.AuthorityLostBeforePublish);
        await Assert.That(authority.IsDispatched).IsFalse();
        await Assert.That(authorityTransport.Messages).IsEmpty();
    }

    [Test]
    public async Task WireCodecRejectsPayloadHeaderAndDuplicateHeaderTampering()
    {
        var prepared = await PreparedAsync(new(Now));
        var wire = RepositoryCiJobWireCodec.Encode(prepared.Pipeline, prepared.Receipt.Job!, Signer);
        var payload = wire.Payload.ToArray();
        payload[^1] ^= 1;
        var changedHeaders = wire.Headers.ToDictionary(static item => item.Key, static item => item.Value);
        changedHeaders["TS-Payload-Sha256"] = new string('a', 64);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers).Document;
        var forgedPayload = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(wire.Payload.Span).Replace(
            $"\"JobDigest\":\"{decoded.JobDigest}\"",
            $"\"JobDigest\":\"{new string('b', 64)}\"",
            StringComparison.Ordinal));
        var forgedHeaders = wire.Headers.ToDictionary(static item => item.Key, static item => item.Value);
        forgedHeaders["TS-Payload-Sha256"] = Convert.ToHexStringLower(SHA256.HashData(forgedPayload));

        await Assert.That(() => RepositoryCiJobWireCodec.Decode(payload, wire.Headers))
            .Throws<InvalidDataException>();
        await Assert.That(() => RepositoryCiJobWireCodec.Decode(wire.Payload, changedHeaders))
            .Throws<InvalidDataException>();
        await Assert.That(() => RepositoryCiJobWireCodec.Decode(forgedPayload, forgedHeaders))
            .Throws<InvalidDataException>();
        await Assert.That(() => RepositoryCiJobWireCodec.Decode(
                wire.Payload,
                wire.Headers.Concat([wire.Headers.First()])))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task RetryWireBindsAttemptSpecificAndBaseIdempotencyToOneJobDigest()
    {
        var clock = new AdjustableTimeProvider(Now);
        var prepared = await PreparedAsync(clock);
        var dispatched = await prepared.Journal.AdvanceAsync(
            prepared.Receipt.Job!,
            RepositoryCiJobPhase.Dispatched,
            Digest('1'),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            71,
            static () => true);
        var running = await prepared.Journal.AdvanceAsync(
            dispatched.Job!,
            RepositoryCiJobPhase.Running,
            Digest('2'),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            0,
            static () => true);
        await prepared.Journal.AdvanceAsync(
            running.Job!,
            RepositoryCiJobPhase.Failed,
            Digest('3'),
            0,
            RepositoryCiJobFailureKind.RunnerLost,
            0,
            static () => true);
        await prepared.Journal.ScheduleRetryAsync(
            prepared.Pipeline,
            prepared.Job.Request.Job,
            "gru-controller-1",
            5,
            $"retry-{prepared.Job.Request.Job.Value}-attempt-1",
            Digest('4'),
            static () => true);
        clock.Advance(TimeSpan.FromSeconds(5));
        var opened = await prepared.Journal.OpenRetryAsync(
            prepared.Pipeline,
            prepared.Job.Request.Job,
            "gru-controller-1",
            5,
            static () => true);
        var retried = await RepositoryCiJobJournalTests.PrepareAsync(
            prepared.Journal,
            prepared.Pipeline,
            opened.Job!.Job);

        var wire = RepositoryCiJobWireCodec.Encode(prepared.Pipeline, retried.Job!, Signer);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers).Document;

        await Assert.That(decoded.Attempt).IsEqualTo(2);
        await Assert.That(decoded.BaseIdempotency).IsEqualTo(prepared.Job.Request.Idempotency.Value);
        await Assert.That(decoded.Idempotency).IsNotEqualTo(decoded.BaseIdempotency);
        await Assert.That(decoded.JobDigest).IsEqualTo(prepared.Receipt.Job!.Document.JobDigest);
        await Assert.That(decoded.RetryAuthorizationDigest).IsEqualTo(Digest('4'));
        await Assert.That(retried.Job!.FencingToken).IsEqualTo(3);
    }

    private static async Task<PreparedJob> PreparedAsync(AdjustableTimeProvider clock)
    {
        var journal = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger(), clock);
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var job = (await journal.ReadAsync(pipeline)).Ready[0];
        var receipt = await RepositoryCiJobJournalTests.PrepareAsync(journal, pipeline, job);
        return new(journal, pipeline, job, receipt);
    }

    private static string Digest(char value) => new(value, 64);

    private sealed class AdjustableTimeProvider(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset value = initial;

        public override DateTimeOffset GetUtcNow() => value;

        internal void Advance(TimeSpan duration) => value = value.Add(duration);
    }

    private sealed class TestTransport(RepositoryCiJobTransportAck acknowledgement)
        : IRepositoryCiJobTransport
    {
        internal RepositoryCiJobTransportAck Acknowledgement { get; set; } = acknowledgement;
        internal List<PublishedMessage> Messages { get; } = [];

        public Task<RepositoryCiJobTransportAck> PublishAsync(
            string subject,
            string messageId,
            RepositoryCiJobWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(new(subject, messageId, message));
            return Task.FromResult(Acknowledgement);
        }
    }

    private sealed class TestSigner(byte[] signature) : IRepositoryCiJobSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed record PreparedJob(
        RepositoryCiJobJournal Journal,
        RepositoryCiPipelinePlan Pipeline,
        RepositoryCiPipelineJob Job,
        RepositoryCiJobJournalReceipt Receipt);

    private sealed record PublishedMessage(
        string Subject,
        string MessageId,
        RepositoryCiJobWireMessage Message);
}
