using System.Collections.Concurrent;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobInboxTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ValidCommandIsAcknowledgedOnlyAfterPayloadAndPointerAreDurable()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [1, 2, 3]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var journal = new RepositoryCiJobAcceptanceJournal(ledger, payloads);
        var executions = new RepositoryCiJobExecutionJournal(ledger);
        var acknowledgements = 0;

        var receipt = await new RepositoryCiJobInbox(journal, executions).ProcessAsync(
            wire.Payload,
            wire.Headers,
            41,
            decoded.Document.Runner,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1, 2, 3]),
            _ =>
            {
                acknowledgements++;
                return Task.CompletedTask;
            });
        var recovered = await new RepositoryCiJobAcceptanceJournal(ledger, payloads).ReadAsync(
            decoded.Document.Runner,
            decoded.Document.PipelineDigest,
            decoded.Document.Job);
        var execution = await executions.ReadAsync(
            decoded.Document.Runner,
            decoded.Document.PipelineDigest,
            decoded.Document.Job);

        await Assert.That(receipt.IsAcknowledged).IsTrue();
        await Assert.That(receipt.AcceptanceDisposition)
            .IsEqualTo(RepositoryCiJobAcceptanceDisposition.Recorded);
        await Assert.That(receipt.ExecutionDisposition)
            .IsEqualTo(RepositoryCiJobExecutionDisposition.Prepared);
        await Assert.That(acknowledgements).IsEqualTo(1);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Command.JobDigest).IsEqualTo(decoded.Document.JobDigest);
        await Assert.That(recovered.Command.AllowedZones).IsEquivalentTo(decoded.Document.AllowedZones);
        await Assert.That(recovered.Command.RequiredCapabilities)
            .IsEquivalentTo(decoded.Document.RequiredCapabilities);
        await Assert.That(recovered.Command.Dependencies).IsEquivalentTo(decoded.Document.Dependencies);
        await Assert.That(recovered.StreamSequence).IsEqualTo(41UL);
        await Assert.That(execution!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Ready);
        await Assert.That(execution.Document.AcceptanceRevision).IsEqualTo(recovered.JournalRevision);
        await Assert.That(recovered.Payload.Span.SequenceEqual(wire.Payload.Span)).IsTrue();
        await Assert.That(recovered.Signature.Span.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        await Assert.That(payloads.Values.Count).IsEqualTo(2);
    }

    [Test]
    public async Task MalformedWrongRunnerInvalidSignatureAndExpiredCommandsAreNeverAcknowledged()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [4]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var acknowledgements = 0;

        var malformed = await Inbox().ProcessAsync(
            wire.Payload,
            wire.Headers.Concat([wire.Headers.First()]),
            1,
            decoded.Document.Runner,
            Now,
            TimeSpan.Zero,
            new TestVerifier([4]),
            Acknowledge);
        var wrongRunner = await Inbox().ProcessAsync(
            wire.Payload,
            wire.Headers,
            2,
            "another-runner",
            Now,
            TimeSpan.Zero,
            new TestVerifier([4]),
            Acknowledge);
        var invalidSignature = await Inbox().ProcessAsync(
            wire.Payload,
            wire.Headers,
            3,
            decoded.Document.Runner,
            Now,
            TimeSpan.Zero,
            new TestVerifier([5]),
            Acknowledge);
        var expired = await Inbox().ProcessAsync(
            wire.Payload,
            wire.Headers,
            4,
            decoded.Document.Runner,
            Now.AddHours(3),
            TimeSpan.Zero,
            new TestVerifier([4]),
            Acknowledge);

        await Assert.That(malformed.Disposition).IsEqualTo(RepositoryCiJobDeliveryDisposition.Malformed);
        await Assert.That(wrongRunner.AcceptanceDisposition)
            .IsEqualTo(RepositoryCiJobAcceptanceDisposition.RunnerMismatch);
        await Assert.That(invalidSignature.ProtocolError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(expired.ProtocolError).IsEqualTo(CommandValidationError.Expired);
        await Assert.That(acknowledgements).IsEqualTo(0);

        Task Acknowledge(CancellationToken _)
        {
            acknowledgements++;
            return Task.CompletedTask;
        }
    }

    [Test]
    public async Task AcknowledgementFailurePreservesAcceptanceForExactRedelivery()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [6]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var journal = new RepositoryCiJobAcceptanceJournal(ledger, payloads);
        var inbox = new RepositoryCiJobInbox(journal, new(ledger));

        await Assert.That(async () => await inbox.ProcessAsync(
                wire.Payload,
                wire.Headers,
                51,
                decoded.Document.Runner,
                Now,
                TimeSpan.Zero,
                new TestVerifier([6]),
                _ => throw new IOException("simulated acknowledgement failure")))
            .Throws<IOException>();
        var durable = await journal.ReadAsync(
            decoded.Document.Runner,
            decoded.Document.PipelineDigest,
            decoded.Document.Job);
        var execution = await new RepositoryCiJobExecutionJournal(ledger).ReadAsync(
            decoded.Document.Runner,
            decoded.Document.PipelineDigest,
            decoded.Document.Job);
        var recovered = await inbox.ProcessAsync(
            wire.Payload,
            wire.Headers,
            51,
            decoded.Document.Runner,
            Now,
            TimeSpan.Zero,
            new TestVerifier([6]),
            _ => Task.CompletedTask);

        await Assert.That(durable).IsNotNull();
        await Assert.That(execution!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Ready);
        await Assert.That(recovered.AcceptanceDisposition)
            .IsEqualTo(RepositoryCiJobAcceptanceDisposition.Duplicate);
        await Assert.That(recovered.IsAcknowledged).IsTrue();
    }

    [Test]
    public async Task ExecutionPreparationFailureNeverAcknowledgesAndExactRedeliveryRepairsIt()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [34]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 2);
        var inbox = new RepositoryCiJobInbox(
            new(ledger, new TestPayloadStore()),
            new(ledger));
        var acknowledgements = 0;

        await Assert.That(async () => await inbox.ProcessAsync(
                wire.Payload,
                wire.Headers,
                52,
                decoded.Document.Runner,
                Now,
                TimeSpan.Zero,
                new TestVerifier([34]),
                _ =>
                {
                    acknowledgements++;
                    return Task.CompletedTask;
                }))
            .Throws<IOException>();
        var repaired = await inbox.ProcessAsync(
            wire.Payload,
            wire.Headers,
            52,
            decoded.Document.Runner,
            Now,
            TimeSpan.Zero,
            new TestVerifier([34]),
            _ =>
            {
                acknowledgements++;
                return Task.CompletedTask;
            });

        await Assert.That(acknowledgements).IsEqualTo(1);
        await Assert.That(repaired.IsAcknowledged).IsTrue();
        await Assert.That(repaired.AcceptanceDisposition)
            .IsEqualTo(RepositoryCiJobAcceptanceDisposition.Duplicate);
        await Assert.That(repaired.ExecutionDisposition)
            .IsEqualTo(RepositoryCiJobExecutionDisposition.Prepared);
    }

    [Test]
    public async Task HigherAuthorityFenceReplacesTheCommandAndRejectsTheOldLeader()
    {
        var prepared = await PreparedAsync();
        var original = Wire(prepared, [7]);
        var first = RepositoryCiJobWireCodec.Decode(original.Payload, original.Headers);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var journal = new RepositoryCiJobAcceptanceJournal(ledger, payloads);
        await journal.AcceptAsync(
            first,
            first.Document.Runner,
            61,
            Now,
            TimeSpan.Zero,
            new TestVerifier([7]));

        var takeover = await prepared.Journal.AcquireAsync(
            prepared.Pipeline,
            prepared.Snapshot.Job.Request.Job,
            "gru-controller-2",
            6,
            static () => true);
        var replacementWire = RepositoryCiJobWireCodec.Encode(
            prepared.Pipeline,
            takeover.Job!,
            new TestSigner([8]));
        var replacement = RepositoryCiJobWireCodec.Decode(replacementWire.Payload, replacementWire.Headers);
        var accepted = await journal.AcceptAsync(
            replacement,
            replacement.Document.Runner,
            62,
            Now,
            TimeSpan.Zero,
            new TestVerifier([8]));
        var stale = await journal.AcceptAsync(
            first,
            first.Document.Runner,
            61,
            Now,
            TimeSpan.Zero,
            new TestVerifier([7]));

        await Assert.That(accepted.Disposition).IsEqualTo(RepositoryCiJobAcceptanceDisposition.Recorded);
        await Assert.That(accepted.Acceptance!.Command.AuthorityEpoch).IsEqualTo(6);
        await Assert.That(accepted.Acceptance.Command.FencingToken).IsEqualTo(2);
        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiJobAcceptanceDisposition.StaleAuthority);
        await Assert.That(stale.CanAcknowledge).IsFalse();
    }

    [Test]
    public async Task CorruptAcceptedPayloadFailsClosedOnRecovery()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [9]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var journal = new RepositoryCiJobAcceptanceJournal(ledger, payloads);
        var accepted = await journal.AcceptAsync(
            decoded,
            decoded.Document.Runner,
            71,
            Now,
            TimeSpan.Zero,
            new TestVerifier([9]));
        payloads.Corrupt(accepted.Acceptance!.PayloadDigest);

        await Assert.That(async () => await journal.ReadAsync(
                decoded.Document.Runner,
                decoded.Document.PipelineDigest,
                decoded.Document.Job))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task RetriesMustBeContiguousAndCarryHigherFences()
    {
        var prepared = await PreparedAsync();
        var first = Wire(prepared, [10]);
        var secondPrepared = await RetryAsync(prepared, 81, 'a', 'b', 'c', 'd');
        var second = Wire(secondPrepared, [10]);
        var thirdPrepared = await RetryAsync(secondPrepared, 82, 'e', 'f', '1', '2');
        var third = Wire(thirdPrepared, [10]);
        var decodedFirst = RepositoryCiJobWireCodec.Decode(first.Payload, first.Headers);
        var decodedSecond = RepositoryCiJobWireCodec.Decode(second.Payload, second.Headers);
        var decodedThird = RepositoryCiJobWireCodec.Decode(third.Payload, third.Headers);
        var journal = new RepositoryCiJobAcceptanceJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestPayloadStore());

        var acceptedFirst = await journal.AcceptAsync(
            decodedFirst, decodedFirst.Document.Runner, 81, prepared.Clock.GetUtcNow(),
            TimeSpan.Zero, new TestVerifier([10]));
        var gap = await journal.AcceptAsync(
            decodedThird, decodedThird.Document.Runner, 83, prepared.Clock.GetUtcNow(),
            TimeSpan.Zero, new TestVerifier([10]));
        var acceptedSecond = await journal.AcceptAsync(
            decodedSecond, decodedSecond.Document.Runner, 82, prepared.Clock.GetUtcNow(),
            TimeSpan.Zero, new TestVerifier([10]));
        var acceptedThird = await journal.AcceptAsync(
            decodedThird, decodedThird.Document.Runner, 83, prepared.Clock.GetUtcNow(),
            TimeSpan.Zero, new TestVerifier([10]));

        await Assert.That(acceptedFirst.CanAcknowledge).IsTrue();
        await Assert.That(gap.Disposition).IsEqualTo(RepositoryCiJobAcceptanceDisposition.AttemptGap);
        await Assert.That(acceptedSecond.Acceptance!.Command.Attempt).IsEqualTo(2);
        await Assert.That(acceptedThird.Acceptance!.Command.Attempt).IsEqualTo(3);
        await Assert.That(acceptedFirst.Acceptance!.Command.FencingToken)
            .IsLessThan(acceptedSecond.Acceptance.Command.FencingToken);
        await Assert.That(acceptedSecond.Acceptance.Command.FencingToken)
            .IsLessThan(acceptedThird.Acceptance.Command.FencingToken);
    }

    private static RepositoryCiJobInbox Inbox()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        return new(new(ledger, new TestPayloadStore()), new(ledger));
    }

    internal static async Task<RepositoryCiAcceptedJob> AcceptedAsync()
    {
        var prepared = await PreparedAsync();
        var wire = Wire(prepared, [31]);
        var decoded = RepositoryCiJobWireCodec.Decode(wire.Payload, wire.Headers);
        var receipt = await new RepositoryCiJobAcceptanceJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestPayloadStore()).AcceptAsync(
                decoded,
                decoded.Document.Runner,
                101,
                Now,
                TimeSpan.Zero,
                new TestVerifier([31]));
        return receipt.Acceptance!;
    }

    internal static async Task<(RepositoryCiAcceptedJob Original, RepositoryCiAcceptedJob Takeover)>
        AcceptedTakeoverAsync()
    {
        var prepared = await PreparedAsync();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiJobAcceptanceJournal(ledger, new TestPayloadStore());
        var originalWire = Wire(prepared, [32]);
        var original = RepositoryCiJobWireCodec.Decode(originalWire.Payload, originalWire.Headers);
        var first = await journal.AcceptAsync(
            original,
            original.Document.Runner,
            102,
            Now,
            TimeSpan.Zero,
            new TestVerifier([32]));
        var takeover = await prepared.Journal.AcquireAsync(
            prepared.Pipeline,
            prepared.Snapshot.Job.Request.Job,
            "gru-controller-2",
            6,
            static () => true);
        var replacementWire = RepositoryCiJobWireCodec.Encode(
            prepared.Pipeline,
            takeover.Job!,
            new TestSigner([33]));
        var replacement = RepositoryCiJobWireCodec.Decode(replacementWire.Payload, replacementWire.Headers);
        var second = await journal.AcceptAsync(
            replacement,
            replacement.Document.Runner,
            103,
            Now,
            TimeSpan.Zero,
            new TestVerifier([33]));
        return (first.Acceptance!, second.Acceptance!);
    }

    private static RepositoryCiJobWireMessage Wire(PreparedJob prepared, byte[] signature) =>
        RepositoryCiJobWireCodec.Encode(prepared.Pipeline, prepared.Snapshot, new TestSigner(signature));

    private static async Task<PreparedJob> PreparedAsync()
    {
        var clock = new AdjustableTimeProvider(Now);
        var journal = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger(), clock);
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var job = (await journal.ReadAsync(pipeline)).Ready[0];
        var prepared = await RepositoryCiJobJournalTests.PrepareAsync(journal, pipeline, job);
        return new(journal, pipeline, prepared.Job!, clock);
    }

    private static async Task<PreparedJob> RetryAsync(
        PreparedJob prepared,
        ulong streamSequence,
        char dispatchEvidence,
        char runningEvidence,
        char failureEvidence,
        char authorizationEvidence)
    {
        var dispatched = await prepared.Journal.AdvanceAsync(
            prepared.Snapshot,
            RepositoryCiJobPhase.Dispatched,
            Digest(dispatchEvidence),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            streamSequence,
            static () => true);
        var running = await prepared.Journal.AdvanceAsync(
            dispatched.Job!,
            RepositoryCiJobPhase.Running,
            Digest(runningEvidence),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            0,
            static () => true);
        await prepared.Journal.AdvanceAsync(
            running.Job!,
            RepositoryCiJobPhase.Failed,
            Digest(failureEvidence),
            0,
            RepositoryCiJobFailureKind.InfrastructureTransient,
            0,
            static () => true);
        await prepared.Journal.ScheduleRetryAsync(
            prepared.Pipeline,
            prepared.Snapshot.Job.Request.Job,
            "gru-controller-1",
            5,
            $"retry-{prepared.Snapshot.Job.Request.Job.Value}-attempt-{prepared.Snapshot.Attempt}",
            Digest(authorizationEvidence),
            static () => true);
        prepared.Clock.Advance(prepared.Snapshot.Attempt == 1
            ? TimeSpan.FromSeconds(5)
            : TimeSpan.FromSeconds(30));
        var opened = await prepared.Journal.OpenRetryAsync(
            prepared.Pipeline,
            prepared.Snapshot.Job.Request.Job,
            "gru-controller-1",
            5,
            static () => true);
        var retried = await RepositoryCiJobJournalTests.PrepareAsync(
            prepared.Journal,
            prepared.Pipeline,
            opened.Job!.Job);
        return prepared with { Snapshot = retried.Job! };
    }

    private static string Digest(char value) => new(value, 64);

    private sealed class TestSigner(byte[] signature) : IRepositoryCiJobSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            signature.Bytes.SequenceEqual(expected) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }

    private sealed class TestPayloadStore : IDeliveryObjectStore
    {
        private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal IReadOnlyCollection<byte[]> Values => (IReadOnlyCollection<byte[]>)values.Values;

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var content)) throw new IOException("Missing CI test payload.");
            return Task.FromResult(content.ToArray());
        }

        internal void Corrupt(string digest) => values[$"ci-job-command-{digest}"] = "corrupt"u8.ToArray();
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset value = initial;

        public override DateTimeOffset GetUtcNow() => value;

        internal void Advance(TimeSpan duration) => value = value.Add(duration);
    }

    private sealed record PreparedJob(
        RepositoryCiJobJournal Journal,
        RepositoryCiPipelinePlan Pipeline,
        RepositoryCiJobSnapshot Snapshot,
        AdjustableTimeProvider Clock);
}
