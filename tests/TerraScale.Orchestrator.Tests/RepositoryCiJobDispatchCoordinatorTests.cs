using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobDispatchCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReadyJobSelectsAnAdmittedRunnerAndDispatchesExactSource()
    {
        var fixture = await Fixture.CreateAsync();

        var receipt = await fixture.DispatchAsync();
        var current = await fixture.CurrentAsync();
        var message = fixture.Transport.Messages.Single();
        var command = RepositoryCiJobWireCodec.Decode(message.Message.Payload, message.Message.Headers).Document;

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.Dispatched);
        await Assert.That(current.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
        await Assert.That(current.RunnerId).IsEqualTo(fixture.Runner.Runner.Value);
        await Assert.That(current.OperationId).IsEqualTo(fixture.Job.Request.Idempotency.Value);
        await Assert.That(current.DispatchStreamSequence).IsEqualTo(41UL);
        await Assert.That(command.SourceBundleSha256).IsEqualTo(current.SourceBundleSha256);
        await Assert.That(command.Operation).IsEqualTo(fixture.Job.Request.Idempotency.Value);
        await Assert.That(fixture.ArchiveReads).IsEqualTo(1);
        await Assert.That(fixture.IsolationReads).IsEqualTo(1);
        await Assert.That(fixture.Objects.PutCount).IsEqualTo(1);
    }

    [Test]
    public async Task MissingRunnerCapacityHoldsBeforeReadingIsolationOrSource()
    {
        var fixture = await Fixture.CreateAsync();

        var receipt = await fixture.DispatchAsync([]);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.SelectionHeld);
        await Assert.That(receipt.HoldReason).IsEqualTo(DeliveryErrorCode.RunnerStale);
        await Assert.That(fixture.ArchiveReads).IsEqualTo(0);
        await Assert.That(fixture.IsolationReads).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages).IsEmpty();
    }

    [Test]
    public async Task IsolationFailureHoldsBeforePublishingTheSourceBundle()
    {
        var fixture = await Fixture.CreateAsync(
            isolation: static (job, _) => RepositoryCiJobJournalTests.Isolation(job) with { CgroupV2 = false });

        var receipt = await fixture.DispatchAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.IsolationDenied);
        await Assert.That(receipt.IsolationReason).IsEqualTo(CiRunnerAdmissionReason.IsolationMissing);
        await Assert.That(fixture.ArchiveReads).IsEqualTo(0);
        await Assert.That(fixture.Objects.PutCount).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages).IsEmpty();
    }

    [Test]
    public async Task AuthorityLossAfterPublishResumesPreparedBytesWithoutRefetchingSource()
    {
        var fixture = await Fixture.CreateAsync();
        var authority = true;
        fixture.Transport.AfterPublish = () => authority = false;

        var interrupted = await fixture.DispatchAsync(authorityStillValid: () => authority);
        var prepared = await fixture.CurrentAsync();
        authority = true;
        fixture.Transport.AfterPublish = null;
        var recovered = await fixture.DispatchAsync(authorityStillValid: () => authority);
        var current = await fixture.CurrentAsync();

        await Assert.That(interrupted.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost);
        await Assert.That(interrupted.Dispatch!.Publication.Disposition)
            .IsEqualTo(RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish);
        await Assert.That(prepared.Phase).IsEqualTo(RepositoryCiJobPhase.DispatchPrepared);
        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.Dispatched);
        await Assert.That(current.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(2);
        await Assert.That(fixture.Transport.Messages[0].Message.Payload.Span.SequenceEqual(
            fixture.Transport.Messages[1].Message.Payload.Span)).IsTrue();
        await Assert.That(fixture.Transport.Messages[0].Message.Headers)
            .IsEquivalentTo(fixture.Transport.Messages[1].Message.Headers);
        await Assert.That(fixture.ArchiveReads).IsEqualTo(1);
        await Assert.That(fixture.IsolationReads).IsEqualTo(1);
        await Assert.That(fixture.Objects.PutCount).IsEqualTo(1);
    }

    [Test]
    public async Task SourceResolverCannotSubstituteAnotherImmutableRevision()
    {
        var fixture = await Fixture.CreateAsync(archive: static source => Archive(new(
            source.Repository,
            source.Commit,
            new string('f', source.Tree.Length),
            source.SignatureVerified)));

        var receipt = await fixture.DispatchAsync();
        var current = await fixture.CurrentAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobDispatchCoordinationDisposition.IdentityConflict);
        await Assert.That(current.Phase).IsEqualTo(RepositoryCiJobPhase.Pending);
        await Assert.That(fixture.Objects.PutCount).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages).IsEmpty();
    }

    private static ForgejoSourceArchive Archive(ForgejoResolvedRevision source)
    {
        var content = new byte[] { 0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4 };
        return new(source, Convert.ToHexStringLower(SHA256.HashData(content)), content);
    }

    private sealed class Fixture
    {
        private readonly RepositoryCiJobJournal jobs;
        private readonly RepositoryCiJobDispatchCoordinator coordinator;

        private Fixture(
            RepositoryCiPipelinePlan pipeline,
            RepositoryCiPipelineJob job,
            RunnerEvidence runner,
            RepositoryCiJobJournal jobs,
            RepositoryCiJobDispatchCoordinator coordinator,
            TestObjectStore objects,
            TestTransport transport)
        {
            Pipeline = pipeline;
            Job = job;
            Runner = runner;
            this.jobs = jobs;
            this.coordinator = coordinator;
            Objects = objects;
            Transport = transport;
        }

        internal RepositoryCiPipelinePlan Pipeline { get; }
        internal RepositoryCiPipelineJob Job { get; }
        internal RunnerEvidence Runner { get; }
        internal TestObjectStore Objects { get; }
        internal TestTransport Transport { get; }
        internal int ArchiveReads { get; private set; }
        internal int IsolationReads { get; private set; }

        internal static async Task<Fixture> CreateAsync(
            Func<RepositoryCiPipelineJob, RunnerEvidence, CiRunnerIsolationEvidence>? isolation = null,
            Func<ForgejoResolvedRevision, ForgejoSourceArchive>? archive = null)
        {
            var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
            var clock = new FixedTimeProvider();
            var jobs = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger(), clock);
            await jobs.InitializeAsync(pipeline, 5, 9, static () => true);
            var job = (await jobs.ReadAsync(pipeline)).Ready[0];
            var runner = RepositoryCiJobJournalTests.Runner(job);
            var objects = new TestObjectStore();
            var transport = new TestTransport();
            isolation ??= static (planned, _) => RepositoryCiJobJournalTests.Isolation(planned);
            archive ??= Archive;
            Fixture? fixture = null;
            var coordinator = new RepositoryCiJobDispatchCoordinator(
                jobs,
                new(objects),
                new(jobs, new(transport, new TestSigner(), clock)),
                (source, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fixture!.ArchiveReads++;
                    return Task.FromResult(archive(source));
                },
                (planned, selected, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fixture!.IsolationReads++;
                    return Task.FromResult(isolation(planned, selected));
                });
            fixture = new(pipeline, job, runner, jobs, coordinator, objects, transport);
            return fixture;
        }

        internal Task<RepositoryCiJobDispatchCoordinationReceipt> DispatchAsync(
            IReadOnlyList<RunnerEvidence>? runners = null,
            Func<bool>? authorityStillValid = null) => coordinator.DispatchAsync(
                Pipeline,
                Job.Request.Job,
                runners ?? [Runner],
                "gru-controller-1",
                5,
                authorityStillValid ?? (() => true));

        internal async Task<RepositoryCiJobSnapshot> CurrentAsync() =>
            (await jobs.ReadAsync(Pipeline)).Jobs.Single(value => value.Job.Request.Job == Job.Request.Job);
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        internal int PutCount { get; private set; }

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PutCount++;
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values[name].ToArray());
        }
    }

    private sealed class TestTransport : IRepositoryCiJobTransport
    {
        internal List<(string Subject, string MessageId, RepositoryCiJobWireMessage Message)> Messages { get; } = [];
        internal Action? AfterPublish { get; set; }

        public Task<RepositoryCiJobTransportAck> PublishAsync(
            string subject,
            string messageId,
            RepositoryCiJobWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add((subject, messageId, message));
            AfterPublish?.Invoke();
            return Task.FromResult(new RepositoryCiJobTransportAck(
                GlobalNatsTopology.CiStream,
                41,
                Messages.Count > 1));
        }
    }

    private sealed class TestSigner : IRepositoryCiJobSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            _ = material;
            OpaqueSignature.TryCopyFrom([1, 2, 3], out var signature);
            return signature!;
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
