using System.Globalization;
using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPipelineRunCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task SignedRunnerResultsAdvanceTheWholeDependencyDagWithoutDuplicateBuilds()
    {
        var fixture = Fixture.Create();
        RepositoryCiPipelineRunCoordinationReceipt? receipt = null;

        for (var tick = 0; tick <= fixture.Pipeline.Jobs.Count; tick++)
        {
            receipt = await fixture.CoordinateAsync();
            if (receipt.Disposition == RepositoryCiPipelineRunCoordinationDisposition.Succeeded) break;
            await Assert.That(receipt.Disposition is
                RepositoryCiPipelineRunCoordinationDisposition.Progressed or
                RepositoryCiPipelineRunCoordinationDisposition.Waiting).IsTrue();
        }

        await Assert.That(receipt!.Disposition)
            .IsEqualTo(RepositoryCiPipelineRunCoordinationDisposition.Succeeded);
        await Assert.That(receipt.Run!.Results.Count).IsEqualTo(fixture.Pipeline.Jobs.Count);
        await Assert.That(receipt.Run.Results.All(static value => value.Succeeded)).IsTrue();
        await Assert.That(fixture.Transport.Jobs.Count).IsEqualTo(fixture.Pipeline.Jobs.Count);
        await Assert.That(fixture.Transport.Jobs.Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(fixture.Pipeline.Jobs.Count);
    }

    [Test]
    public async Task MissingRunnerCapacityLeavesTheReadyDagWaitingWithoutPublishing()
    {
        var fixture = Fixture.Create(runners: static _ => []);

        var receipt = await fixture.CoordinateAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineRunCoordinationDisposition.Waiting);
        await Assert.That(receipt.Run!.Ready).IsNotEmpty();
        await Assert.That(receipt.Dispatches.All(static value =>
            value.Disposition == RepositoryCiJobDispatchCoordinationDisposition.SelectionHeld)).IsTrue();
        await Assert.That(fixture.Transport.Jobs).IsEmpty();
    }

    [Test]
    public async Task PermanentRunnerFailureStopsDispatchBeyondTheInitialReadyFrontier()
    {
        var fixture = Fixture.Create(failure: (_, position) => position == 0
            ? RepositoryCiJobFailureKind.WorkloadFailed
            : RepositoryCiJobFailureKind.Unspecified);
        var initialReady = fixture.Pipeline.Jobs.Count(static job => job.DependsOn.Count == 0);

        await fixture.CoordinateAsync();
        var receipt = await fixture.CoordinateAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineRunCoordinationDisposition.Failed);
        await Assert.That(receipt.Run!.State).IsEqualTo(RepositoryCiPipelineRunState.Failed);
        await Assert.That(fixture.Transport.Jobs.Count).IsEqualTo(initialReady);
        await Assert.That(receipt.Run.Results.Any(static value => !value.Succeeded)).IsTrue();
    }

    [Test]
    public async Task AuthorizedTransientFailureRetriesThroughTheSameSignedDag()
    {
        var fixture = Fixture.Create(
            failure: static (command, position) => position == 0 && command.Attempt == 1
                ? RepositoryCiJobFailureKind.RunnerLost
                : RepositoryCiJobFailureKind.Unspecified,
            retry: true);
        RepositoryCiPipelineRunCoordinationReceipt? receipt = null;

        for (var tick = 0; tick <= fixture.Pipeline.Jobs.Count + 4; tick++)
        {
            receipt = await fixture.CoordinateAsync();
            if (receipt.Disposition == RepositoryCiPipelineRunCoordinationDisposition.Succeeded) break;
            if (receipt.Disposition == RepositoryCiPipelineRunCoordinationDisposition.Waiting)
                fixture.Clock.Advance(TimeSpan.FromSeconds(5));
        }

        await Assert.That(receipt!.Disposition)
            .IsEqualTo(RepositoryCiPipelineRunCoordinationDisposition.Succeeded);
        await Assert.That(receipt.Run!.Results.All(static value => value.Succeeded)).IsTrue();
        await Assert.That(receipt.Run.Results.Any(static value => value.Attempt == 2)).IsTrue();
        await Assert.That(fixture.Transport.Jobs.Count).IsEqualTo(fixture.Pipeline.Jobs.Count + 1);
    }

    [Test]
    public async Task LostAuthorityCannotInitializeOrPublishPipelineWork()
    {
        var fixture = Fixture.Create();

        var receipt = await fixture.CoordinateAsync(static () => false);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost);
        await Assert.That(receipt.Run).IsNull();
        await Assert.That(fixture.Transport.Jobs).IsEmpty();
    }

    private sealed class Fixture
    {
        private readonly RepositoryCiPipelineRunCoordinator coordinator;

        private Fixture(
            RepositoryCiPipelinePlan pipeline,
            RepositoryCiPipelineRunCoordinator coordinator,
            AutoRunnerTransport transport,
            AdjustableTimeProvider clock)
        {
            Pipeline = pipeline;
            this.coordinator = coordinator;
            Transport = transport;
            Clock = clock;
        }

        internal RepositoryCiPipelinePlan Pipeline { get; }
        internal AutoRunnerTransport Transport { get; }
        internal AdjustableTimeProvider Clock { get; }

        internal static Fixture Create(
            Func<RepositoryCiPipelineJob, IReadOnlyList<RunnerEvidence>>? runners = null,
            Func<RepositoryCiJobWireDocument, int, RepositoryCiJobFailureKind>? failure = null,
            bool retry = false)
        {
            var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
            var controllerLedger = new ForgejoWebhookJournalTests.TestLedger();
            var runnerLedger = new ForgejoWebhookJournalTests.TestLedger();
            var objects = new TestObjectStore();
            var clock = new AdjustableTimeProvider(Now);
            var jobs = new RepositoryCiJobJournal(controllerLedger, clock);
            var executions = new RepositoryCiJobExecutionJournal(runnerLedger);
            var inbox = new RepositoryCiJobInbox(
                new(runnerLedger, objects),
                executions);
            var transport = new AutoRunnerTransport(inbox, executions, clock, failure);
            var dispatch = new RepositoryCiJobDispatchCoordinator(
                jobs,
                new(objects),
                new(jobs, new(transport, new TestSigner(), clock)),
                static (source, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return Task.FromResult(Archive(source));
                },
                static (job, _, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return Task.FromResult(RepositoryCiJobJournalTests.Isolation(job));
                });
            runners ??= static job => [RepositoryCiJobJournalTests.Runner(job)];
            var retryCoordinator = retry
                ? new RepositoryCiJobRetryCoordinator(
                    jobs,
                    static (job, cancellationToken) =>
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        return Task.FromResult<RepositoryCiJobRetryAuthorization?>(new(
                            $"retry-{job.Job.Request.Job.Value}-attempt-{job.Attempt}",
                            new string('a', 64)));
                    })
                : null;
            return new(
                pipeline,
                new(
                    jobs,
                    dispatch,
                    new(jobs, executions),
                    (job, cancellationToken) =>
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        return Task.FromResult(runners(job));
                    },
                    retryCoordinator),
                transport,
                clock);
        }

        internal Task<RepositoryCiPipelineRunCoordinationReceipt> CoordinateAsync(
            Func<bool>? authorityStillValid = null) => coordinator.CoordinateAsync(
                Pipeline,
                "gru-controller-1",
                5,
                9,
                authorityStillValid ?? (() => true));
    }

    private sealed class AutoRunnerTransport(
        RepositoryCiJobInbox inbox,
        RepositoryCiJobExecutionJournal executions,
        TimeProvider clock,
        Func<RepositoryCiJobWireDocument, int, RepositoryCiJobFailureKind>? failure) : IRepositoryCiJobTransport
    {
        private ulong sequence = 40;
        internal List<string> Jobs { get; } = [];

        public async Task<RepositoryCiJobTransportAck> PublishAsync(
            string subject,
            string messageId,
            RepositoryCiJobWireMessage message,
            CancellationToken cancellationToken)
        {
            _ = subject;
            _ = messageId;
            var next = ++sequence;
            var now = clock.GetUtcNow();
            var command = RepositoryCiJobWireCodec.Decode(message.Payload, message.Headers).Document;
            var prepared = await inbox.PrepareAsync(
                message.Payload,
                message.Headers,
                next,
                command.Runner,
                now,
                TimeSpan.Zero,
                new TestVerifier(),
                cancellationToken);
            if (!prepared.CanAcknowledge)
                throw new InvalidDataException("The in-memory runner rejected a signed CI command.");
            var lease = await executions.AcquireAsync(
                prepared.Acceptance!,
                command.Operation,
                now.AddSeconds(1),
                TimeSpan.FromMinutes(5),
                cancellationToken);
            if (lease.Disposition != RepositoryCiJobExecutionDisposition.Acquired || lease.Execution is null)
                throw new InvalidDataException("The in-memory runner could not acquire its CI execution.");
            var failureKind = failure?.Invoke(command, Jobs.Count) ?? RepositoryCiJobFailureKind.Unspecified;
            var completed = await executions.CompleteAsync(
                lease.Execution,
                failureKind == RepositoryCiJobFailureKind.Unspecified,
                next.ToString("x64", CultureInfo.InvariantCulture),
                0,
                failureKind,
                now.AddSeconds(2),
                cancellationToken);
            if (completed.Disposition != RepositoryCiJobExecutionDisposition.Completed)
                throw new InvalidDataException("The in-memory runner could not complete its CI execution.");
            Jobs.Add(command.Job);
            return new(GlobalNatsTopology.CiStream, next, Duplicate: false);
        }
    }

    private static ForgejoSourceArchive Archive(ForgejoResolvedRevision source)
    {
        var content = new byte[] { 0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4 };
        return new(source, Convert.ToHexStringLower(SHA256.HashData(content)), content);
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values[name].ToArray());
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

    private sealed class TestVerifier : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature)
        {
            _ = signedMaterial;
            return signature.Bytes.SequenceEqual(new byte[] { 1, 2, 3 })
                ? VerificationOutcome.Valid
                : VerificationOutcome.Invalid;
        }
    }

    internal sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset now = now;
        public override DateTimeOffset GetUtcNow() => now;
        internal void Advance(TimeSpan duration) => now = now.Add(duration);
    }
}
