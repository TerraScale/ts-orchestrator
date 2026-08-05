using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CreateNodeCoordinatorTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReceiptIsSignedPersistedAndRejectsTamperExpiryAndWrongBindings()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeHandoffReceiptSigner("handoff-key-1", key);
        var receipt = signer.Sign("op-1", "tenant-a", "node-request-1", "create-key-1", Start, Start.AddMinutes(5));
        var publicKey = signer.ExportPublicKey();

        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, publicKey,
            "op-1", "tenant-a", "node-request-1", "create-key-1", Start.AddMinutes(1))).IsTrue();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt with { TenantId = "tenant-b" }, publicKey,
            "op-1", "tenant-b", "node-request-1", "create-key-1", Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, publicKey,
            "op-1", "tenant-a", "other-request", "create-key-1", Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, publicKey,
            "op-1", "tenant-a", "node-request-1", "create-key-1", Start.AddMinutes(5))).IsFalse();
    }

    [Test]
    public async Task DuplicateAndRestartResumeUseOnePersistedProviderSideEffect()
    {
        var clock = new FixedTimeProvider(Start);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeHandoffReceiptSigner("handoff-key-1", key);
        var provider = new DeterministicCreateNodeProvider(signer.ExportPublicKey(), clock);
        var directory = Path.Combine(Path.GetTempPath(), $"terrascale-create-node-{Guid.NewGuid():N}");
        try
        {
            var first = new CreateNodeCoordinator(new FileCreateNodeOperationJournal(directory), provider, signer, clock);
            var dispatch = Dispatch();
            var completed = await first.ExecuteAsync(dispatch);
            var resumed = new CreateNodeCoordinator(new FileCreateNodeOperationJournal(directory), provider, signer, clock);
            var duplicate = await resumed.ExecuteAsync(dispatch);

            await Assert.That(completed.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
            await Assert.That(duplicate.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
            await Assert.That(duplicate.Entry.Receipt.Signature).IsEqualTo(completed.Entry.Receipt.Signature);
            await Assert.That(provider.SideEffectCount).IsEqualTo(1);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task ConcurrentCoordinatorsUseCasToSuppressTheSecondProviderCall()
    {
        var clock = new FixedTimeProvider(Start);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeHandoffReceiptSigner("handoff-key-1", key);
        var deterministic = new DeterministicCreateNodeProvider(signer.ExportPublicKey(), clock);
        var blocking = new BlockingProvider(deterministic);
        var journal = new InMemoryCreateNodeOperationJournal();
        var first = new CreateNodeCoordinator(journal, blocking, signer, clock);
        var second = new CreateNodeCoordinator(journal, blocking, signer, clock);
        var dispatch = Dispatch();

        var executing = first.ExecuteAsync(dispatch).AsTask();
        await blocking.Started.Task;
        var contender = await second.ExecuteAsync(dispatch);
        blocking.Release.TrySetResult();
        var completed = await executing;

        await Assert.That(contender.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.InProgress);
        await Assert.That(completed.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        await Assert.That(blocking.CallCount).IsEqualTo(1);
        await Assert.That(deterministic.SideEffectCount).IsEqualTo(1);
    }

    [Test]
    public async Task CompareExchangeRejectsConcurrentStaleJournalTransitions()
    {
        var journal = new InMemoryCreateNodeOperationJournal();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeHandoffReceiptSigner("handoff-key-1", key);
        var receipt = signer.Sign("op-1", "tenant-a", "node-request-1", "create-key-1", Start, Start.AddMinutes(5));
        var prepared = new CreateNodeOperationJournalEntry(0, "fingerprint", "op-1", "tenant-a", "node-request-1",
            "create-key-1", receipt, CreateNodeJournalStage.Prepared, null, 0, null);
        await Assert.That(await journal.CompareExchangeAsync(null, prepared, default)).IsTrue();
        var stored = (await journal.ReadAsync("op-1", default))!;
        var one = stored with { Stage = CreateNodeJournalStage.ProviderCallStarted, ProviderCallStartedAt = Start, ProviderAttempts = 1 };
        var two = stored with { Stage = CreateNodeJournalStage.ProviderCallStarted, ProviderCallStartedAt = Start.AddSeconds(1), ProviderAttempts = 1 };

        var results = await Task.WhenAll(
            journal.CompareExchangeAsync(stored, one, default).AsTask(),
            journal.CompareExchangeAsync(stored, two, default).AsTask());
        await Assert.That(results.Count(static result => result)).IsEqualTo(1);
    }

    [Test]
    public async Task OciAdapterFailsClosedBeforeCallingItsClientWhenDisabled()
    {
        var clock = new FixedTimeProvider(Start);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeHandoffReceiptSigner("handoff-key-1", key);
        var client = new CountingOciClient();
        var provider = new OciCreateNodeProvider(new(false), client, signer.ExportPublicKey(), clock);
        var dispatch = Dispatch();
        var receipt = signer.Sign("op-1", "tenant-a", "node-request-1", "create-key-1", Start, Start.AddMinutes(5));
        var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters,
            dispatch.TenantId, dispatch.NodeRequestId, receipt);

        Func<Task> invoke = async () => { await provider.CreateNodeAsync(request, default); };
        await Assert.That(invoke).Throws<InvalidOperationException>();
        await Assert.That(client.CallCount).IsEqualTo(0);
    }

    private static CreateNodeDispatch Dispatch()
    {
        var desired = new DesiredOperation("aggregate-a", 7, "desired-rv-7", "create-node", "node-request-1", "present",
            "payload-sha256", "idempotency-1", Start.AddMinutes(5));
        var expected = new ObservedResource("aggregate-a", 7, "expected-rv-1", "expected-observation", "node-request-1", "absent", true);
        var prepared = OperationEngine.Decide([], new PrepareOperation("op-1", 10, Start, desired, expected, ["observe-only"])).EventsToAppend.ToList();
        var evidence = new AuthorizationEvidence(new("aggregate-a", 7, "authorized-rv-2", "authorized-observation", "node-request-1", "absent", true),
            "approval-sha256", "evidence-sha256", true, true, true, true);
        prepared.AddRange(OperationEngine.Decide(prepared, new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), evidence)).EventsToAppend);
        var operationIntent = (DispatchProviderIntent)OperationEngine.Decide(prepared,
            new RecordDispatch("op-1", 12, Start.AddMinutes(2), "coordinator", 1)).Intents.Single();
        var context = new ProviderOperationContext(new("op-1"), new("cell-a"), new("compartment-a"), new(12),
            ProviderResourceKind.Node, ProviderAction.CreateNode, new IdempotentProviderCreate(new("create-key-1")), new(7),
            ProviderObservedState.Absent, ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority],
            new(DeadlineEvidenceStatus.Valid, new(7)), new("idempotency-1"), [ProviderCompensation.ObserveOnly],
            new CreateNodeProviderParameters(new("template-a"), new("placement-a"), new(new string('a', 64))));
        var authorization = ProviderOwnershipEngine.Authorize(new ProviderAuthorizationRequest(context,
            new(new("cell-a"), new("compartment-a"), new(12)), [], [], ProviderObservationCompleteness.Complete, [],
            [new ProviderCreateObservation(new("create-key-1"), new("cell-a"), new("compartment-a"), new(7), ProviderObservedState.Absent, null)],
            [ProviderApproval.RegionalAuthority], null, new(context, ProviderCallStatus.NotCalled, null)));
        return new(operationIntent, (CreateNodeProviderIntent)authorization.Intents.Single(), "tenant-a", "node-request-1");
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class BlockingProvider(DeterministicCreateNodeProvider inner) : ICreateNodeProvider
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int CallCount { get; private set; }

        public async ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
        {
            CallCount++;
            Started.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return await inner.CreateNodeAsync(request, cancellationToken);
        }
    }

    private sealed class CountingOciClient : IOciCreateNodeClient
    {
        public int CallCount { get; private set; }
        public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
        {
            CallCount++;
            throw new InvalidOperationException("The disabled adapter must never call this client.");
        }
    }
}
