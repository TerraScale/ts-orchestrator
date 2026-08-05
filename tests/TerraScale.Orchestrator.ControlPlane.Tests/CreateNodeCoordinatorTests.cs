using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CreateNodeCoordinatorTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReceiptBindsEveryImmutableProviderAndAuthorizationFieldAndSupportsRetainedOldKey()
    {
        using var old = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var current = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var oldSigner = new CreateNodeHandoffReceiptSigner("old", old); var signer = new CreateNodeHandoffReceiptSigner("current", current);
        var keys = new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { ["old"] = oldSigner.ExportPublicKey(), ["current"] = signer.ExportPublicKey() });
        var binding = Binding(); var receipt = oldSigner.Sign(binding, Start, Start.AddMinutes(5));
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, binding, Start.AddMinutes(1))).IsTrue();
        foreach (var changed in Variants(binding)) await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, changed, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt with { KeyId = "missing" }, keys, binding, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt with { Algorithm = "RSA" }, keys, binding, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, binding, Start.AddMinutes(5))).IsFalse();
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        await Assert.That(() => new CreateNodeHandoffReceiptSigner("p384", p384)).Throws<ArgumentException>();
        using var tenantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tenantSigner = new CreateNodeTenantAuthorizationSigner("tenant", tenantKey);
        var tenantKeys = new CreateNodeTenantAuthorityKeyRing(new Dictionary<string, byte[]> { ["tenant"] = tenantKey.ExportSubjectPublicKeyInfo() });
        var receiptDomainProof = oldSigner.SignTenantProof("tenant-a", "op-1", "authorization-digest", Start.AddMinutes(5));
        await Assert.That(CreateNodeTenantAuthorizationVerifier.Verify(receiptDomainProof, tenantKeys, "op-1", "authorization-digest", Start, out _)).IsFalse();
        await Assert.That(CreateNodeTenantAuthorizationVerifier.Verify(tenantSigner.Sign("tenant-a", "op-1", "authorization-digest", Start.AddMinutes(5)), tenantKeys, "op-1", "authorization-digest", Start, out _)).IsTrue();
    }

    [Test]
    public async Task CrashAfterProviderSuccessReconcilesWithoutSecondCreateAgainstNonDeduplicatingProvider()
    {
        var clock = new MutableTime(Start); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("key", key); var keys = Keys(signer);
        var provider = new NonDeduplicatingProvider(keys, new CreateNodeProviderProofSigner("key", key), clock); var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal());
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, keys, TenantKeys(signer), ProviderKeys(signer), clock); var first = await coordinator.ExecuteAsync(Dispatch(signer));
        await Assert.That(first.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.InProgress);
        clock.Advance(TimeSpan.FromMinutes(2)); var recovered = await coordinator.ExecuteAsync(Dispatch(signer));
        await Assert.That(recovered.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        await Assert.That(provider.CreateCalls).IsEqualTo(1); await Assert.That(provider.ReconcileCalls).IsEqualTo(1);
    }

    [Test]
    public async Task ExpiredInFlightLeaseNotFoundRequiresManualRecoveryAndNeverCreatesAgain()
    {
        var clock = new MutableTime(Start); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("key", key); var keys = Keys(signer);
        var provider = new NonDeduplicatingProvider(keys, new CreateNodeProviderProofSigner("key", key), clock) { ReturnNotFound = true }; var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal());
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, keys, TenantKeys(signer), ProviderKeys(signer), clock); await coordinator.ExecuteAsync(Dispatch(signer));
        clock.Advance(TimeSpan.FromMinutes(2)); var held = await coordinator.ExecuteAsync(Dispatch(signer));
        await Assert.That(held.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        await Assert.That(provider.CreateCalls).IsEqualTo(1); await Assert.That(provider.ReconcileCalls).IsEqualTo(1);
    }

    [Test]
    public async Task ForgedTenantAndMismatchedProviderProofRequireManualRecovery()
    {
        var clock = new MutableTime(Start); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("key", key); var keys = Keys(signer);
        var provider = new NonDeduplicatingProvider(keys, new CreateNodeProviderProofSigner("key", key), clock) { TamperProof = true };
        var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal()); var coordinator = new CreateNodeCoordinator(journal, provider, signer, keys, TenantKeys(signer), ProviderKeys(signer), clock);
        await coordinator.ExecuteAsync(Dispatch(signer)); clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.That((await coordinator.ExecuteAsync(Dispatch(signer))).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        var forged = Dispatch(signer) with { TenantProof = signer.SignTenantProof("tenant-b", "op-1", "wrong-digest", Start.AddMinutes(5)) };
        Func<Task> executeForged = async () => { await coordinator.ExecuteAsync(forged); };
        await Assert.That(executeForged).Throws<ArgumentException>();
    }

    [Test]
    public async Task DevelopmentJournalRejectsTamperedFullRecord()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"create-node-{Guid.NewGuid():N}"); var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var keys = new CreateNodeJournalTagKeyRing(new Dictionary<string, byte[]> { ["journal"] = key });
            var journal = new DevelopmentFileCreateNodeOperationJournal("Development", directory, "journal", key, keys);
            var signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("receipt", signerKey);
            var binding = Binding(); var entry = new CreateNodeOperationJournalEntry(0, "fingerprint", binding, signer.Sign(binding, Start, Start.AddMinutes(5)), CreateNodeJournalStage.Prepared, null, 0, null);
            await journal.CompareExchangeAsync(null, entry, default);
            var file = Directory.EnumerateFiles(directory, "*.json").Single(); var bytes = await File.ReadAllBytesAsync(file); bytes[^1] ^= 1; await File.WriteAllBytesAsync(file, bytes);
            await Assert.That(() => journal.ReadAsync(binding.OperationId, default).AsTask()).Throws<InvalidDataException>();
            signerKey.Dispose();
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    [Test]
    public async Task OciAdapterIsDisabledBeforeAnyClientCall()
    {
        var clock = new MutableTime(Start); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("key", key); var keys = Keys(signer); var client = new OciClient();
        var provider = new OciCreateNodeProvider(new(false), client, keys, clock); var dispatch = Dispatch(signer); var binding = Binding(); var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, binding, signer.Sign(binding, Start, Start.AddMinutes(5)));
        Func<Task> call = async () => { await provider.CreateNodeAsync(request, default); }; await Assert.That(call).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    private static ICreateNodeReceiptKeyResolver Keys(CreateNodeHandoffReceiptSigner signer) => new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { [signer.KeyId] = signer.ExportPublicKey() });
    private static ICreateNodeTenantAuthorityKeyResolver TenantKeys(CreateNodeHandoffReceiptSigner signer) => new CreateNodeTenantAuthorityKeyRing(new Dictionary<string, byte[]> { [signer.KeyId] = signer.ExportPublicKey() });
    private static ICreateNodeProviderAttestationKeyResolver ProviderKeys(CreateNodeHandoffReceiptSigner signer) => new CreateNodeProviderAttestationKeyRing(new Dictionary<string, byte[]> { [signer.KeyId] = signer.ExportPublicKey() });
    private static CreateNodeReceiptBinding Binding() => new("op-1", "tenant-a", "node-request-1", "idempotency-1", "create-key-1", "cell-a", "compartment-a", 7, 12, "template-a", "placement-a", new string('a', 64), 2, "authorization-digest", "context-fingerprint");
    private static IEnumerable<CreateNodeReceiptBinding> Variants(CreateNodeReceiptBinding value) => [value with { OperationId = "op-2" }, value with { TenantId = "tenant-b" }, value with { NodeRequestId = "node-2" }, value with { IdempotencyKey = "idempotency-2" }, value with { CreateKey = "create-key-2" }, value with { CellId = "cell-b" }, value with { CompartmentId = "compartment-b" }, value with { Generation = 8 }, value with { Epoch = 13 }, value with { TemplateId = "template-b" }, value with { PlacementId = "placement-b" }, value with { BootstrapEnvelopeDigest = new string('b', 64) }, value with { AuthorizationSequence = 3 }, value with { AuthorizationDigest = "other-digest" }];
    private static CreateNodeDispatch Dispatch(CreateNodeHandoffReceiptSigner signer)
    {
        var desired = new DesiredOperation("aggregate", 7, "rv", "create-node", "node-request-1", "present", "payload", "idempotency-1", Start.AddMinutes(5)); var observed = new ObservedResource("aggregate", 7, "rv-1", "obs-1", "node-request-1", "absent", true);
        var history = OperationEngine.Decide([], new PrepareOperation("op-1", 10, Start, desired, observed, ["observe"])).EventsToAppend.ToList(); var evidence = new AuthorizationEvidence(new("aggregate", 7, "rv-2", "obs-2", "node-request-1", "absent", true), "approval", "evidence", true, true, true, true) { TenantId = "tenant-a" };
        history.AddRange(OperationEngine.Decide(history, new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), evidence)).EventsToAppend); var authorization = (OperationAuthorized)history.Last(); var intent = (DispatchProviderIntent)OperationEngine.Decide(history, new RecordDispatch("op-1", 12, Start.AddMinutes(2), "executor", 1)).Intents.Single();
        var context = new ProviderOperationContext(new("op-1"), new("cell-a"), new("compartment-a"), new(12), ProviderResourceKind.Node, ProviderAction.CreateNode, new IdempotentProviderCreate(new("create-key-1")), new(7), ProviderObservedState.Absent, ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority], new(DeadlineEvidenceStatus.Valid, new(7)), new("idempotency-1"), [ProviderCompensation.ObserveOnly], new CreateNodeProviderParameters(new("template-a"), new("placement-a"), new(new string('a', 64))));
        var provider = (CreateNodeProviderIntent)ProviderOwnershipEngine.Authorize(new ProviderAuthorizationRequest(context, new(new("cell-a"), new("compartment-a"), new(12)), [], [], ProviderObservationCompleteness.Complete, [], [new ProviderCreateObservation(new("create-key-1"), new("cell-a"), new("compartment-a"), new(7), ProviderObservedState.Absent, null)], [ProviderApproval.RegionalAuthority], null, new(context, ProviderCallStatus.NotCalled, null))).Intents.Single(); return new(intent, authorization, provider, "node-request-1", signer.SignTenantProof("tenant-a", intent.OperationId, intent.AuthorizationDigest, Start.AddMinutes(5)));
    }
    private sealed class MutableTime(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; public void Advance(TimeSpan value) => now += value; }
    private sealed class NonDeduplicatingProvider(ICreateNodeReceiptKeyResolver keys, CreateNodeProviderProofSigner proofSigner, TimeProvider clock) : ICreateNodeProvider { private CreateNodeProviderResponse? response; public int CreateCalls { get; private set; } public int ReconcileCalls { get; private set; } public bool ReturnNotFound { get; init; } public bool TamperProof { get; init; } public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken token) { DeterministicCreateNodeProvider.Validate(request, keys, clock.GetUtcNow()); CreateCalls++; return ValueTask.FromResult(response = new(new("node-1"), new("work-1"))); } public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken token) { DeterministicCreateNodeProvider.Validate(request, keys, clock.GetUtcNow()); ReconcileCalls++; if (ReturnNotFound) return ValueTask.FromResult(new CreateNodeReconciliation(CreateNodeReconciliationStatus.NotFound, null, null)); var proof = proofSigner.Sign(TamperProof ? request.Binding with { TenantId = "tenant-b" } : request.Binding, response!); return ValueTask.FromResult(CreateNodeReconciliation.Found(response!, proof)); } }
    private sealed class DropCompletionJournal(ICreateNodeOperationJournal inner) : ICreateNodeOperationJournal { private bool drop = true; public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) => inner.ReadAsync(id, token); public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken token) { if (drop && replacement.Stage == CreateNodeJournalStage.Completed) { drop = false; return ValueTask.FromResult(false); } return inner.CompareExchangeAsync(expected, replacement, token); } }
    private sealed class OciClient : IOciCreateNodeClient { public int Calls { get; private set; } public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest r, CancellationToken t) { Calls++; throw new InvalidOperationException(); } public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest r, CancellationToken t) { Calls++; throw new InvalidOperationException(); } }
}
