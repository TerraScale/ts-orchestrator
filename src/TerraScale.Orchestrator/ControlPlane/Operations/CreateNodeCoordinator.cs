using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public sealed record CreateNodeDispatch(DispatchProviderIntent OperationIntent, OperationAuthorized Authorization,
    CreateNodeProviderIntent ProviderIntent, string NodeRequestId, CreateNodeTenantAuthorizationProof TenantProof);
public enum CreateNodeCoordinationDisposition { Completed = 1, InProgress = 2, RequiresManualRecovery = 3 }
public sealed record CreateNodeCoordinationResult(CreateNodeCoordinationDisposition Disposition, CreateNodeOperationJournalEntry Entry);
public sealed record CreateNodeCoordinatorOptions(TimeSpan ProviderInvocationLease)
{ public static CreateNodeCoordinatorOptions Default { get; } = new(TimeSpan.FromMinutes(1)); public void Validate() { if (ProviderInvocationLease <= TimeSpan.Zero || ProviderInvocationLease > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(ProviderInvocationLease)); } }

/// <summary>Never retries a recorded CreateNode call. Recovery only reconciles its durable create key, then holds on uncertainty.</summary>
public sealed class CreateNodeCoordinator(ICreateNodeOperationJournal journal, ICreateNodeProvider provider,
    CreateNodeHandoffReceiptSigner signer, ICreateNodeReceiptKeyResolver receiptKeys, ICreateNodeTenantAuthorityKeyResolver tenantKeys,
    ICreateNodeProviderAttestationKeyResolver providerKeys, CreateNodeRecoveryLookupSigner recoverySigner, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, TimeProvider clock,
    CreateNodeCoordinatorOptions? options = null)
{
    private readonly ICreateNodeOperationJournal journal = journal ?? throw new ArgumentNullException(nameof(journal));
    private readonly ICreateNodeProvider provider = provider ?? throw new ArgumentNullException(nameof(provider));
    private readonly CreateNodeHandoffReceiptSigner signer = signer ?? throw new ArgumentNullException(nameof(signer));
    private readonly ICreateNodeReceiptKeyResolver receiptKeys = receiptKeys ?? throw new ArgumentNullException(nameof(receiptKeys));
    private readonly ICreateNodeTenantAuthorityKeyResolver tenantKeys = tenantKeys ?? throw new ArgumentNullException(nameof(tenantKeys));
    private readonly ICreateNodeProviderAttestationKeyResolver providerKeys = providerKeys ?? throw new ArgumentNullException(nameof(providerKeys));
    private readonly CreateNodeRecoveryLookupSigner recoverySigner = recoverySigner ?? throw new ArgumentNullException(nameof(recoverySigner));
    private readonly ICreateNodeRecoveryLookupKeyResolver recoveryKeys = recoveryKeys ?? throw new ArgumentNullException(nameof(recoveryKeys));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly CreateNodeCoordinatorOptions options = options ?? CreateNodeCoordinatorOptions.Default;
    public async ValueTask<CreateNodeCoordinationResult> ExecuteAsync(CreateNodeDispatch dispatch, CancellationToken cancellationToken = default)
    {
        if (provider.IsExternalMutationProvider && journal.Durability != CreateNodeJournalDurability.AuthoritativeCrashDurable)
            throw new InvalidOperationException("External CreateNode mutation requires an authoritative crash-durable journal.");
        var spec = Validate(dispatch, clock.GetUtcNow()); options.Validate();
        while (true)
        {
            var now = clock.GetUtcNow(); var current = await journal.ReadAsync(spec.Binding.OperationId, cancellationToken);
            if (current is null)
            {
                var prepared = new CreateNodeOperationJournalEntry(0, spec.Fingerprint, spec.Binding,
                    signer.Sign(spec.Binding, now, dispatch.OperationIntent.Deadline), recoverySigner.Sign(spec.Binding, now, now.AddDays(1)), CreateNodeJournalStage.Prepared, null, 0, null);
                if (!await journal.CompareExchangeAsync(null, prepared, cancellationToken)) continue; continue;
            }
            if (current.OperationFingerprint != spec.Fingerprint || current.Binding != spec.Binding)
                throw new InvalidOperationException("CreateNode journal does not contain the exact current signed authorization.");
            if (current.Stage == CreateNodeJournalStage.Completed) return new(CreateNodeCoordinationDisposition.Completed, current);
            if (current.Stage == CreateNodeJournalStage.RequiresManualRecovery) return new(CreateNodeCoordinationDisposition.RequiresManualRecovery, current);
            if (current.Stage == CreateNodeJournalStage.ProviderCallStarted && !CreateNodeRecoveryLookupVerifier.Verify(current.RecoveryAuthority, recoveryKeys, spec.Binding, now))
            { var held = current with { Stage = CreateNodeJournalStage.RequiresManualRecovery }; if (!await journal.CompareExchangeAsync(current, held, cancellationToken)) continue; continue; }
            var mutationAuthority = CreateNodeHandoffReceiptVerifier.Verify(current.Receipt, receiptKeys, spec.Binding, now);
            var recoveryAuthority = current.Stage == CreateNodeJournalStage.ProviderCallStarted && CreateNodeRecoveryLookupVerifier.Verify(current.RecoveryAuthority, recoveryKeys, spec.Binding, now);
            if (!mutationAuthority && !recoveryAuthority)
            {
                if (current.Stage == CreateNodeJournalStage.ProviderCallStarted)
                { var held = current with { Stage = CreateNodeJournalStage.RequiresManualRecovery }; if (!await journal.CompareExchangeAsync(current, held, cancellationToken)) continue; continue; }
                throw new InvalidOperationException("CreateNode mutation authority has expired.");
            }
            if (current.Stage == CreateNodeJournalStage.ProviderCallStarted)
            {
                if (now - current.ProviderCallStartedAt!.Value < options.ProviderInvocationLease) return new(CreateNodeCoordinationDisposition.InProgress, current);
                var reconciliation = await provider.ReconcileCreateNodeAsync(Request(dispatch, current.Receipt, current.RecoveryAuthority, spec.Binding), cancellationToken);
                if (reconciliation.Status == CreateNodeReconciliationStatus.Found && reconciliation.Response is not null && reconciliation.Proof is not null &&
                    CreateNodeProviderProofVerifier.Verify(reconciliation.Proof, providerKeys, spec.Binding) &&
                    reconciliation.Proof.NodeId == reconciliation.Response.NodeId && reconciliation.Proof.WorkRequestId == reconciliation.Response.WorkRequestId)
                {
                    var completed = current with { Stage = CreateNodeJournalStage.Completed, Response = reconciliation.Response };
                    if (!await journal.CompareExchangeAsync(current, completed, cancellationToken)) continue; continue;
                }
                var held = current with { Stage = CreateNodeJournalStage.RequiresManualRecovery };
                if (!await journal.CompareExchangeAsync(current, held, cancellationToken)) continue; continue;
            }
            var started = current with { Stage = CreateNodeJournalStage.ProviderCallStarted, ProviderCallStartedAt = now, ProviderAttempts = checked(current.ProviderAttempts + 1) };
            if (!await journal.CompareExchangeAsync(current, started, cancellationToken)) continue;
            var persisted = await journal.ReadAsync(spec.Binding.OperationId, cancellationToken) ?? throw new InvalidOperationException("Invocation checkpoint was not persisted.");
            var response = await provider.CreateNodeAsync(Request(dispatch, persisted.Receipt, persisted.RecoveryAuthority, spec.Binding), cancellationToken);
            var completedNow = persisted with { Stage = CreateNodeJournalStage.Completed, Response = response };
            if (!await journal.CompareExchangeAsync(persisted, completedNow, cancellationToken)) continue;
        }
    }
    private static CreateNodeProviderRequest Request(CreateNodeDispatch dispatch, CreateNodeHandoffReceipt receipt, CreateNodeRecoveryLookupAuthority recovery, CreateNodeReceiptBinding binding) => new(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, binding, receipt, recovery);
    private Specification Validate(CreateNodeDispatch dispatch, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(dispatch); ArgumentNullException.ThrowIfNull(dispatch.OperationIntent); ArgumentNullException.ThrowIfNull(dispatch.Authorization); ArgumentNullException.ThrowIfNull(dispatch.ProviderIntent);
        var op = dispatch.OperationIntent; var auth = dispatch.Authorization; var context = dispatch.ProviderIntent.Context; var parameters = dispatch.ProviderIntent.Parameters;
        if (op.OperationKind != "create-node" || !CreateNodeTenantAuthorizationVerifier.Verify(dispatch.TenantProof, tenantKeys, op.OperationId, op.AuthorizationDigest, now, out var tenant))
            throw new ArgumentException("CreateNode requires a verified tenant authorization proof.", nameof(dispatch));
        if (op.OperationKind != "create-node" || op.TargetIdentity != dispatch.NodeRequestId ||
            auth.OperationId != op.OperationId || auth.Sequence != op.AuthorizationSequence || auth.AuthorizationDigest != op.AuthorizationDigest ||
            auth.EventDigest != OperationDigest.Event(auth) || context.OperationId.Value != op.OperationId || context.IdempotencyKey.Value != op.IdempotencyKey ||
            context.ExpectedGeneration.Value != (ulong)op.DesiredGeneration || context.Action != ProviderAction.CreateNode || context.ResourceKind != ProviderResourceKind.Node ||
            context.Target is not IdempotentProviderCreate create)
            throw new ArgumentException("CreateNode requires an exact authenticated operation authorization and provider intent.", nameof(dispatch));
        var binding = new CreateNodeReceiptBinding(op.OperationId, tenant, dispatch.NodeRequestId, op.IdempotencyKey, create.Key.Value,
            context.CellId.Value, context.CompartmentId.Value, context.ExpectedGeneration.Value, context.ControllerEpoch.Value,
            parameters.TemplateId.Value, parameters.PlacementId.Value, parameters.BootstrapEnvelopeDigest.Sha256,
            op.AuthorizationSequence, op.AuthorizationDigest, context.Fingerprint);
        CreateNodeHandoffReceiptSigner.Validate(binding, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddTicks(1));
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-journal-v2", binding.OperationId, binding.TenantId, binding.NodeRequestId, binding.IdempotencyKey, binding.CreateKey, binding.CellId, binding.CompartmentId, binding.Generation, binding.Epoch, binding.TemplateId, binding.PlacementId, binding.BootstrapEnvelopeDigest, binding.AuthorizationSequence, binding.AuthorizationDigest))));
        return new(fingerprint, binding);
    }
    private sealed record Specification(string Fingerprint, CreateNodeReceiptBinding Binding);
}
