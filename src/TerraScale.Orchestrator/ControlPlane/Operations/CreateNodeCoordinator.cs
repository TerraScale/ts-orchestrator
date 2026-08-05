using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public sealed record CreateNodeDispatch(
    DispatchProviderIntent OperationIntent,
    CreateNodeProviderIntent ProviderIntent,
    string TenantId,
    string NodeRequestId);

public enum CreateNodeCoordinationDisposition { Completed = 1, InProgress = 2 }
public sealed record CreateNodeCoordinationResult(
    CreateNodeCoordinationDisposition Disposition,
    CreateNodeOperationJournalEntry Entry);

public sealed record CreateNodeCoordinatorOptions(TimeSpan ProviderInvocationLease)
{
    public static CreateNodeCoordinatorOptions Default { get; } = new(TimeSpan.FromMinutes(1));
    public void Validate()
    {
        if (ProviderInvocationLease <= TimeSpan.Zero || ProviderInvocationLease > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(ProviderInvocationLease));
    }
}

/// <summary>Wires existing operation/provider decisions through a durable, replay-safe CreateNode provider boundary.</summary>
public sealed class CreateNodeCoordinator(
    ICreateNodeOperationJournal journal,
    ICreateNodeProvider provider,
    CreateNodeHandoffReceiptSigner signer,
    TimeProvider clock,
    CreateNodeCoordinatorOptions? options = null)
{
    private readonly ICreateNodeOperationJournal journal = journal ?? throw new ArgumentNullException(nameof(journal));
    private readonly ICreateNodeProvider provider = provider ?? throw new ArgumentNullException(nameof(provider));
    private readonly CreateNodeHandoffReceiptSigner signer = signer ?? throw new ArgumentNullException(nameof(signer));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly CreateNodeCoordinatorOptions options = options ?? CreateNodeCoordinatorOptions.Default;

    public async ValueTask<CreateNodeCoordinationResult> ExecuteAsync(CreateNodeDispatch dispatch, CancellationToken cancellationToken = default)
    {
        var specification = Validate(dispatch);
        options.Validate();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = clock.GetUtcNow();
            var current = await journal.ReadAsync(specification.OperationId, cancellationToken);
            if (current is null)
            {
                var receipt = signer.Sign(specification.OperationId, specification.TenantId, specification.NodeRequestId,
                    specification.CreateKey, now, dispatch.OperationIntent.Deadline);
                var prepared = new CreateNodeOperationJournalEntry(0, specification.Fingerprint, specification.OperationId,
                    specification.TenantId, specification.NodeRequestId, specification.CreateKey, receipt,
                    CreateNodeJournalStage.Prepared, null, 0, null);
                if (!await journal.CompareExchangeAsync(null, prepared, cancellationToken)) continue;
                continue;
            }

            if (!StringComparer.Ordinal.Equals(current.OperationFingerprint, specification.Fingerprint) ||
                !CreateNodeHandoffReceiptVerifier.Verify(current.Receipt, signer.ExportPublicKey(), specification.OperationId,
                    specification.TenantId, specification.NodeRequestId, specification.CreateKey, now))
                throw new InvalidOperationException("CreateNode journal entry is not an exact, current signed handoff.");

            if (current.Stage == CreateNodeJournalStage.Completed)
                return new(CreateNodeCoordinationDisposition.Completed, current);

            if (current.Stage == CreateNodeJournalStage.ProviderCallStarted && current.ProviderCallStartedAt is not null &&
                now - current.ProviderCallStartedAt < options.ProviderInvocationLease)
                return new(CreateNodeCoordinationDisposition.InProgress, current);

            var invocation = current with
            {
                Stage = CreateNodeJournalStage.ProviderCallStarted,
                ProviderCallStartedAt = now,
                ProviderAttempts = checked(current.ProviderAttempts + 1),
            };
            if (!await journal.CompareExchangeAsync(current, invocation, cancellationToken)) continue;

            var persistedInvocation = await journal.ReadAsync(specification.OperationId, cancellationToken)
                ?? throw new InvalidOperationException("CreateNode provider invocation was not durably persisted.");

            var response = await provider.CreateNodeAsync(new(
                dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, specification.TenantId,
                specification.NodeRequestId, persistedInvocation.Receipt), cancellationToken);
            var completed = persistedInvocation with { Stage = CreateNodeJournalStage.Completed, Response = response };
            if (!await journal.CompareExchangeAsync(persistedInvocation, completed, cancellationToken)) continue;
            var persisted = await journal.ReadAsync(specification.OperationId, cancellationToken)
                ?? throw new InvalidOperationException("CreateNode completion was not durably persisted.");
            return new(CreateNodeCoordinationDisposition.Completed, persisted);
        }
    }

    private static CreateNodeSpecification Validate(CreateNodeDispatch dispatch)
    {
        ArgumentNullException.ThrowIfNull(dispatch);
        ArgumentNullException.ThrowIfNull(dispatch.OperationIntent);
        ArgumentNullException.ThrowIfNull(dispatch.ProviderIntent);
        var operation = dispatch.OperationIntent;
        var context = dispatch.ProviderIntent.Context;
        if (operation.OperationKind != "create-node" || operation.OperationId != context.OperationId.Value ||
            operation.IdempotencyKey != context.IdempotencyKey.Value || operation.DesiredGeneration != (long)context.ExpectedGeneration.Value ||
            operation.TargetIdentity != dispatch.NodeRequestId || context.Action != ProviderAction.CreateNode ||
            context.ResourceKind != ProviderResourceKind.Node || context.Target is not IdempotentProviderCreate create ||
            string.IsNullOrWhiteSpace(dispatch.TenantId) || string.IsNullOrWhiteSpace(dispatch.NodeRequestId))
            throw new ArgumentException("CreateNode coordinator requires exact existing operation and provider authorization intents.", nameof(dispatch));

        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|',
            "create-node-v1", operation.OperationId, operation.IdempotencyKey, operation.DesiredGeneration,
            operation.TargetIdentity, operation.AuthorizationSequence, operation.AuthorizationDigest,
            context.CellId.Value, context.CompartmentId.Value, context.ControllerEpoch.Value, create.Key.Value,
            dispatch.ProviderIntent.Parameters.TemplateId.Value, dispatch.ProviderIntent.Parameters.PlacementId.Value,
            dispatch.ProviderIntent.Parameters.BootstrapEnvelopeDigest.Sha256, dispatch.TenantId, dispatch.NodeRequestId))));
        return new(fingerprint, operation.OperationId, dispatch.TenantId, dispatch.NodeRequestId, create.Key.Value);
    }

    private sealed record CreateNodeSpecification(string Fingerprint, string OperationId, string TenantId, string NodeRequestId, string CreateKey);
}
