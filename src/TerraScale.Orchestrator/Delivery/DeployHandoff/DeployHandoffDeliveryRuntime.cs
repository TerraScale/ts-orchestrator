using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery.DeployHandoff;

/// <summary>
/// The consumption seam between the ratified Deploy-to-Orchestrator handoff (#26 mapping v1) and
/// the canonical direct-delivery runtime (#3). One bounded handoff manifest becomes one
/// canonical <see cref="DeliveryRequest"/> through <see cref="DeployHandoffMapper"/> and is
/// executed by the composed <see cref="DirectDeliveryService"/>; a rejected manifest never
/// produces request data, so it can never reach the target-mutation path.
/// </summary>
/// <remarks>
/// The version-1 delivery request cannot carry the handoff's artifact architecture or its
/// declared rollback artifact, and the runtime deliberately does not trust either: rollback
/// targets are observed from the target's durable state by the coordinator, never accepted from
/// caller-supplied declarations. The handoff's rollback artifact is advisory input for the
/// sending side's own bookkeeping; a mismatch with observed state is surfaced by the delivery
/// receipt's rollback section, not by substituting the declared artifact.
/// </remarks>
internal sealed class DeployHandoffDeliveryRuntime(DirectDeliveryService delivery)
{
    private readonly DirectDeliveryService delivery = delivery ?? throw new ArgumentNullException(nameof(delivery));

    /// <summary>Maps one handoff manifest document and executes its canonical delivery request.</summary>
    public ValueTask<DeliveryReceipt> DeliverManifestAsync(
        string manifestJson,
        DeployHandoffAdmissionContext? context = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(manifestJson))
            return ValueTask.FromResult(Rejected(DirectDeliveryErrorCode.InvalidInput,
                "The handoff manifest is empty.",
                "Send the bounded handoff manifest document produced by TerraScale.Deploy."));
        DeployHandoffMappingResult mapping;
        try
        {
            mapping = DeployHandoffMapper.Map(manifestJson, context);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and
            not AccessViolationException)
        {
            return ValueTask.FromResult(Rejected(DirectDeliveryErrorCode.InvalidInput,
                "The handoff manifest could not be evaluated.",
                "Send the bounded handoff manifest document produced by TerraScale.Deploy."));
        }
        return DeliverMappedAsync(mapping, 1, 1, 1, cancellationToken);
    }

    /// <summary>
    /// Executes an already-mapped handoff request through the signed ingress. The handoff signer
    /// cannot claim a regional authority lease it cannot observe, so the runtime — which owns the
    /// lease — binds execution to the currently observed authority by stamping it onto the
    /// canonical request. Fencing is not weakened: the coordinator re-checks the live lease
    /// before dispatch and before every regional mutation, and the stamped identity is part of
    /// the durable operation fingerprint.
    /// </summary>
    public ValueTask<DeliveryReceipt> DeliverMappedAsync(
        DeployHandoffMappingResult mapping,
        long authorityGeneration,
        long writerEpoch,
        int attempt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        if (authorityGeneration <= 0 || writerEpoch <= 0 || attempt <= 0)
            return ValueTask.FromResult(Rejected(DirectDeliveryErrorCode.AuthorityFenced,
                "The delivery authority lease is not usable for a handoff execution.",
                "Retry the same handoff manifest once the control plane reports a ready authority lease."));
        if (!mapping.IsAdmittedForTargetMutation || mapping.Request is not { } request)
            return ValueTask.FromResult(Rejected(DirectDeliveryErrorCode.InvalidInput,
                $"The handoff manifest was rejected ({mapping.Error?.Code ?? "handoff_document_invalid"}): {mapping.Error?.Message}",
                mapping.Error?.Remediation ??
                    "Correct the manifest and resend it; see docs/contracts/deploy-orchestrator-handoff.md."));
        return delivery.DeliverAsync(
            request.Delivery with
            {
                AuthorityGeneration = authorityGeneration,
                WriterEpoch = writerEpoch,
                Attempt = attempt,
            },
            cancellationToken);
    }

    /// <summary>
    /// The redacted pre-admission refusal. Handoff rejections happen before any operation is
    /// admitted, so they are never journaled and use the direct-delivery error space with the
    /// bounded handoff detail carried in the message.
    /// </summary>
    private static DeliveryReceipt Rejected(string code, string message, string remediation) => new(
        DeliveryRequest.CurrentSchemaVersion,
        "invalid",
        DeliveryReceiptStatus.Failed,
        null,
        null,
        null,
        new DeliveryProvenance(false, null, null),
        new DeliveryHealth([], false),
        new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired),
        "handoff",
        new DeliveryErrorInfo(code, message, remediation));
}

