namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>
/// Source-side OCI Block Volume expansion only. The caller has already obtained the closed,
/// authorized provider intent; this adapter deliberately does not infer ownership from tags.
/// </summary>
internal sealed class OciBlockVolumeExpansionAdapter(
    OciBlockVolumeExpansionScope scope,
    IOciBlockVolumeExpansionTransport transport)
{
    private readonly OciBlockVolumeExpansionScope scope = scope ?? throw new ArgumentNullException(nameof(scope));
    private readonly IOciBlockVolumeExpansionTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));

    internal async ValueTask<OciBlockVolumeExpansionResult> ExpandAsync(
        ProviderIntent intent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = Validate(intent);
        var observed = await ReadExactAsync(request, cancellationToken);
        if (observed is null)
            return OciBlockVolumeExpansionResult.OutcomeUnknown(request, null);

        var observedSize = observed.Size!;
        if (observedSize.Value == request.NewSize.Value)
            return OciBlockVolumeExpansionResult.Converged(request, observedSize);

        // A lower absolute target is a shrink request. OCI Block Volume expansion is irreversible.
        if (observedSize.Value > request.NewSize.Value)
            throw new InvalidOperationException("OCI Block Volume shrink requests are not permitted.");

        var update = new OciBlockVolumeUpdateRequest(
            request.VolumeId,
            request.CompartmentId,
            request.NewSize,
            request.IdempotencyKey,
            observed.ETag!);

        try
        {
            var response = await transport.UpdateVolumeAsync(update, cancellationToken);
            return response?.WorkRequestId is not null
                ? OciBlockVolumeExpansionResult.UpdateAccepted(request, observedSize, response.WorkRequestId)
                : await ReobserveAfterIndeterminateUpdateAsync(request, cancellationToken);
        }
        catch (OciBlockVolumeResponseLostException)
        {
            return await ReobserveAfterIndeterminateUpdateAsync(request, cancellationToken);
        }
        catch (TimeoutException)
        {
            return await ReobserveAfterIndeterminateUpdateAsync(request, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A transport timeout may surface as cancellation. Caller cancellation is always propagated.
            return await ReobserveAfterIndeterminateUpdateAsync(request, cancellationToken);
        }
    }

    private async ValueTask<OciBlockVolumeExpansionResult> ReobserveAfterIndeterminateUpdateAsync(
        OciBlockVolumeExpansionRequest request,
        CancellationToken cancellationToken)
    {
        var observed = await ReadExactAsync(request, cancellationToken);
        // Never issue a second logical mutation after an indeterminate result. The stable retry
        // identity remains available in the returned result for durable reconciliation.
        return observed is { Size: { } observedSize } && observedSize.Value >= request.NewSize.Value
            ? OciBlockVolumeExpansionResult.Converged(request, observedSize)
            : OciBlockVolumeExpansionResult.OutcomeUnknown(request, observed?.Size);
    }

    private async ValueTask<OciBlockVolumeObservation?> ReadExactAsync(
        OciBlockVolumeExpansionRequest request,
        CancellationToken cancellationToken)
    {
        var observed = await transport.GetVolumeAsync(
            new(request.VolumeId, request.CompartmentId), cancellationToken);
        if (observed is null || observed.VolumeId is null || observed.CompartmentId is null ||
            observed.Size is null || string.IsNullOrWhiteSpace(observed.ETag))
            return null;

        if (observed.VolumeId != request.VolumeId || observed.CompartmentId != request.CompartmentId)
            throw new InvalidOperationException("OCI Block Volume readback did not match the exact authorized scope.");
        if (!IsOcid(observed.VolumeId.Value, "volume") || !IsOcid(observed.CompartmentId.Value, "compartment"))
            return null;

        return observed;
    }

    private OciBlockVolumeExpansionRequest Validate(ProviderIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (intent is not ExpandVolumeProviderIntent expansion || expansion.Context is null ||
            expansion.Parameters is null)
            throw new InvalidOperationException("Only an ExpandVolumeProviderIntent is accepted.");

        var context = expansion.Context;
        if (context.ResourceKind != ProviderResourceKind.Volume || context.Action != ProviderAction.ExpandVolume ||
            context.DesiredTerminalState != ProviderTerminalState.Expanded ||
            context.Target is not ExistingProviderResource target ||
            context.ActionParameters is not ExpandVolumeProviderParameters ||
            !ReferenceEquals(context.ActionParameters, expansion.Parameters) ||
            context.ExpectedObservedState != ProviderObservedState.Present ||
            context.PermittedCompensations.Count != 0)
            throw new InvalidOperationException("The OCI Block Volume expansion intent is not an exact irreversible volume expansion.");

        if (context.CellId != scope.CellId || context.CompartmentId != scope.CompartmentId ||
            !IsOcid(target.Id.Value, "volume") || !IsOcid(context.CompartmentId.Value, "compartment"))
            throw new InvalidOperationException("The OCI Block Volume expansion target or scope is invalid.");

        return new(target.Id, context.CompartmentId, expansion.Parameters.NewSize, context.IdempotencyKey);
    }

    private static bool IsOcid(string value, string resourceKind) =>
        value is { Length: >= 12 and <= 255 } &&
        value.StartsWith($"ocid1.{resourceKind}.", StringComparison.Ordinal) &&
        value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character));
}

internal sealed record OciBlockVolumeExpansionScope
{
    internal OciBlockVolumeExpansionScope(ProviderCellId cellId, ProviderCompartmentId compartmentId)
    {
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        CompartmentId = compartmentId ?? throw new ArgumentNullException(nameof(compartmentId));
        if (!compartmentId.Value.StartsWith("ocid1.compartment.", StringComparison.Ordinal))
            throw new ArgumentException("An OCI Block Volume scope requires a compartment OCID.", nameof(compartmentId));
    }

    internal ProviderCellId CellId { get; }
    internal ProviderCompartmentId CompartmentId { get; }
}

internal sealed record OciBlockVolumeExpansionRequest(
    ProviderResourceId VolumeId,
    ProviderCompartmentId CompartmentId,
    ProviderByteCount NewSize,
    ProviderIdempotencyKey IdempotencyKey);

internal sealed record OciBlockVolumeReadRequest(ProviderResourceId VolumeId, ProviderCompartmentId CompartmentId);

internal sealed record OciBlockVolumeUpdateRequest(
    ProviderResourceId VolumeId,
    ProviderCompartmentId CompartmentId,
    ProviderByteCount NewSize,
    ProviderIdempotencyKey OpcRetryToken,
    string IfMatch);

internal sealed record OciBlockVolumeObservation(
    ProviderResourceId? VolumeId,
    ProviderCompartmentId? CompartmentId,
    ProviderByteCount? Size,
    string? ETag);

internal sealed record OciBlockVolumeUpdateResponse(ProviderWorkRequestId? WorkRequestId);

/// <summary>Tiny typed seam for an OCI SDK implementation; no factory or external client is wired here.</summary>
internal interface IOciBlockVolumeExpansionTransport
{
    ValueTask<OciBlockVolumeObservation?> GetVolumeAsync(
        OciBlockVolumeReadRequest request,
        CancellationToken cancellationToken);

    ValueTask<OciBlockVolumeUpdateResponse?> UpdateVolumeAsync(
        OciBlockVolumeUpdateRequest request,
        CancellationToken cancellationToken);
}

internal sealed class OciBlockVolumeResponseLostException : Exception
{
    internal OciBlockVolumeResponseLostException() : base("The OCI Block Volume update response was lost.") { }
}

internal enum OciBlockVolumeExpansionOutcome { Converged = 1, UpdateAccepted = 2, OutcomeUnknown = 3 }
internal enum OciBlockVolumeExpansionCleanup { None = 1 }

internal sealed record OciBlockVolumeExpansionResult(
    OciBlockVolumeExpansionOutcome Outcome,
    ProviderIdempotencyKey IdempotencyKey,
    ProviderByteCount? ObservedSize,
    ProviderWorkRequestId? WorkRequestId,
    OciBlockVolumeExpansionCleanup Cleanup)
{
    internal static OciBlockVolumeExpansionResult Converged(
        OciBlockVolumeExpansionRequest request,
        ProviderByteCount observedSize) =>
        new(OciBlockVolumeExpansionOutcome.Converged, request.IdempotencyKey, observedSize, null,
            OciBlockVolumeExpansionCleanup.None);

    internal static OciBlockVolumeExpansionResult UpdateAccepted(
        OciBlockVolumeExpansionRequest request,
        ProviderByteCount observedSize,
        ProviderWorkRequestId workRequestId) =>
        new(OciBlockVolumeExpansionOutcome.UpdateAccepted, request.IdempotencyKey, observedSize,
            workRequestId, OciBlockVolumeExpansionCleanup.None);

    internal static OciBlockVolumeExpansionResult OutcomeUnknown(
        OciBlockVolumeExpansionRequest request,
        ProviderByteCount? observedSize) =>
        new(OciBlockVolumeExpansionOutcome.OutcomeUnknown, request.IdempotencyKey, observedSize, null,
            OciBlockVolumeExpansionCleanup.None);
}
