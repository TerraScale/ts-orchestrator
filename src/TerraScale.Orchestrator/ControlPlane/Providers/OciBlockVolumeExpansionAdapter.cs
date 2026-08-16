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
            return OciBlockVolumeExpansionResult.Converged(request, observed);

        // A lower absolute target is a shrink request. OCI Block Volume expansion is irreversible.
        if (observedSize.Value > request.NewSize.Value)
            throw new InvalidOperationException("OCI Block Volume shrink requests are not permitted.");

        var update = new OciBlockVolumeUpdateRequest(
            request.VolumeId,
            request.CompartmentId,
            request.NewSize,
            observed.ETag!);

        try
        {
            var response = await transport.UpdateVolumeAsync(update, cancellationToken);
            var updated = ExactObservation(request, response);
            return updated is { Size: { } updatedSize } && updatedSize.Value >= request.NewSize.Value
                ? OciBlockVolumeExpansionResult.Converged(request, updated)
                : await ReobserveAfterIndeterminateUpdateAsync(request, observed, cancellationToken);
        }
        catch (OciBlockVolumeResponseLostException)
        {
            return await ReobserveAfterIndeterminateUpdateAsync(request, observed, cancellationToken);
        }
        catch (TimeoutException)
        {
            return await ReobserveAfterIndeterminateUpdateAsync(request, observed, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A transport timeout may surface as cancellation. Caller cancellation is always propagated.
            return await ReobserveAfterIndeterminateUpdateAsync(request, observed, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            // A malformed or wrong-scope synchronous response follows a possible mutation. It
            // cannot be reported as a safe-to-retry failure or as success.
            return OciBlockVolumeExpansionResult.OutcomeUnknown(request, observed);
        }
    }

    private async ValueTask<OciBlockVolumeExpansionResult> ReobserveAfterIndeterminateUpdateAsync(
        OciBlockVolumeExpansionRequest request,
        OciBlockVolumeObservation lastKnownObservation,
        CancellationToken cancellationToken)
    {
        try
        {
            var observed = await ReadExactAsync(request, cancellationToken);
            // Never issue a second logical mutation after an indeterminate result. The stable
            // TerraScale operation identity and the last observed fence remain available for
            // durable reconciliation; they are not represented as an OCI retry header.
            return observed is { Size: { } observedSize } && observedSize.Value >= request.NewSize.Value
                ? OciBlockVolumeExpansionResult.Converged(request, observed)
                : OciBlockVolumeExpansionResult.OutcomeUnknown(request, observed ?? lastKnownObservation);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            // Once UpdateVolume might have reached OCI, even failed readback is indeterminate.
            // Do not leak a restart-safe failure signal to a caller that could issue a new grow.
            return OciBlockVolumeExpansionResult.OutcomeUnknown(request, lastKnownObservation);
        }
    }

    private async ValueTask<OciBlockVolumeObservation?> ReadExactAsync(
        OciBlockVolumeExpansionRequest request,
        CancellationToken cancellationToken)
    {
        var observed = await transport.GetVolumeAsync(
            new(request.VolumeId, request.CompartmentId), cancellationToken);
        return ExactObservation(request, observed);
    }

    private static OciBlockVolumeObservation? ExactObservation(
        OciBlockVolumeExpansionRequest request,
        OciBlockVolumeObservation? observed)
    {
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
    string IfMatch);

internal sealed record OciBlockVolumeObservation(
    ProviderResourceId? VolumeId,
    ProviderCompartmentId? CompartmentId,
    ProviderByteCount? Size,
    string? ETag);

/// <summary>Tiny typed seam for an OCI SDK implementation; no factory or external client is wired here.</summary>
internal interface IOciBlockVolumeExpansionTransport
{
    ValueTask<OciBlockVolumeObservation?> GetVolumeAsync(
        OciBlockVolumeReadRequest request,
        CancellationToken cancellationToken);

    ValueTask<OciBlockVolumeObservation?> UpdateVolumeAsync(
        OciBlockVolumeUpdateRequest request,
        CancellationToken cancellationToken);
}

internal sealed class OciBlockVolumeResponseLostException : Exception
{
    internal OciBlockVolumeResponseLostException() : base("The OCI Block Volume update response was lost.") { }
}

internal enum OciBlockVolumeExpansionOutcome { Converged = 1, OutcomeUnknown = 2 }
internal enum OciBlockVolumeExpansionCleanup { None = 1 }

internal sealed record OciBlockVolumeExpansionResult(
    OciBlockVolumeExpansionOutcome Outcome,
    ProviderIdempotencyKey IdempotencyKey,
    ProviderByteCount? ObservedSize,
    string? ObservedETag,
    OciBlockVolumeExpansionCleanup Cleanup)
{
    internal static OciBlockVolumeExpansionResult Converged(
        OciBlockVolumeExpansionRequest request,
        OciBlockVolumeObservation observed) =>
        new(OciBlockVolumeExpansionOutcome.Converged, request.IdempotencyKey, observed.Size, observed.ETag,
            OciBlockVolumeExpansionCleanup.None);

    internal static OciBlockVolumeExpansionResult OutcomeUnknown(
        OciBlockVolumeExpansionRequest request,
        OciBlockVolumeObservation? observed) =>
        new(OciBlockVolumeExpansionOutcome.OutcomeUnknown, request.IdempotencyKey, observed?.Size, observed?.ETag,
            OciBlockVolumeExpansionCleanup.None);
}
