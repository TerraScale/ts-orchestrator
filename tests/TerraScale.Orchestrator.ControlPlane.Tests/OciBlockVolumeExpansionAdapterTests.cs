using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciBlockVolumeExpansionAdapterTests
{
    private static readonly ProviderCellId Cell = new("cell-gru");
    private static readonly ProviderCompartmentId Compartment = new("ocid1.compartment.oc1..terrascale");
    private static readonly ProviderResourceId Volume = new("ocid1.volume.oc1.sa-saopaulo-1.terrascale");

    [Test]
    public async Task ExactSynchronousExpansionResponseConvergesWithAbsoluteSizeFenceAndLogicalIdentity()
    {
        var transport = new Transport(Observation(1_000));
        transport.UpdateResult = Observation(2_000, "etag-2");
        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);
        var update = transport.Updates.Single();

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.Converged);
        await Assert.That(update.VolumeId).IsEqualTo(Volume);
        await Assert.That(update.CompartmentId).IsEqualTo(Compartment);
        await Assert.That(update.NewSize.Value).IsEqualTo(2_000UL);
        await Assert.That(update.IfMatch).IsEqualTo("etag-1");
        await Assert.That(result.IdempotencyKey.Value).IsEqualTo("expand-idempotency-1");
        await Assert.That(result.ObservedETag).IsEqualTo("etag-2");
        await Assert.That(transport.Reads).IsEqualTo(1);
        await Assert.That(result.Cleanup).IsEqualTo(OciBlockVolumeExpansionCleanup.None);
    }

    [Test]
    public async Task AlreadyExpandedVolumeConvergesWithoutUpdate()
    {
        var transport = new Transport(Observation(2_000));

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.Converged);
        await Assert.That(transport.Updates).IsEmpty();
        await Assert.That(result.ObservedETag).IsEqualTo("etag-1");
        await Assert.That(result.Cleanup).IsEqualTo(OciBlockVolumeExpansionCleanup.None);
    }

    [Test]
    public async Task ShrinkIsRejectedWithoutUpdate()
    {
        var transport = new Transport(Observation(2_000));
        Func<Task> expand = async () => await Adapter(transport).ExpandAsync(Intent(1_000), default);

        await Assert.That(expand).Throws<InvalidOperationException>();
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task WrongIntentSemanticsScopeAndOcidAreRejectedBeforeAnyProviderCall()
    {
        var transport = new Transport(Observation(1_000));
        var adapter = Adapter(transport);
        var variants = new[]
        {
            Intent(2_000, resourceKind: ProviderResourceKind.Node),
            Intent(2_000, action: ProviderAction.ChangeVolumePerformance),
            Intent(2_000, terminal: ProviderTerminalState.Present),
            Intent(2_000, expectedObservedState: ProviderObservedState.Running),
            Intent(2_000, compartment: new("ocid1.compartment.oc1..other")),
            Intent(2_000, volume: new("volume-not-an-oci-ocid")),
            Intent(2_000, compensations: [ProviderCompensation.ObserveOnly]),
        };

        foreach (var intent in variants)
        {
            Func<Task> expand = async () => await adapter.ExpandAsync(intent, default);
            await Assert.That(expand).Throws<InvalidOperationException>();
        }

        await Assert.That(transport.Reads).IsEqualTo(0);
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task ResponseLossReobservesWithTheSameLogicalIdentityAndNeverIssuesSecondUpdate()
    {
        var transport = new Transport(Observation(1_000), Observation(2_000));
        transport.UpdateFailure = new OciBlockVolumeResponseLostException();

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.Converged);
        await Assert.That(transport.Reads).IsEqualTo(2);
        await Assert.That(transport.Updates).Count().IsEqualTo(1);
        await Assert.That(result.IdempotencyKey.Value).IsEqualTo("expand-idempotency-1");
        await Assert.That(result.ObservedETag).IsEqualTo("etag-1");
    }

    [Test]
    public async Task NullMalformedOrNotYetTargetUpdateResponsesReadBackOnceWithoutDuplicateMutation()
    {
        var nullResponse = new Transport(Observation(1_000), Observation(2_000));
        nullResponse.UpdateResult = null;
        var malformedResponse = new Transport(Observation(1_000), Observation(2_000));
        malformedResponse.UpdateResult = new(null, null, null, null);
        var notYetTarget = new Transport(Observation(1_000), Observation(2_000));
        notYetTarget.UpdateResult = Observation(1_500, "etag-2");

        foreach (var transport in new[] { nullResponse, malformedResponse, notYetTarget })
        {
            var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);
            await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.Converged);
            await Assert.That(transport.Updates).Count().IsEqualTo(1);
            await Assert.That(transport.Reads).IsEqualTo(2);
            await Assert.That(result.ObservedETag).IsEqualTo("etag-1");
        }
    }

    [Test]
    public async Task WrongScopeSynchronousUpdateResponseIsNeverSuccess()
    {
        var transport = new Transport(Observation(1_000))
        {
            UpdateResult = new(new("ocid1.volume.oc1.sa-saopaulo-1.other"), Compartment, new(2_000), "etag-2"),
        };

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.OutcomeUnknown);
        await Assert.That(result.ObservedETag).IsEqualTo("etag-1");
        await Assert.That(transport.Updates).Count().IsEqualTo(1);
        await Assert.That(transport.Reads).IsEqualTo(1);
    }

    [Test]
    public async Task MissingInitialProviderReadIsOutcomeUnknownWithoutMutation()
    {
        var transport = new Transport((OciBlockVolumeObservation?)null);

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.OutcomeUnknown);
        await Assert.That(result.ObservedSize).IsNull();
        await Assert.That(result.ObservedETag).IsNull();
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task CancellationIsPropagatedBeforeAnyExternalCall()
    {
        var transport = new Transport(Observation(1_000));
        using var source = new CancellationTokenSource();
        source.Cancel();
        Func<Task> expand = async () => await Adapter(transport).ExpandAsync(Intent(2_000), source.Token);

        await Assert.That(expand).Throws<OperationCanceledException>();
        await Assert.That(transport.Reads).IsEqualTo(0);
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task IndeterminateUpdateReadbackFailureReturnsUnknownWithLastKnownFence()
    {
        var transport = new Transport(Observation(1_000))
        {
            UpdateFailure = new OciBlockVolumeResponseLostException(),
            ReadFailure = new TimeoutException(),
            ThrowReadOnCall = 2,
        };

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Outcome).IsEqualTo(OciBlockVolumeExpansionOutcome.OutcomeUnknown);
        await Assert.That(result.IdempotencyKey.Value).IsEqualTo("expand-idempotency-1");
        await Assert.That(result.ObservedSize!.Value).IsEqualTo(1_000UL);
        await Assert.That(result.ObservedETag).IsEqualTo("etag-1");
        await Assert.That(transport.Updates).Count().IsEqualTo(1);
        await Assert.That(transport.Reads).IsEqualTo(2);
    }

    [Test]
    public async Task CallerCancellationDuringIndeterminateReadbackIsPropagated()
    {
        using var source = new CancellationTokenSource();
        var transport = new Transport(Observation(1_000))
        {
            UpdateFailure = new OciBlockVolumeResponseLostException(),
            OnRead = read => { if (read == 2) source.Cancel(); },
        };
        Func<Task> expand = async () => await Adapter(transport).ExpandAsync(Intent(2_000), source.Token);

        await Assert.That(expand).Throws<OperationCanceledException>();
        await Assert.That(transport.Updates).Count().IsEqualTo(1);
        await Assert.That(transport.Reads).IsEqualTo(2);
    }

    [Test]
    public async Task ExpansionDeclaresNoCleanupSideEffects()
    {
        var transport = new Transport(Observation(1_000));
        transport.UpdateResult = Observation(2_000, "etag-2");

        var result = await Adapter(transport).ExpandAsync(Intent(2_000), default);

        await Assert.That(result.Cleanup).IsEqualTo(OciBlockVolumeExpansionCleanup.None);
        await Assert.That(transport.CleanupCalls).IsEqualTo(0);
        await Assert.That(typeof(IOciBlockVolumeExpansionTransport).GetMethods()
            .Select(static method => method.Name)).DoesNotContain("DeleteVolumeAsync");
    }

    private static OciBlockVolumeExpansionAdapter Adapter(Transport transport) =>
        new(new(Cell, Compartment), transport);

    private static ExpandVolumeProviderIntent Intent(
        ulong size,
        ProviderResourceKind resourceKind = ProviderResourceKind.Volume,
        ProviderAction action = ProviderAction.ExpandVolume,
        ProviderTerminalState terminal = ProviderTerminalState.Expanded,
        ProviderObservedState expectedObservedState = ProviderObservedState.Present,
        ProviderCompartmentId? compartment = null,
        ProviderResourceId? volume = null,
        IEnumerable<ProviderCompensation>? compensations = null)
    {
        var parameters = new ExpandVolumeProviderParameters(new(size));
        var context = new ProviderOperationContext(
            new("expand-operation-1"),
            Cell,
            compartment ?? Compartment,
            new(1),
            resourceKind,
            action,
            new ExistingProviderResource(volume ?? Volume),
            new(1),
            expectedObservedState,
            terminal,
            [ProviderApproval.RegionalAuthority],
            new(DeadlineEvidenceStatus.Valid, new(1)),
            new("expand-idempotency-1"),
            compensations ?? [],
            parameters);
        return new(context);
    }

    private static OciBlockVolumeObservation Observation(ulong size, string eTag = "etag-1") =>
        new(Volume, Compartment, new(size), eTag);

    private sealed class Transport(params OciBlockVolumeObservation?[] observations) : IOciBlockVolumeExpansionTransport
    {
        private readonly Queue<OciBlockVolumeObservation?> observations = new(observations);
        internal int Reads { get; private set; }
        internal int CleanupCalls { get; private set; }
        internal List<OciBlockVolumeUpdateRequest> Updates { get; } = [];
        internal OciBlockVolumeObservation? UpdateResult { get; set; }
        internal Exception? UpdateFailure { get; set; }
        internal Exception? ReadFailure { get; set; }
        internal int? ThrowReadOnCall { get; set; }
        internal Action<int>? OnRead { get; set; }

        public ValueTask<OciBlockVolumeObservation?> GetVolumeAsync(
            OciBlockVolumeReadRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            OnRead?.Invoke(Reads);
            cancellationToken.ThrowIfCancellationRequested();
            if (ReadFailure is not null && ThrowReadOnCall == Reads)
                throw ReadFailure;
            return ValueTask.FromResult(observations.Count == 0 ? null : observations.Dequeue());
        }

        public ValueTask<OciBlockVolumeObservation?> UpdateVolumeAsync(
            OciBlockVolumeUpdateRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Updates.Add(request);
            if (UpdateFailure is not null)
                throw UpdateFailure;
            return ValueTask.FromResult(UpdateResult);
        }
    }
}
