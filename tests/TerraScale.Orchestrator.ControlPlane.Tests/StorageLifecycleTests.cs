using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageLifecycleTests
{
    [Test]
    public async Task Create_workflow_emits_typed_restartable_next_actions()
    {
        var expected = new Dictionary<StorageCreateCheckpoint, StorageAction>
        {
            [StorageCreateCheckpoint.ClaimAccepted] = StorageAction.Observe,
            [StorageCreateCheckpoint.CapacityAndBudgetChecked] = StorageAction.Create,
            [StorageCreateCheckpoint.VolumeCreated] = StorageAction.Attach,
            [StorageCreateCheckpoint.AttachmentCreated] = StorageAction.Verify,
            [StorageCreateCheckpoint.DeviceIdentityVerified] = StorageAction.Classify,
            [StorageCreateCheckpoint.Classified] = StorageAction.Format,
            [StorageCreateCheckpoint.FormattedIfNew] = StorageAction.Mount,
            [StorageCreateCheckpoint.Mounted] = StorageAction.Verify,
            [StorageCreateCheckpoint.Ready] = StorageAction.Verify,
        };
        foreach (var item in expected)
        {
            var decision = StorageCreatePlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), item.Key, StorageTestData.Format());
            await Assert.That(decision.Action).IsEqualTo(item.Value);
        }
    }

    [Test]
    public async Task Format_requires_exact_owner_provider_blank_and_current_fence()
    {
        var volume = StorageTestData.Volume();
        var valid = StorageFormatPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Format());
        var wrongProvider = StorageFormatPlanner.Plan(volume, StorageTestData.Context(provider: StorageTestData.Provider("other")), StorageTestData.Format());
        var wrongOwner = StorageFormatPlanner.Plan(volume, StorageTestData.Context(member: StorageTestData.Member("other")), StorageTestData.Format());
        var staleFence = StorageFormatPlanner.Plan(volume, StorageTestData.Context(fence: StorageTestData.Fence("other")), StorageTestData.Format());
        var noBlank = StorageFormatPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Format(blank: StorageProof.Unknown));
        var validScope = StorageTestData.Require(valid.Scope);

        await Assert.That(valid.Action).IsEqualTo(StorageAction.Format);
        await Assert.That(validScope.DeviceId).IsEqualTo(StorageTestData.Device());
        await Assert.That(validScope.FilesystemId).IsEqualTo(StorageTestData.Filesystem());
        await Assert.That(wrongProvider.Code).IsEqualTo(StorageDecisionCode.WrongProviderVolume);
        await Assert.That(wrongOwner.Code).IsEqualTo(StorageDecisionCode.WrongOwner);
        await Assert.That(staleFence.Code).IsEqualTo(StorageDecisionCode.WrongFence);
        await Assert.That(noBlank.Code).IsEqualTo(StorageDecisionCode.BlankProofRequired);

        var replayed = StorageFormatPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Format(
            scope: StorageTestData.Scope(operation: StorageTestData.Operation("other"))));
        await Assert.That(replayed.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
        await Assert.That(replayed.IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Recognized_volume_never_formats_through_either_planner()
    {
        var direct = StorageFormatPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Format(classification: StorageDeviceClassification.Recognized));
        var workflow = StorageCreatePlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageCreateCheckpoint.Classified,
            StorageTestData.Format(classification: StorageDeviceClassification.Recognized));

        await Assert.That(direct.Action).IsEqualTo(StorageAction.Mount);
        await Assert.That(workflow.Action).IsEqualTo(StorageAction.Mount);
        await Assert.That(new[] { direct, workflow }.Any(static d => d.Action == StorageAction.Format)).IsFalse();

        var unidentified = StorageFormatPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(),
            StorageTestData.Format(classification: StorageDeviceClassification.Recognized, filesystem: StorageProof.Unknown));
        await Assert.That(unidentified.Action).IsEqualTo(StorageAction.Hold);
    }

    [Test]
    public async Task Dual_writer_is_held_and_writer_evidence_is_defensively_copied()
    {
        var writers = new List<StorageWriterObservation?>
        {
            new(StorageTestData.Node("a"),StorageTestData.Attachment("a"),StorageTestData.Epoch(7)),
            new(StorageTestData.Node("b"),StorageTestData.Attachment("b"),StorageTestData.Epoch(8)),
        };
        var evidence = new StorageReattachEvidence(StorageTestData.Scope(), writers, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(9), 4);
        writers.Clear();
        var decision = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("c"), evidence);
        await Assert.That(evidence.Writers.Count).IsEqualTo(2);
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Hold);
        await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.DualWriter);
    }

    [Test]
    public async Task Reattach_requires_stop_lease_detach_new_epoch_and_health()
    {
        var writer = new StorageWriterObservation(StorageTestData.Node("old"), StorageTestData.Attachment(), StorageTestData.Epoch(7));
        StorageReattachEvidence E(StorageProof stop, StorageProof lease, StorageProof detached, ulong epoch) =>
            new(StorageTestData.Scope(), [writer], stop, lease, detached, StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(epoch), 2);
        var missing = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Unknown, StorageProof.Proven, StorageProof.Proven, 8));
        var detach = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Proven, StorageProof.Proven, StorageProof.Unknown, 8));
        var stale = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, 7));
        var attach = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, 8));

        await Assert.That(missing.Code).IsEqualTo(StorageDecisionCode.ReattachProofMissing);
        await Assert.That(detach.Action).IsEqualTo(StorageAction.Detach);
        await Assert.That(stale.Code).IsEqualTo(StorageDecisionCode.NewWriterEpochRequired);
        await Assert.That(attach.Action).IsEqualTo(StorageAction.Attach);
        await Assert.That(StorageTestData.Require(attach.Trace).Epoch).IsEqualTo(StorageTestData.Epoch(8));
    }

    [Test]
    public async Task Empty_writer_inventory_must_be_proven_complete_before_attach()
    {
        StorageReattachEvidence E(StorageProof complete) => new(StorageTestData.Scope(), [], StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Unknown, complete, StorageTestData.Epoch(8), 2);
        var unknown = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Unknown));
        var complete = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), E(StorageProof.Proven));
        await Assert.That(unknown.Action).IsEqualTo(StorageAction.Hold);
        await Assert.That(complete.Action).IsEqualTo(StorageAction.Attach);
        await Assert.That(StorageTestData.Require(complete.Trace).Epoch).IsEqualTo(StorageTestData.Epoch(8));
        var stale = new StorageReattachEvidence(StorageTestData.Scope(), [], StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(7), 2);
        var staleDecision = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), stale);
        await Assert.That(staleDecision.Code).IsEqualTo(StorageDecisionCode.NewWriterEpochRequired);

        var replayed = new StorageReattachEvidence(StorageTestData.Scope(provider: StorageTestData.Provider("other")), [],
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 2);
        var replayedDecision = StorageAttachmentPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), replayed);
        await Assert.That(replayedDecision.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
    }

    [Test]
    public async Task Writer_observation_permutation_does_not_change_dual_writer_decision()
    {
        var a = new StorageWriterObservation(StorageTestData.Node("a"), StorageTestData.Attachment("a"), StorageTestData.Epoch(7));
        var b = new StorageWriterObservation(StorageTestData.Node("b"), StorageTestData.Attachment("b"), StorageTestData.Epoch(8));
        StorageDecision Plan(IEnumerable<StorageWriterObservation> writers) => StorageAttachmentPlanner.Plan(
            StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("c"),
            new StorageReattachEvidence(StorageTestData.Scope(), writers, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
                StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(9), 4));
        await Assert.That(Plan([a, b])).IsEqualTo(Plan([b, a]));
    }
}

