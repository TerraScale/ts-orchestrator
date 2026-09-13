using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class StoragePlannerPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Create_and_format_planners_match_exact_independent_action_target_code_oracles()
    {
        var failures = new List<string>();
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var requested = 10_000L + seed;
                var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
                var evidence = StorageTestData.Format(scope: volume.EvidenceScope);
                var checkpoint = (StorageCreateCheckpoint)(1 + seed % 10);
                var expected = CreateExpected(checkpoint);
                SetCultures("en-US");
                var first = StorageCreatePlanner.Plan(volume, StorageTestData.Context(), checkpoint, evidence);
                var firstRendering = first.ToString();
                SetCultures((seed % 3) switch { 0 => "tr-TR", 1 => "ar-SA", _ => "ja-JP" });
                var replay = StorageCreatePlanner.Plan(volume, StorageTestData.Context(), checkpoint, evidence);
                Require(first, expected, volume, StorageTestData.Epoch(), StorageConflictClass.None, seed, "create", failures);
                if (first != replay || !StringComparer.Ordinal.Equals(firstRendering, replay.ToString()))
                    failures.Add($"create-replay:{seed}");

                var formatCase = seed % 6;
                var formatEvidence = formatCase switch
                {
                    0 => StorageTestData.Format(provider: StorageProof.Unknown, scope: volume.EvidenceScope),
                    1 => StorageTestData.Format(classification: StorageDeviceClassification.Recognized, scope: volume.EvidenceScope),
                    2 => StorageTestData.Format(classification: StorageDeviceClassification.Recognized, filesystem: StorageProof.Unknown, scope: volume.EvidenceScope),
                    3 => StorageTestData.Format(classification: StorageDeviceClassification.Unknown, scope: volume.EvidenceScope),
                    4 => StorageTestData.Format(blank: StorageProof.Unknown, scope: volume.EvidenceScope),
                    _ => evidence,
                };
                var formatExpected = formatCase switch
                {
                    0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongProviderVolume),
                    1 => E(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.RecognizedVolumeNeverFormats),
                    2 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongOwner),
                    3 => E(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
                    4 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.BlankProofRequired),
                    _ => E(StorageAction.Format, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
                };
                SetCultures("en-US");
                var firstFormat = StorageFormatPlanner.Plan(volume, StorageTestData.Context(), formatEvidence);
                var firstFormatRendering = firstFormat.ToString();
                SetCultures((seed % 3) switch { 0 => "ja-JP", 1 => "tr-TR", _ => "ar-SA" });
                var replayFormat = StorageFormatPlanner.Plan(volume, StorageTestData.Context(), formatEvidence);
                Require(firstFormat, formatExpected, volume, StorageTestData.Epoch(), StorageConflictClass.None, seed, "format", failures);
                if (firstFormat != replayFormat || !StringComparer.Ordinal.Equals(firstFormatRendering, replayFormat.ToString()))
                    failures.Add($"format-replay:{seed}");
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Attachment_planner_matches_single_writer_fencing_and_recovery_oracle_under_permutation()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 20_000L + seed;
            var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
            var current = new StorageWriterObservation(StorageTestData.Node($"old-{seed}"), StorageTestData.Attachment(), StorageTestData.Epoch());
            var second = new StorageWriterObservation(StorageTestData.Node($"other-{seed}"), StorageTestData.Attachment($"other-{seed}"), StorageTestData.Epoch(8));
            var target = seed % 10 is 4 or 5 ? current.Node : StorageTestData.Node($"new-{seed}");
            var variant = seed % 10;
            var writers = variant == 0
                ? (seed % 2 == 0 ? new[] { current, second } : new[] { second, current })
                : variant >= 4 ? new[] { current } : [];
            var evidence = new StorageReattachEvidence(volume.EvidenceScope, writers,
                variant >= 7 ? StorageProof.Proven : StorageProof.Unknown,
                variant >= 7 ? StorageProof.Proven : StorageProof.Unknown,
                variant is 2 or 3 or 8 or 9 ? StorageProof.Proven : StorageProof.Unknown,
                variant == 5 ? StorageProof.Proven : StorageProof.Unknown,
                StorageProof.Proven, StorageTestData.Epoch(variant is 3 or 9 ? 8UL : 7UL), 4);
            var expected = variant switch
            {
                0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DualWriter),
                1 => E(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
                2 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.NewWriterEpochRequired),
                3 => E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
                4 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.HealthVerificationRequired),
                5 => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed),
                6 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.ReattachProofMissing),
                7 => E(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
                8 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.NewWriterEpochRequired),
                _ => E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
            };
            var decision = StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), target, evidence);
            Require(decision, expected, volume, decision.Action == StorageAction.Attach ? StorageTestData.Epoch(8) : StorageTestData.Epoch(),
                StorageConflictClass.None, seed, "attach", failures, decision.Action == StorageAction.Attach ? target : null);
            if (decision.Action == StorageAction.Attach && decision.Trace?.Epoch != StorageTestData.Epoch(8))
                failures.Add($"attach-epoch:{seed}");
            if (variant == 0)
            {
                var reverse = new StorageReattachEvidence(volume.EvidenceScope, writers.Reverse(),
                    StorageProof.Unknown, StorageProof.Unknown, StorageProof.Unknown, StorageProof.Unknown,
                    StorageProof.Proven, StorageTestData.Epoch(), 4);
                if (StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), target, reverse) != decision)
                    failures.Add($"attach-permutation:{seed}");
            }
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Expansion_and_crash_recovery_match_first_unproven_step_and_never_repeat_irreversible_work()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 30_000L + seed;
            var stage = seed % 13;
            var (volume, evidence, expected) = ExpansionCase(stage, requested);
            var first = StorageExpansionPlanner.Plan(volume, StorageTestData.Context(), evidence);
            var replay = StorageExpansionPlanner.Plan(volume, StorageTestData.Context(), evidence);
            Require(first, expected, volume, StorageTestData.Epoch(),
                stage == 11 ? StorageConflictClass.BackupRestore : StorageConflictClass.None, seed, "expand", failures);
            if (first != replay) failures.Add($"expand-replay:{seed}");
            if (stage == 12 && first.Action == StorageAction.Extend) failures.Add($"expand-duplicate:{seed}");
            if (first.Trace is not { } trace || trace.Provider.Value != volume.ProviderBytes.Value ||
                trace.Block.Value != volume.BlockBytes.Value || trace.Filesystem.Value != volume.FilesystemBytes.Value ||
                trace.Performance != volume.Performance)
                failures.Add($"expand-trace:{seed}");
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Every_authorized_reattach_subject_names_the_requested_target_node_exactly()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 25_000L + seed;
            var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
            var target = StorageTestData.Node($"target-{seed}");
            var evidence = new StorageReattachEvidence(volume.EvidenceScope, [], StorageProof.Proven,
                StorageProof.Proven, StorageProof.Proven, StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 4);
            var decision = StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), target, evidence);
            Require(decision, E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
                volume, StorageTestData.Epoch(8), StorageConflictClass.None, seed, "attach-target", failures, target);
            if (decision.Scope?.Node == volume.Node) failures.Add($"attach-old-node:{seed}");
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Deletion_retention_and_post_delete_recovery_precedence_match_exact_oracle()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 40_000L + seed;
            var variant = seed % 10;
            var retention = variant == 0 ? StorageRetention.Permanent :
                variant == 3 ? StorageRetention.ExplicitDisposable : StorageRetention.ElasticQuarantine;
            var volume = StorageTestData.Volume(requested: requested, retention: retention,
                performance: Performance(requested), forecast: requested + 7);
            var context = variant == 9 ? StorageTestData.Context(generation: StorageTestData.Generation(99)) : StorageTestData.Context();
            var scope = variant == 8
                ? volume.EvidenceScope with { Operation=StorageTestData.Operation($"other-{seed}") }
                : volume.EvidenceScope;
            var evidence = StorageTestData.Deletion(
                leadership: variant == 1 ? StorageProof.Unknown : StorageProof.Proven,
                quarantine: variant == 2 ? StorageProof.Unknown : StorageProof.Proven,
                disposable: variant == 3 ? StorageProof.Unknown : StorageProof.Proven,
                requested: variant >= 5 && variant <= 7 ? StorageProof.Proven : StorageProof.Unknown,
                absent: variant >= 6 && variant <= 7 ? StorageProof.Proven : StorageProof.Unknown,
                auditPassed: variant == 7 ? StorageProof.Proven : StorageProof.Unknown,
                scopeRetention: retention, scope: scope);
            var expected = variant switch
            {
                0 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.PermanentRetention),
                1 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DeletionProofMissing),
                2 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.QuarantineProofMissing),
                3 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.DisposableProofMissing),
                4 => E(StorageAction.Delete, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
                5 => E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending),
                6 => E(StorageAction.Observe, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.PostDeleteAuditRequired),
                7 => E(StorageAction.Verify, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.Completed),
                8 => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongEvidenceScope),
                _ => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.StaleGeneration),
            };
            var first = StorageDeletionPlanner.Plan(volume, context, evidence);
            Require(first, expected, volume, StorageTestData.Epoch(), StorageConflictClass.None, seed, "delete", failures);
            if (first != StorageDeletionPlanner.Plan(volume, context, evidence)) failures.Add($"delete-replay:{seed}");
            if (variant >= 5 && first.Action == StorageAction.Delete) failures.Add($"delete-duplicate:{seed}");
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Every_planner_rejects_the_exact_authority_or_evidence_scope_dimension_before_mutation()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 50_000L + seed;
            var dimension = seed % 9;
            var context = dimension switch
            {
                0 => StorageTestData.Context(provider: StorageTestData.Provider($"p-{seed}")),
                1 => StorageTestData.Context(claim: StorageTestData.Claim($"c-{seed}")),
                2 => StorageTestData.Context(cell: StorageTestData.Cell($"c-{seed}")),
                3 => StorageTestData.Context(workload: StorageTestData.Workload($"w-{seed}")),
                4 => StorageTestData.Context(member: StorageTestData.Member($"m-{seed}")),
                5 => StorageTestData.Context(fence: StorageTestData.Fence($"f-{seed}")),
                6 => StorageTestData.Context(generation: StorageTestData.Generation((ulong)(100 + seed))),
                7 => StorageTestData.Context(epoch: StorageTestData.Epoch((ulong)(100 + seed))),
                _ => StorageTestData.Context(),
            };
            var expectedCode = dimension switch
            {
                0 => StorageDecisionCode.WrongProviderVolume,
                1 or 2 or 3 or 4 => StorageDecisionCode.WrongOwner,
                5 => StorageDecisionCode.WrongFence,
                6 => StorageDecisionCode.StaleGeneration,
                7 => StorageDecisionCode.StaleWriterEpoch,
                _ => StorageDecisionCode.WrongEvidenceScope,
            };
            var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
            var scope = dimension == 8
                ? volume.EvidenceScope with { Operation=StorageTestData.Operation($"op-{seed}") }
                : volume.EvidenceScope;
            StorageDecision decision = (seed % 5) switch
            {
                0 => StorageCreatePlanner.Plan(volume, context, StorageCreateCheckpoint.CapacityAndBudgetChecked, StorageTestData.Format(scope: scope)),
                1 => StorageFormatPlanner.Plan(volume, context, StorageTestData.Format(scope: scope)),
                2 => StorageAttachmentPlanner.Plan(volume, context, StorageTestData.Node($"n-{seed}"),
                    new StorageReattachEvidence(scope, [], StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
                        StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 4)),
                3 => StorageExpansionPlanner.Plan(volume, context, StorageTestData.Expansion(scope: scope)),
                _ => StorageDeletionPlanner.Plan(volume, context, StorageTestData.Deletion(scope: scope)),
            };
            Require(decision, E(StorageAction.Hold, StorageIntentTarget.None, expectedCode), volume, StorageTestData.Epoch(),
                StorageConflictClass.None, seed, "scope", failures);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Evidence_scope_replay_is_bound_to_every_identity_generation_epoch_capacity_and_retention_field()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 55_000L + seed;
            var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
            var scope = volume.EvidenceScope;
            scope = (seed % 26) switch
            {
                0 => scope with { Claim = StorageTestData.Claim($"c-{seed}") },
                1 => scope with { ProviderVolume = StorageTestData.Provider($"p-{seed}") },
                2 => scope with { Attachment = StorageTestData.Attachment($"a-{seed}") },
                3 => scope with { Cell = StorageTestData.Cell($"c-{seed}") },
                4 => scope with { Node = StorageTestData.Node($"n-{seed}") },
                5 => scope with { Workload = StorageTestData.Workload($"w-{seed}") },
                6 => scope with { Member = StorageTestData.Member($"m-{seed}") },
                7 => scope with { DeviceId = StorageTestData.Device($"d-{seed}") },
                8 => scope with { FilesystemId = StorageTestData.Filesystem($"fs-{seed}") },
                9 => scope with { FilesystemType = StorageFilesystemType.Ext4 },
                10 => scope with { Layout = StorageLayout.WholeDevice },
                11 => scope with { RequestedBytes = StorageTestData.B(requested + 1) },
                12 => scope with { ObservedBytes = StorageTestData.B(scope.ObservedBytes.Value + 1) },
                13 => scope with { ProviderBytes = StorageTestData.B(scope.ProviderBytes.Value + 1) },
                14 => scope with { BlockBytes = StorageTestData.B(scope.BlockBytes.Value + 1) },
                15 => scope with { FilesystemBytes = StorageTestData.B(scope.FilesystemBytes.Value + 1) },
                16 => scope with { UsedBytes = StorageTestData.B(scope.UsedBytes.Value + 1) },
                17 => scope with { FreeBytes = StorageTestData.B(scope.FreeBytes.Value + 1) },
                18 => scope with { Performance = Performance(requested + 1) },
                19 => scope with { ForecastExhaustion = StorageTestData.B(scope.ForecastExhaustion.Value + 1) },
                20 => scope with { Retention = StorageRetention.Permanent },
                21 => scope with { Backup = StorageTestData.Backup($"b-{seed}") },
                22 => scope with { Operation = StorageTestData.Operation($"op-{seed}") },
                23 => scope with { Fence = StorageTestData.Fence($"f-{seed}") },
                24 => scope with { Generation = StorageTestData.Generation((ulong)(100 + seed)) },
                _ => scope with { WriterEpoch = StorageTestData.Epoch((ulong)(100 + seed)) },
            };
            var decision = (seed % 5) switch
            {
                0 => StorageCreatePlanner.Plan(volume, StorageTestData.Context(), StorageCreateCheckpoint.CapacityAndBudgetChecked,
                    StorageTestData.Format(scope: scope)),
                1 => StorageFormatPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Format(scope: scope)),
                2 => StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Node($"target-{seed}"),
                    new StorageReattachEvidence(scope, [], StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
                        StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 4)),
                3 => StorageExpansionPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Expansion(scope: scope)),
                _ => StorageDeletionPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Deletion(scope: scope)),
            };
            Require(decision, E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.WrongEvidenceScope), volume,
                StorageTestData.Epoch(), StorageConflictClass.None, seed, "evidence-scope", failures);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Undefined_and_contradicted_proofs_never_authorize_attach_detach_or_delete()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var requested = 58_000L + seed;
            var volume = StorageTestData.Volume(requested: requested, performance: Performance(requested), forecast: requested + 7);
            var proof = seed % 2 == 0 ? (StorageProof)99 : StorageProof.Contradicted;
            var expectedCode = proof == StorageProof.Contradicted ? StorageDecisionCode.StepContradicted : StorageDecisionCode.InvalidInput;
            StorageDecision decision;
            if (seed % 3 == 0)
            {
                decision = StorageDeletionPlanner.Plan(volume, StorageTestData.Context(),
                    DeletionWithProof(seed % 13, proof, volume.EvidenceScope));
            }
            else
            {
                decision = StorageAttachmentPlanner.Plan(volume, StorageTestData.Context(), StorageTestData.Node($"proof-target-{seed}"),
                    ReattachWithProof(seed % 5, proof, volume.EvidenceScope));
            }
            Require(decision, E(StorageAction.Hold, StorageIntentTarget.None, expectedCode), volume, StorageTestData.Epoch(),
                StorageConflictClass.None, seed, "proof-catalog", failures);
            if (decision.Action is StorageAction.Attach or StorageAction.Detach or StorageAction.Delete)
                failures.Add($"proof-mutation:{seed}");
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Writer_enumeration_is_technically_bounded_before_extra_current_and_is_secret_safe()
    {
        var nullWriters = new StorageReattachEvidence(StorageTestData.Scope(), null, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), 1);
        await Assert.That(nullWriters.IsWellFormed).IsTrue();
        await Assert.That(nullWriters.Writers).IsEmpty();

        var exact = Enumerable.Range(0, StorageTechnicalInputLimits.MaximumWriterObservationCount)
            .Select(index => new StorageWriterObservation(StorageTestData.Node($"n{index}"), StorageTestData.Attachment($"a{index}"), StorageTestData.Epoch()));
        var accepted = new StorageReattachEvidence(StorageTestData.Scope(), exact, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), int.MaxValue);
        await Assert.That(accepted.IsWellFormed).IsTrue();
        await Assert.That(accepted.Writers.Count).IsEqualTo(StorageTechnicalInputLimits.MaximumWriterObservationCount);

        var oversized = new BoundaryWriters(StorageTechnicalInputLimits.MaximumWriterObservationCount + 1);
        var rejected = new StorageReattachEvidence(StorageTestData.Scope(), oversized, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), int.MaxValue);
        await Assert.That(rejected.IsWellFormed).IsFalse();
        await Assert.That(rejected.Writers).IsEmpty();
        await Assert.That(oversized.ExtraCurrentRead).IsFalse();

        var endless = new EndlessWriters();
        var endlessEvidence = new StorageReattachEvidence(StorageTestData.Scope(), endless, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), int.MaxValue);
        await Assert.That(endlessEvidence.IsWellFormed).IsFalse();
        await Assert.That(endless.CurrentReads).IsEqualTo(StorageTechnicalInputLimits.MaximumWriterObservationCount);

        var businessBound = new BoundaryWriters(3);
        var businessRejected = new StorageReattachEvidence(StorageTestData.Scope(), businessBound, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), 2);
        await Assert.That(businessRejected.IsWellFormed).IsFalse();
        await Assert.That(businessBound.CurrentReads).IsEqualTo(2);

        var disposeMutation = new DisposeMutationWriters();
        var disposeCaptured = new StorageReattachEvidence(StorageTestData.Scope(), disposeMutation, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), 2);
        await Assert.That(disposeMutation.Disposed).IsTrue();
        await Assert.That(disposeMutation.BackingCount).IsEqualTo(0);
        await Assert.That(disposeCaptured.Writers.Single().Node).IsEqualTo(StorageTestData.Node("before-dispose"));

        foreach (var phase in Enum.GetValues<EnumerationPhase>())
        {
            var ordinary = new PhaseThrowingWriters(phase, new InvalidOperationException("storage-secret"));
            var ordinaryEvidence = new StorageReattachEvidence(StorageTestData.Scope(), ordinary, StorageProof.Proven, StorageProof.Proven,
                StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageTestData.Epoch(8), int.MaxValue);
            await Assert.That(ordinaryEvidence.IsWellFormed).IsFalse();
            await Assert.That(ordinaryEvidence.ToString()).DoesNotContain("storage-secret");
            foreach (var fatal in new Exception[] { new OutOfMemoryException(), new StackOverflowException(), new AccessViolationException() })
                await Assert.That(Capture(() => new StorageReattachEvidence(StorageTestData.Scope(), new PhaseThrowingWriters(phase, fatal),
                    StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
                    StorageProof.Proven, StorageTestData.Epoch(8), int.MaxValue))?.GetType()).IsEqualTo(fatal.GetType());
        }
    }

    [Test]
    public async Task Accepted_storage_decisions_traces_and_intent_subjects_reuse_construction_closure()
    {
        foreach (var type in new[] { typeof(StorageDecision), typeof(StorageNumericTrace), typeof(StorageIntentScope) })
        {
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
            await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(method => method.ReturnType == type)).IsEmpty();
        }

        await Assert.That(typeof(StorageIntentScope).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(static property => property.Name).ToArray()).IsEquivalentTo(new[]
            {
                nameof(StorageIntentScope.Claim), nameof(StorageIntentScope.ProviderVolume),
                nameof(StorageIntentScope.Attachment), nameof(StorageIntentScope.Cell), nameof(StorageIntentScope.Node),
                nameof(StorageIntentScope.Workload), nameof(StorageIntentScope.Member), nameof(StorageIntentScope.Domain),
                nameof(StorageIntentScope.EncryptionKey), nameof(StorageIntentScope.Placement), nameof(StorageIntentScope.DeviceId),
                nameof(StorageIntentScope.FilesystemId), nameof(StorageIntentScope.FilesystemType), nameof(StorageIntentScope.Layout),
                nameof(StorageIntentScope.MountPurpose),
                nameof(StorageIntentScope.Retention), nameof(StorageIntentScope.Backup),
                nameof(StorageIntentScope.Operation), nameof(StorageIntentScope.Fence),
            });
    }

    private static (StorageAction Action, StorageIntentTarget Target, StorageDecisionCode Code) CreateExpected(StorageCreateCheckpoint checkpoint) => checkpoint switch
    {
        StorageCreateCheckpoint.ClaimAccepted => E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.CapacityAndBudgetChecked => E(StorageAction.Create, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.VolumeCreated => E(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.AttachmentCreated => E(StorageAction.Verify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.DeviceIdentityVerified => E(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.Classified => E(StorageAction.Format, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.FormattedIfNew => E(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.Mounted => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep),
        StorageCreateCheckpoint.OwnershipAndPerformanceVerified or StorageCreateCheckpoint.Ready => E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed),
        _ => E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.InvalidInput),
    };

    private static (StorageVolumeRecord, StorageExpansionEvidence, (StorageAction, StorageIntentTarget, StorageDecisionCode)) ExpansionCase(int stage, long requested)
    {
        var performance = Performance(requested);
        var baseVolume = StorageTestData.Volume(requested: requested, performance: performance, forecast: requested + 7);
        var grown = StorageTestData.Volume(requested: requested, provider: requested, block: requested,
            filesystem: requested, used: requested / 2, free: requested - requested / 2,
            performance: performance, forecast: requested + 7);
        var providerGrown = StorageTestData.Volume(requested: requested, provider: requested,
            performance: performance, forecast: requested + 7);
        var deviceGrown = StorageTestData.Volume(requested: requested, provider: requested, block: requested,
            performance: performance, forecast: requested + 7);
        return stage switch
        {
            0 => (baseVolume, StorageTestData.Expansion(volume: baseVolume), E(StorageAction.Observe, StorageIntentTarget.None, StorageDecisionCode.NextStep)),
            1 => (baseVolume, StorageTestData.Expansion(intent: StorageProof.Proven, volume: baseVolume), E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep)),
            2 => (baseVolume, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: baseVolume), E(StorageAction.Extend, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep)),
            3 => (baseVolume, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: baseVolume), E(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending)),
            4 => (providerGrown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: providerGrown), E(StorageAction.Rescan, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep)),
            5 => (deviceGrown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: deviceGrown), E(StorageAction.Extend, StorageIntentTarget.StorageLayout, StorageDecisionCode.NextStep)),
            6 => (deviceGrown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: deviceGrown), E(StorageAction.Grow, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep)),
            7 => (grown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: grown), E(StorageAction.Verify, StorageIntentTarget.Filesystem, StorageDecisionCode.SizeDisagreement)),
            8 => (grown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: grown), E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep)),
            9 => (grown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: grown), E(StorageAction.Observe, StorageIntentTarget.MetricsAndCost, StorageDecisionCode.NextStep)),
            10 => (grown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: grown), E(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed)),
            11 => (baseVolume, StorageTestData.Expansion(conflicts: StorageConflictClass.BackupRestore, volume: baseVolume), E(StorageAction.Hold, StorageIntentTarget.None, StorageDecisionCode.ConflictingOperation)),
            _ => (providerGrown, StorageTestData.Expansion(StorageProof.Proven, StorageProof.Proven, StorageProof.Proven, volume: providerGrown), E(StorageAction.Verify, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep)),
        };
    }

    private static StorageReattachEvidence ReattachWithProof(int field, StorageProof proof, StorageEvidenceScope scope) =>
        new(scope, [], field == 0 ? proof : StorageProof.Proven, field == 1 ? proof : StorageProof.Proven,
            field == 2 ? proof : StorageProof.Proven, field == 3 ? proof : StorageProof.Proven,
            field == 4 ? proof : StorageProof.Proven, StorageTestData.Epoch(8), 4);

    private static StorageDeletionEvidence DeletionWithProof(int field, StorageProof proof, StorageEvidenceScope scope) =>
        StorageTestData.Deletion(
            leadership: field == 0 ? proof : StorageProof.Proven,
            topology: field == 1 ? proof : StorageProof.Proven,
            quorum: field == 2 ? proof : StorageProof.Proven,
            noReference: field == 3 ? proof : StorageProof.Proven,
            backup: field == 4 ? proof : StorageProof.Proven,
            retention: field == 5 ? proof : StorageProof.Proven,
            ownerFence: field == 6 ? proof : StorageProof.Proven,
            quarantine: field == 7 ? proof : StorageProof.Proven,
            disposable: field == 8 ? proof : StorageProof.Proven,
            auditReady: field == 9 ? proof : StorageProof.Proven,
            requested: field == 10 ? proof : StorageProof.Unknown,
            absent: field == 11 ? proof : StorageProof.Unknown,
            auditPassed: field == 12 ? proof : StorageProof.Unknown,
            scope: scope);

    private static void Require(StorageDecision actual, (StorageAction Action, StorageIntentTarget Target, StorageDecisionCode Code) expected,
        StorageVolumeRecord volume, StorageWriterEpoch expectedEpoch, StorageConflictClass expectedConflicts,
        int seed, string family, List<string> failures, StorageNodeId? expectedNode = null)
    {
        var expectedMutation = expected.Action is StorageAction.Create or StorageAction.Attach or StorageAction.Format or
            StorageAction.Mount or StorageAction.Rescan or StorageAction.Extend or StorageAction.Grow or StorageAction.Detach or StorageAction.Delete;
        var trace = actual.Trace;
        var scope = trace?.Scope;
        if (actual.Action != expected.Action || actual.Target != expected.Target || actual.Code != expected.Code ||
            actual.IsMutationAuthorized != expectedMutation || trace is null ||
            trace.Observed != volume.ObservedBytes || trace.Requested != volume.RequestedBytes ||
            trace.Provider != volume.ProviderBytes || trace.Block != volume.BlockBytes ||
            trace.Filesystem != volume.FilesystemBytes || trace.Used != volume.UsedBytes || trace.Free != volume.FreeBytes ||
            trace.ForecastExhaustion != volume.ForecastExhaustion || trace.Generation != volume.Generation ||
            trace.Epoch != expectedEpoch || trace.Performance != volume.Performance || trace.Conflicts != expectedConflicts ||
            scope is null || scope.Claim != volume.Claim || scope.ProviderVolume != volume.ProviderVolume ||
            scope.Attachment != volume.Attachment || scope.Cell != volume.Cell || scope.Node != (expectedNode ?? volume.Node) ||
            scope.Workload != volume.Workload || scope.Member != volume.Member || scope.DeviceId != volume.DeviceId ||
            scope.Domain != volume.Domain || !ReferenceEquals(scope.EncryptionKey, volume.EncryptionKey) ||
            !ReferenceEquals(scope.Placement, volume.Placement) || scope.MountPurpose != volume.MountPurpose ||
            scope.FilesystemId != volume.FilesystemId || scope.FilesystemType != volume.FilesystemType ||
            scope.Layout != volume.Layout || scope.Retention != volume.Retention ||
            !ReferenceEquals(scope.Backup, volume.Backup) || scope.Operation != volume.Operation || scope.Fence != volume.WriterFence)
            failures.Add($"{family}:{seed}:{expected}:{actual}");
    }

    private static (StorageAction, StorageIntentTarget, StorageDecisionCode) E(StorageAction action, StorageIntentTarget target, StorageDecisionCode code) => (action, target, code);
    private static void SetCultures(string name)
    {
        var culture = CultureInfo.GetCultureInfo(name);
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }
    private static StoragePerformance Performance(long seed) => new(
        seed % 2 == 0 ? StoragePerformanceTier.Balanced : StoragePerformanceTier.HighPerformance,
        StorageTestData.B(10 + seed % 17), StorageTestData.B(1_000 + seed), StorageTestData.B(200 + seed % 101),
        StorageTestData.B(2 + seed % 7), StorageTestData.B(900 + seed % 97),
        StorageTestData.B(180 + seed % 83), StorageTestData.B(10 + seed % 5));
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }

    private sealed class BoundaryWriters(int count) : IEnumerable<StorageWriterObservation?>
    {
        public bool ExtraCurrentRead { get; private set; }
        public int CurrentReads { get; private set; }
        public IEnumerator<StorageWriterObservation?> GetEnumerator() => new Enumerator(this, count);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(BoundaryWriters owner, int count) : IEnumerator<StorageWriterObservation?>
        {
            private int _index = -1;
            public StorageWriterObservation? Current
            {
                get
                {
                    owner.CurrentReads++;
                    if (_index == StorageTechnicalInputLimits.MaximumWriterObservationCount) owner.ExtraCurrentRead = true;
                    return new(StorageTestData.Node($"bn{_index}"), StorageTestData.Attachment($"ba{_index}"), StorageTestData.Epoch());
                }
            }
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext() => ++_index < count;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { }
        }
    }

    private sealed class EndlessWriters : IEnumerable<StorageWriterObservation?>
    {
        public int CurrentReads { get; private set; }
        public IEnumerator<StorageWriterObservation?> GetEnumerator() => new Enumerator(this);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(EndlessWriters owner) : IEnumerator<StorageWriterObservation?>
        {
            private int _index;
            public StorageWriterObservation? Current
            {
                get { owner.CurrentReads++; return new(StorageTestData.Node($"en{_index}"), StorageTestData.Attachment($"ea{_index}"), StorageTestData.Epoch()); }
            }
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext() { _index++; return true; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { }
        }
    }

    private sealed class DisposeMutationWriters : IEnumerable<StorageWriterObservation?>
    {
        private readonly List<StorageWriterObservation?> _backing =
            [new(StorageTestData.Node("before-dispose"), StorageTestData.Attachment(), StorageTestData.Epoch())];
        public bool Disposed { get; private set; }
        public int BackingCount => _backing.Count;
        public IEnumerator<StorageWriterObservation?> GetEnumerator() => new Enumerator(this);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(DisposeMutationWriters owner) : IEnumerator<StorageWriterObservation?>
        {
            private int _index = -1;
            public StorageWriterObservation? Current => owner._backing[_index];
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext() => ++_index == 0;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { owner.Disposed = true; owner._backing.Clear(); }
        }
    }

    private enum EnumerationPhase { GetEnumerator, MoveNext, Current, Dispose }

    private sealed class PhaseThrowingWriters(EnumerationPhase phase, Exception exception) : IEnumerable<StorageWriterObservation?>
    {
        public IEnumerator<StorageWriterObservation?> GetEnumerator() => phase == EnumerationPhase.GetEnumerator
            ? throw exception : new Enumerator(phase, exception);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(EnumerationPhase phase, Exception exception) : IEnumerator<StorageWriterObservation?>
        {
            private bool _moved;
            public StorageWriterObservation? Current => phase == EnumerationPhase.Current
                ? throw exception : new(StorageTestData.Node("phase"), StorageTestData.Attachment(), StorageTestData.Epoch());
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext()
            {
                if (phase == EnumerationPhase.MoveNext) throw exception;
                return !_moved && (_moved = true);
            }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (phase == EnumerationPhase.Dispose) throw exception; }
        }
    }
}

