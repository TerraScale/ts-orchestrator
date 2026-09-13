using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StoragePropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Generated_authority_variants_fail_on_the_independently_selected_exact_dimension()
    {
        var failures = new List<string>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var dimension = seed % 6;
            var context = dimension switch
            {
                0 => StorageTestData.Context(provider: StorageTestData.Provider($"provider-{seed}")),
                1 => StorageTestData.Context(claim: StorageTestData.Claim($"claim-{seed}")),
                2 => StorageTestData.Context(fence: StorageTestData.Fence($"fence-{seed}")),
                3 => StorageTestData.Context(generation: StorageTestData.Generation((ulong)(seed + 10))),
                4 => StorageTestData.Context(epoch: StorageTestData.Epoch((ulong)(seed + 10))),
                _ => StorageTestData.Context(member: StorageTestData.Member($"member-{seed}")),
            };
            var expected = dimension switch
            {
                0 => StorageDecisionCode.WrongProviderVolume,
                1 or 5 => StorageDecisionCode.WrongOwner,
                2 => StorageDecisionCode.WrongFence,
                3 => StorageDecisionCode.StaleGeneration,
                _ => StorageDecisionCode.StaleWriterEpoch,
            };
            var actual = StorageExpansionPlanner.Plan(StorageTestData.Volume(), context, StorageTestData.Expansion());
            if (actual.Code != expected || actual.IsMutationAuthorized) failures.Add($"{seed}:{expected}:{actual.Code}");
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_capacity_arithmetic_matches_an_independent_checked_oracle_and_replays()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var filesystem = 1_000L + seed;
            var requested = seed % 4 == 0 ? filesystem - 1 : filesystem + 100;
            var used = seed % 5 == 0 ? long.MaxValue : filesystem / 2;
            var free = seed % 5 == 0 ? 1 : filesystem - used;
            var expected = requested < filesystem
                ? StorageDecisionCode.ShrinkForbidden
                : seed % 5 == 0 ? StorageDecisionCode.ArithmeticOverflow : StorageDecisionCode.NextStep;
            var volume = StorageTestData.Volume(requested: requested, filesystem: filesystem, used: used, free: free);
            var evidence = StorageTestData.Expansion(volume: volume);
            var first = StorageExpansionPlanner.Plan(volume, StorageTestData.Context(), evidence);
            var replay = StorageExpansionPlanner.Plan(volume, StorageTestData.Context(), evidence);
            if (first.Code != expected || first != replay || (expected != StorageDecisionCode.NextStep && first.IsMutationAuthorized))
                failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_deletion_proof_matrix_never_authorizes_without_every_independent_gate()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var missing = seed % 8;
            var evidence = StorageTestData.Deletion(
                leadership: missing == 0 ? StorageProof.Unknown : StorageProof.Proven,
                topology: missing == 1 ? StorageProof.Unknown : StorageProof.Proven,
                quorum: missing == 2 ? StorageProof.Unknown : StorageProof.Proven,
                noReference: missing == 3 ? StorageProof.Unknown : StorageProof.Proven,
                backup: missing == 4 ? StorageProof.Unknown : StorageProof.Proven,
                retention: missing == 5 ? StorageProof.Unknown : StorageProof.Proven,
                ownerFence: missing == 6 ? StorageProof.Unknown : StorageProof.Proven,
                auditReady: missing == 7 ? StorageProof.Unknown : StorageProof.Proven);
            var decision = StorageDeletionPlanner.Plan(StorageTestData.Volume(), StorageTestData.Context(), evidence);
            if (decision.Code != StorageDecisionCode.DeletionProofMissing || decision.IsMutationAuthorized) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_complete_deletion_decisions_are_culture_and_replay_deterministic()
    {
        var failures = new List<int>();
        var original = CultureInfo.CurrentCulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var volume = StorageTestData.Volume(requested: 200 + seed);
                var context = StorageTestData.Context();
                var deletion = StorageTestData.Deletion(scope: StorageTestData.Scope(requested: 200 + seed));
                CultureInfo.CurrentCulture = new("tr-TR");
                var first = StorageDeletionPlanner.Plan(volume, context, deletion);
                CultureInfo.CurrentCulture = new("ar-SA");
                var replay = StorageDeletionPlanner.Plan(volume, context, deletion);
                if (first != replay || first.Action != StorageAction.Delete || first.Trace?.Generation != StorageTestData.Generation())
                    failures.Add(seed);
            }
        }
        finally { CultureInfo.CurrentCulture = original; }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Storage_accepted_outputs_and_observable_catalogs_are_construction_closed()
    {
        await Assert.That(typeof(StorageDecision).GetConstructors().Length).IsEqualTo(0);
        await Assert.That(typeof(StorageNumericTrace).GetConstructors().Length).IsEqualTo(0);
        foreach (var type in new[] { typeof(StorageAction), typeof(StorageDecisionCode), typeof(StorageProof),
                     typeof(StorageRetention), typeof(StorageFilesystemType), typeof(StorageLayout) })
            await Assert.That(Enum.GetValues(type).Cast<object>().All(value => Enum.IsDefined(type, value))).IsTrue();
    }

    [Test]
    public async Task Storage_action_numeric_contract_is_exact_and_append_only()
    {
        var actions = Enum.GetValues<StorageAction>();
        var expected = new[]
        {
            StorageAction.Uninitialized,StorageAction.Observe,StorageAction.Create,StorageAction.Attach,
            StorageAction.Classify,StorageAction.Format,StorageAction.Mount,StorageAction.Rescan,
            StorageAction.Extend,StorageAction.Grow,StorageAction.Verify,StorageAction.Detach,
            StorageAction.Delete,StorageAction.Hold,
        };
        await Assert.That(actions.Length).IsEqualTo(14);
        for (var index = 0; index < expected.Length; index++)
        {
            await Assert.That(actions[index]).IsEqualTo(expected[index]);
            await Assert.That((int)actions[index]).IsEqualTo(index);
        }
    }
}

