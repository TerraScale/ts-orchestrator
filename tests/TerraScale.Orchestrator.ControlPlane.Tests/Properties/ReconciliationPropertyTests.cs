using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ReconciliationPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Dependency_order_trace_and_exact_subjects_follow_independent_oracle_for_1000_cases()
    {
        var distinct = new HashSet<string>(StringComparer.Ordinal);
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var graph = ReconciliationData.Graph(seed);
            var plan = ReconciliationData.Plan(graph, graph.Select(ReconciliationData.Exact));
            var expected = new[] { $"a-root-{seed:D4}", $"b-peer-{seed:D4}", $"c-middle-{seed:D4}", $"d-leaf-{seed:D4}" };
            Require(plan.Errors.Count == 0, seed, "valid graph");
            Require(plan.Steps.Select(step => step.Desired.Identity.Value).SequenceEqual(expected), seed, "topological order");
            Require(plan.Steps.Select(step => step.Order).SequenceEqual([1, 2, 3, 4]), seed, "step sequence");
            Require(plan.Trace.Select(trace => trace.Sequence).SequenceEqual([1, 2, 3, 4]), seed, "trace sequence");
            foreach (var step in plan.Steps)
            {
                var output = step.Output;
                Require(output is ConvergedResource && output.Identity == step.Desired.Identity &&
                    output.Kind == step.Desired.Kind && output.Generation == step.Desired.Generation &&
                    output.Digest == step.Desired.Digest, seed, "exact converged subject");
                Require(step.Trace.Count == 1 && step.Trace[0] == plan.Trace[step.Order - 1] &&
                    step.Trace[0].Resource == step.Desired.Identity &&
                    step.Trace[0].Reason == ReconciliationReasonCode.ExactConvergence &&
                    step.Trace[0].RelatedResource is null, seed, "exact trace");
                distinct.Add(output.Identity.Value);
            }
        }

        await Assert.That(distinct.Count).IsEqualTo(Cases * 4);
    }

    [Test]
    public async Task Observation_generation_and_condition_precedence_follow_exact_oracle_for_1000_cases()
    {
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 8);
            var (plan, target) = ReconciliationData.ObservationCase(seed, variant);
            var step = plan.Steps.Single(item => item.Desired.Identity == target.Identity);
            var expected = variant switch
            {
                0 => (ReconciliationReasonCode.ExactConvergence, typeof(ConvergedResource)),
                1 => (ReconciliationReasonCode.MissingObservation, typeof(ObserveResourceIntent)),
                2 => (ReconciliationReasonCode.StaleObservation, typeof(ObserveResourceIntent)),
                3 => (ReconciliationReasonCode.FailedObservation, typeof(HoldResource)),
                4 => (ReconciliationReasonCode.HeldObservation, typeof(HoldResource)),
                5 => (ReconciliationReasonCode.FutureObservation, typeof(HoldResource)),
                6 => (ReconciliationReasonCode.ConflictingObservation, typeof(HoldResource)),
                _ => (ReconciliationReasonCode.DriftEligible, typeof(ReconcileResourceIntent)),
            };
            Require(step.Trace.Single().Reason == expected.Item1 && step.Output.GetType() == expected.Item2,
                seed, "observation outcome");
            Require(step.Output.Identity == target.Identity && step.Output.Kind == target.Kind &&
                step.Output.Generation == target.Generation && step.Output.Digest == target.Digest,
                seed, "frozen output subject");
            if (step.Output is HoldResource hold)
                Require(hold.RootResource == target.Identity && step.Trace.Single().RelatedResource == target.Identity,
                    seed, "observation hold root");
            if (step.Output is ReconcileResourceIntent reconcile)
                Require(reconcile.DependencyProofs.Count == 0, seed, "root dependency proof");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Eligible_drift_with_converged_dependencies_emits_exact_sorted_proofs_for_1000_cases()
    {
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var first = new DesiredResource(new($"proof-{seed:D4}-a"), "service", 100 + (long)seed,
                $"digest-proof-{seed}-a", []);
            var second = new DesiredResource(new($"proof-{seed:D4}-b"), "database", 200 + (long)seed,
                $"digest-proof-{seed}-b", []);
            var target = new DesiredResource(new($"proof-{seed:D4}-target"),
                seed % 2 == 0 ? "service" : "database", 100 + (long)seed,
                $"digest-proof-{seed}", [second.Identity, first.Identity]);
            var observations = new[]
            {
                ReconciliationData.Exact(target) with
                {
                    Generation = target.Generation - 1,
                    Digest = $"old-proof-{seed}",
                    FreshnessSequence = 50 + (long)(seed % 101),
                },
                ReconciliationData.Exact(second) with
                {
                    ObservationId = $"proof-observation-{seed}-b",
                    FreshnessSequence = 200 + (long)seed,
                },
                ReconciliationData.Exact(first) with
                {
                    ObservationId = $"proof-observation-{seed}-a",
                    FreshnessSequence = 100 + (long)seed,
                },
            };
            var plan = ReconciliationData.Plan([target, second, first], observations);
            var step = plan.Steps.Single(item => item.Desired.Identity == target.Identity);
            var intent = step.Output as ReconcileResourceIntent;
            Require(intent is not null && step.Trace.Single().Reason == ReconciliationReasonCode.DriftEligible,
                seed, "eligible dependency drift");
            string[] expected =
            [
                $"{first.Identity.Value}:{first.Kind}:{first.Generation}:{first.Digest}:proof-observation-{seed}-a:{100 + seed}:Ready",
                $"{second.Identity.Value}:{second.Kind}:{second.Generation}:{second.Digest}:proof-observation-{seed}-b:{200 + seed}:Ready",
            ];
            var actual = intent!.DependencyProofs.Select(proof =>
                $"{proof.Identity.Value}:{proof.Kind}:{proof.Generation}:{proof.Digest}:{proof.ObservationId}:{proof.FreshnessSequence}:{proof.Condition}");
            Require(actual.SequenceEqual(expected, StringComparer.Ordinal), seed, "sorted exact dependency proofs");
            Require(intent.DependencyProofs.All(proof => proof.Condition == ObservedCondition.Ready),
                seed, "only exact ready dependency evidence authorizes mutation");
            Require(intent.Identity == target.Identity && intent.Kind == target.Kind &&
                intent.Generation == target.Generation && intent.Digest == target.Digest,
                seed, "proof intent subject");
            var observation = observations[0];
            Require(intent.ObservationProof.Identity == observation.Identity &&
                intent.ObservationProof.Kind == observation.Kind &&
                intent.ObservationProof.Generation == observation.Generation &&
                intent.ObservationProof.Digest == observation.Digest &&
                intent.ObservationProof.ObservationId == observation.ObservationId &&
                intent.ObservationProof.FreshnessSequence == observation.FreshnessSequence &&
                intent.ObservationProof.Condition == observation.Condition,
                seed, "exact authorizing observation proof");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Missing_cycle_conflict_and_dependency_hold_roots_follow_exact_oracle_for_1000_cases()
    {
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var variant = (int)(seed % 5);
            var prefix = $"case-{seed:D4}";
            ReconciliationPlan plan;
            switch (variant)
            {
                case 0:
                    {
                        var parent = ReconciliationData.Resource($"{prefix}-a", $"{prefix}-missing");
                        var child = ReconciliationData.Resource($"{prefix}-b", parent.Identity.Value);
                        plan = ReconciliationData.Plan([child, parent], [ReconciliationData.Exact(child), ReconciliationData.Exact(parent)]);
                        Require(plan.Errors.Single().Code == ReconciliationErrorCode.MissingDependency, seed, "missing error");
                        Require(ReconciliationData.Hold(plan, parent).RootResource.Value == $"{prefix}-missing", seed, "missing root");
                        var propagated = ReconciliationData.Hold(plan, child);
                        Require(propagated.Reason == ReconciliationReasonCode.MissingDependency &&
                            propagated.RootResource.Value == $"{prefix}-missing" &&
                            plan.Steps.Single(step => step.Desired.Identity == child.Identity).Trace.Single().RelatedResource == parent.Identity,
                            seed, "missing propagation");
                        break;
                    }
                case 1:
                    {
                        var a = ReconciliationData.Resource($"{prefix}-a", $"{prefix}-b");
                        var b = ReconciliationData.Resource($"{prefix}-b", a.Identity.Value);
                        plan = ReconciliationData.Plan([b, a], [ReconciliationData.Exact(b), ReconciliationData.Exact(a)]);
                        Require(plan.Errors.Count == 2 && plan.Errors.All(error => error.Code == ReconciliationErrorCode.DependencyCycle), seed, "cycle errors");
                        foreach (var step in plan.Steps)
                            Require(step.Output is HoldResource hold && hold.Reason == ReconciliationReasonCode.CyclicDependency &&
                                hold.RootResource == step.Desired.Identity && step.Trace.Single().RelatedResource == step.Desired.Identity,
                                seed, "cycle holds");
                        break;
                    }
                case 2:
                    {
                        var root = ReconciliationData.Resource($"{prefix}-a");
                        var child = ReconciliationData.Resource($"{prefix}-b", root.Identity.Value);
                        var observations = new[] { ReconciliationData.Exact(root) with { Generation = root.Generation - 1, Digest = $"old-{seed}" }, ReconciliationData.Exact(child) };
                        plan = ReconciliationData.Plan([child, root], observations);
                        Require(plan.Steps.Single(step => step.Desired.Identity == root.Identity).Output is ReconcileResourceIntent, seed, "root drift");
                        var hold = ReconciliationData.Hold(plan, child);
                        Require(hold.Reason == ReconciliationReasonCode.DependencyNotConverged && hold.RootResource == root.Identity &&
                            plan.Steps.Single(step => step.Desired.Identity == child.Identity).Trace.Single().RelatedResource == root.Identity,
                            seed, "drift dependency hold");
                        break;
                    }
                case 3:
                    {
                        var resource = ReconciliationData.Resource($"{prefix}-a");
                        plan = ReconciliationData.Plan([resource, resource], []);
                        Require(plan.Steps.Count == 0 && plan.Trace.Count == 0 &&
                            plan.Errors.Single().Code == ReconciliationErrorCode.DuplicateResource, seed, "duplicate resource fatal");
                        break;
                    }
                default:
                    {
                        var resource = ReconciliationData.Resource($"{prefix}-a"); var observation = ReconciliationData.Exact(resource);
                        plan = ReconciliationData.Plan([resource], [observation, observation]);
                        Require(plan.Steps.Count == 0 && plan.Trace.Count == 0 &&
                            plan.Errors.Single().Code == ReconciliationErrorCode.DuplicateObservation, seed, "duplicate observation fatal");
                        break;
                    }
            }
            Require(plan.Steps.All(step => step.Output is not ObserveResourceIntent and not ReconcileResourceIntent) || variant == 2,
                seed, "mutation exclusion");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Only_actual_cycle_members_are_errors_and_descendants_propagate_stable_root_for_1000_permutations()
    {
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var prefix = $"cycle-{seed:D4}";
            var a = ReconciliationData.Resource($"{prefix}-a", $"{prefix}-b");
            var b = ReconciliationData.Resource($"{prefix}-b", a.Identity.Value);
            var c = ReconciliationData.Resource($"{prefix}-c", b.Identity.Value);
            var d = ReconciliationData.Resource($"{prefix}-d", c.Identity.Value);
            DesiredResource[] desired = [d, b, c, a];
            var observed = desired.Select(ReconciliationData.Exact).ToArray();
            var first = ReconciliationData.Plan(desired, observed);
            var replay = ReconciliationData.Plan(desired.Reverse(), observed.Reverse());
            Require(ReconciliationData.Signature(first) == ReconciliationData.Signature(replay), seed, "cycle permutation");
            Require(first.Errors.Count == 2 &&
                first.Errors.Select(error => error.Resource!.Value).SequenceEqual([$"{prefix}-a", $"{prefix}-b"]),
                seed, "actual cycle membership");
            Require(first.Steps.Select(step => step.Desired.Identity.Value).SequenceEqual(
                [$"{prefix}-a", $"{prefix}-b", $"{prefix}-c", $"{prefix}-d"]), seed, "cycle descendant order");
            var cStep = first.Steps.Single(step => step.Desired.Identity == c.Identity);
            var dStep = first.Steps.Single(step => step.Desired.Identity == d.Identity);
            Require(cStep.Output is HoldResource cHold && cHold.Reason == ReconciliationReasonCode.CyclicDependency &&
                cHold.RootResource == b.Identity && cStep.Trace.Single().RelatedResource == b.Identity,
                seed, "direct cycle root propagation");
            Require(dStep.Output is HoldResource dHold && dHold.Reason == ReconciliationReasonCode.CyclicDependency &&
                dHold.RootResource == b.Identity && dStep.Trace.Single().RelatedResource == c.Identity,
                seed, "transitive cycle root propagation");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Multiple_disconnected_cycles_and_shared_descendant_choose_ordinal_first_root_for_1000_permutations()
    {
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var prefix = $"multi-cycle-{seed:D4}";
            var a = ReconciliationData.Resource($"{prefix}-a", $"{prefix}-b");
            var b = ReconciliationData.Resource($"{prefix}-b", a.Identity.Value);
            var c = ReconciliationData.Resource($"{prefix}-c", $"{prefix}-d");
            var d = ReconciliationData.Resource($"{prefix}-d", c.Identity.Value);
            var shared = new DesiredResource(new($"{prefix}-shared"), "service", 100,
                $"digest-{prefix}-shared", [d.Identity, b.Identity]);
            var descendant = ReconciliationData.Resource($"{prefix}-tail", shared.Identity.Value);
            DesiredResource[] desired = [shared, d, descendant, b, c, a];
            var observed = desired.Select(ReconciliationData.Exact).ToArray();
            var first = ReconciliationData.Plan(desired, observed);
            var permutedDesired = desired.Reverse().Select(resource => new DesiredResource(resource.Identity,
                resource.Kind, resource.Generation, resource.Digest, resource.Dependencies.Reverse())).ToArray();
            var replay = ReconciliationData.Plan(permutedDesired, observed.Reverse());

            Require(ReconciliationData.Signature(first) == ReconciliationData.Signature(replay), seed, "multi-cycle permutation");
            var expectedMembers = new[] { a.Identity.Value, b.Identity.Value, c.Identity.Value, d.Identity.Value };
            Require(first.Errors.Count == 4 && first.Errors.All(error =>
                    error.Code == ReconciliationErrorCode.DependencyCycle && error.Resource == error.RelatedResource) &&
                first.Errors.Select(error => error.Resource!.Value).SequenceEqual(expectedMembers),
                seed, "multi-cycle exact errors");
            foreach (var member in new[] { a, b, c, d })
            {
                var step = first.Steps.Single(item => item.Desired.Identity == member.Identity);
                Require(step.Output is HoldResource hold && hold.Reason == ReconciliationReasonCode.CyclicDependency &&
                    hold.RootResource == member.Identity && step.Trace.Single().RelatedResource == member.Identity,
                    seed, "cycle member self root");
            }
            var sharedStep = first.Steps.Single(item => item.Desired.Identity == shared.Identity);
            var tailStep = first.Steps.Single(item => item.Desired.Identity == descendant.Identity);
            Require(sharedStep.Output is HoldResource sharedHold && sharedHold.RootResource == b.Identity &&
                sharedStep.Trace.Single().RelatedResource == b.Identity, seed, "ordinal shared root");
            Require(tailStep.Output is HoldResource tailHold && tailHold.RootResource == b.Identity &&
                tailStep.Trace.Single().RelatedResource == shared.Identity, seed, "shared root propagation");
            executed++;
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Desired_observed_dependency_permutation_and_culture_replay_is_stable_for_1000_cases()
    {
        var cultures = new[] { "tr-TR", "ar-SA", "ja-JP", "en-US" };
        var executed = 0;
        for (ulong seed = 1; seed <= Cases; seed++)
        {
            var original = CultureInfo.CurrentCulture; var originalUi = CultureInfo.CurrentUICulture;
            try
            {
                var graph = ReconciliationData.Graph(seed); var observations = graph.Select(ReconciliationData.Exact).ToArray();
                if (seed % 3 == 0) observations[Array.FindIndex(observations, item => item.Identity == graph[0].Identity)] =
                    ReconciliationData.Exact(graph[0]) with { Generation = graph[0].Generation - 1, Digest = $"old-{seed}" };
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US"); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
                var first = ReconciliationData.Plan(graph, observations);
                var reversed = graph.Reverse().Select(resource => new DesiredResource(resource.Identity, resource.Kind,
                    resource.Generation, resource.Digest, resource.Dependencies.Reverse())).ToArray();
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % 4]); CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
                var replay = ReconciliationData.Plan(reversed, observations.Reverse());
                Require(ReconciliationData.Signature(first) == ReconciliationData.Signature(replay), seed, "culture permutation replay");
                executed++;
            }
            finally { CultureInfo.CurrentCulture = original; CultureInfo.CurrentUICulture = originalUi; }
        }

        await Assert.That(executed).IsEqualTo(Cases);
    }

    [Test]
    public async Task Strict_pinned_replay_is_complete_and_input_sensitive()
    {
        var corpus = ReconciliationCorpus.Load();
        await Assert.That(corpus.Count).IsEqualTo(12);
        await Assert.That(corpus.Select(entry => entry.Variant).Order().SequenceEqual(Enumerable.Range(0, 12))).IsTrue();
        foreach (var entry in corpus)
        {
            var result = ReconciliationData.Replay(entry.Seed, entry.Variant);
            Require(result.Outcome == entry.Expected, entry.Seed, entry.Id);
            Require(result.Fingerprint == ReconciliationData.ExpectedFingerprint(entry.Seed, entry.Variant), entry.Seed, "fingerprint oracle");
            Require(ReconciliationData.Replay(entry.Seed + 1, entry.Variant).Fingerprint != result.Fingerprint,
                entry.Seed, "seed sensitivity");
            if (entry.Variant <= 7)
                Require(ReconciliationData.Replay(entry.Seed, (entry.Variant + 1) % 8).Fingerprint != result.Fingerprint,
                    entry.Seed, "variant sensitivity");
        }
    }

    [Test]
    public async Task Replay_reader_rejects_byte_shape_schema_identity_seed_and_vocabulary_drift()
    {
        await Assert.That(ReconciliationCorpus.ReadBounded(new MemoryStream(new byte[8192])).Length).IsEqualTo(8192);
        await Assert.That(Fails(() => ReconciliationCorpus.ReadBounded(new MemoryStream(new byte[8193])))).IsTrue();
        var valid = Entry("exact", "1", 0, "ExactConvergence:ConvergedResource");
        await Assert.That(ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(valid), false).Count).IsEqualTo(1);
        var exact = Encoding.UTF8.GetBytes(valid + new string(' ', 8192 - Encoding.UTF8.GetByteCount(valid)));
        await Assert.That(ReconciliationCorpus.Parse(exact, false).Count).IsEqualTo(1);
        await Assert.That(Fails(() => ReconciliationCorpus.Parse(exact.Append((byte)' ').ToArray(), false))).IsTrue();
        string[] invalid =
        [
            "{}", "{/*x*/\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[]}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[],}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[]} trailing",
            Entry("bad id", "1", 0, "ExactConvergence:ConvergedResource"), Entry("-bad", "1", 0, "ExactConvergence:ConvergedResource"),
            Entry("bad-", "1", 0, "ExactConvergence:ConvergedResource"), Entry("bad--id", "1", 0, "ExactConvergence:ConvergedResource"),
            Entry("Bad", "1", 0, "ExactConvergence:ConvergedResource"), Entry(new string('a', 65), "1", 0, "ExactConvergence:ConvergedResource"),
            Entry("x", "0", 0, "ExactConvergence:ConvergedResource"), Entry("x", "1000001", 0, "ExactConvergence:ConvergedResource"),
            Entry("x", "\"1\"", 0, "ExactConvergence:ConvergedResource"), Entry("x", "1", 12, "ExactConvergence:ConvergedResource"),
            Entry("x", "1", 0, "DriftEligible:ReconcileResourceIntent"),
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[],\"extra\":1}",
            "{\"schema\":1,\"entries\":[]}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\"}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\",\"extra\":1}]}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0}]}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":\"0\",\"expected\":\"ExactConvergence:ConvergedResource\"}]}",
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"}]}",
        ];
        foreach (var json in invalid)
            await Assert.That(Fails(() => ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(json), false))).IsTrue();
        var duplicateId = "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"},{\"id\":\"x\",\"seed\":2,\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"}]}";
        var duplicateSeed = "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"},{\"id\":\"y\",\"seed\":1,\"variant\":1,\"expected\":\"MissingObservation:ObserveResourceIntent\"}]}";
        await Assert.That(Fails(() => ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(duplicateId), false))).IsTrue();
        await Assert.That(Fails(() => ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(duplicateSeed), false))).IsTrue();
        await Assert.That(Fails(() => ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(
            "{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[]}"), false))).IsTrue();
        var sixtyFour = Document(Enumerable.Range(1, 64).Select(index =>
            $"{{\"id\":\"id-{index}\",\"seed\":{index},\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"}}"));
        var sixtyFive = Document(Enumerable.Range(1, 65).Select(index =>
            $"{{\"id\":\"id-{index}\",\"seed\":{index},\"variant\":0,\"expected\":\"ExactConvergence:ConvergedResource\"}}"));
        await Assert.That(ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(sixtyFour), false).Count).IsEqualTo(64);
        await Assert.That(Fails(() => ReconciliationCorpus.Parse(Encoding.UTF8.GetBytes(sixtyFive), false))).IsTrue();
    }

    private static string Entry(string id, string seed, int variant, string expected) =>
        $"{{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{{\"id\":\"{id}\",\"seed\":{seed},\"variant\":{variant},\"expected\":\"{expected}\"}}]}}";
    private static string Document(IEnumerable<string> entries) =>
        $"{{\"schema\":\"terrascale.reconciliation-replay.v1\",\"entries\":[{string.Join(',', entries)}]}}";
    private static void Require(bool condition, ulong seed, string property)
    { if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed.ToString(CultureInfo.InvariantCulture)}."); }
    private static bool Fails(Action action) { try { action(); return false; } catch (Exception) { return true; } }
}

internal static class ReconciliationData
{
    internal static DesiredResource Resource(string identity, params string[] dependencies) => new(
        new(identity), "service", 100, $"digest-{identity}", dependencies.Select(value => new ResourceIdentity(value)));

    internal static DesiredResource[] Graph(ulong seed)
    {
        var root = Resource($"a-root-{seed:D4}"); var peer = Resource($"b-peer-{seed:D4}");
        var middle = Resource($"c-middle-{seed:D4}", root.Identity.Value);
        var leaf = Resource($"d-leaf-{seed:D4}", middle.Identity.Value, root.Identity.Value);
        return [leaf, peer, middle, root];
    }

    internal static ObservedResourceState Exact(DesiredResource resource) => new(resource.Identity, resource.Kind,
        resource.Generation, resource.Digest, $"observation-{resource.Identity.Value}", 100, ObservedCondition.Ready);

    internal static ReconciliationPlan Plan(IEnumerable<DesiredResource> desired, IEnumerable<ObservedResourceState> observed) =>
        ReconciliationEngine.Plan(new ReconciliationRequest(desired, observed, Policy()));

    private static ReconciliationPolicy Policy() => new(["service", "database"], new Dictionary<ResourceIdentity, long>(),
        16, 64, 32, 128, 96, 4, 50);

    internal static (ReconciliationPlan Plan, DesiredResource Target) ObservationCase(ulong seed, int variant)
    {
        var target = Resource($"observation-{seed:D4}"); var observation = Exact(target);
        IEnumerable<ObservedResourceState> observations = variant switch
        {
            1 => [],
            2 => [observation with { FreshnessSequence = 49 }],
            3 => [observation with { Condition = ObservedCondition.Failed }],
            4 => [observation with { Condition = ObservedCondition.Held }],
            5 => [observation with { Generation = target.Generation + 1, Digest = $"future-{seed}" }],
            6 => [observation with { Digest = $"conflict-{seed}" }],
            7 => [observation with { Generation = target.Generation - 1, Digest = $"old-{seed}" }],
            _ => [observation],
        };
        return (Plan([target], observations), target);
    }

    internal static HoldResource Hold(ReconciliationPlan plan, DesiredResource resource) =>
        (HoldResource)plan.Steps.Single(step => step.Desired.Identity == resource.Identity).Output;

    internal static string Signature(ReconciliationPlan plan) =>
        string.Join('|', plan.Errors.Select(error => $"E:{error.Code}:{error.Resource?.Value}:{error.RelatedResource?.Value}")) + "#" +
        string.Join('|', plan.Steps.Select(StepFingerprint));

    internal static (string Outcome, string Fingerprint) Replay(ulong seed, int variant)
    {
        var identity = $"replay-{seed}";
        if (variant <= 7)
        {
            var (plan, target) = ObservationCase(seed, variant); var step = plan.Steps.Single();
            return ($"{step.Trace.Single().Reason}:{step.Output.GetType().Name}",
                $"D:{target.Identity.Value}:{target.Kind}:{target.Generation}:{target.Digest}|{StepFingerprint(step)}");
        }
        if (variant == 8)
        {
            var resource = Resource(identity, $"missing-{seed}"); var plan = Plan([resource], [Exact(resource)]); var step = plan.Steps.Single();
            return ($"{step.Trace.Single().Reason}:{step.Output.GetType().Name}",
                $"{resource.Identity.Value}:{resource.Generation}:{resource.Digest}:{((HoldResource)step.Output).RootResource.Value}");
        }
        if (variant == 9)
        {
            var a = Resource($"{identity}-a", $"{identity}-b"); var b = Resource($"{identity}-b", a.Identity.Value);
            var plan = Plan([b, a], [Exact(b), Exact(a)]); var step = plan.Steps[0];
            return ($"{step.Trace.Single().Reason}:{step.Output.GetType().Name}",
                $"{a.Identity.Value}:{a.Generation}:{a.Digest}:{b.Identity.Value}");
        }
        if (variant == 10)
        {
            var resource = Resource(identity); var plan = Plan([resource, resource], []);
            return ($"{plan.Errors.Single().Code}:InvalidPlan", $"{resource.Identity.Value}:{resource.Generation}:{resource.Digest}:2");
        }
        else
        {
            var resource = Resource(identity); var observation = Exact(resource); var plan = Plan([resource], [observation, observation]);
            return ($"{plan.Errors.Single().Code}:InvalidPlan", $"{resource.Identity.Value}:{resource.Generation}:{resource.Digest}:{observation.ObservationId}");
        }
    }

    internal static string ExpectedFingerprint(ulong seed, int variant)
    {
        var identity = variant <= 7 ? $"observation-{seed:D4}" : $"replay-{seed}";
        var digest = $"digest-{identity}";
        if (variant <= 7)
        {
            var observationId = $"observation-{identity}";
            var observation = variant switch
            {
                1 => "<missing>",
                2 => $"{identity}:service:100:{digest}:{observationId}:49:Ready",
                3 => $"{identity}:service:100:{digest}:{observationId}:100:Failed",
                4 => $"{identity}:service:100:{digest}:{observationId}:100:Held",
                5 => $"{identity}:service:101:future-{seed}:{observationId}:100:Ready",
                6 => $"{identity}:service:100:conflict-{seed}:{observationId}:100:Ready",
                7 => $"{identity}:service:99:old-{seed}:{observationId}:100:Ready",
                _ => $"{identity}:service:100:{digest}:{observationId}:100:Ready",
            };
            var reason = variant switch
            {
                0 => ReconciliationReasonCode.ExactConvergence,
                1 => ReconciliationReasonCode.MissingObservation,
                2 => ReconciliationReasonCode.StaleObservation,
                3 => ReconciliationReasonCode.FailedObservation,
                4 => ReconciliationReasonCode.HeldObservation,
                5 => ReconciliationReasonCode.FutureObservation,
                6 => ReconciliationReasonCode.ConflictingObservation,
                _ => ReconciliationReasonCode.DriftEligible,
            };
            var output = variant switch
            {
                0 => nameof(ConvergedResource),
                1 or 2 => nameof(ObserveResourceIntent),
                3 or 4 or 5 or 6 => nameof(HoldResource),
                _ => nameof(ReconcileResourceIntent),
            };
            var related = variant is >= 3 and <= 6 ? identity : string.Empty;
            var root = variant is >= 3 and <= 6 ? identity : string.Empty;
            var observationProof = variant == 7 ? observation : string.Empty;
            return $"D:{identity}:service:100:{digest}|1:{identity}:service:100:{digest}:O:{observation}:X:{output}:{identity}:service:100:{digest}:R:{reason}:{related}:H:{root}:OP:{observationProof}:P:";
        }
        return variant switch
        {
            8 => $"{identity}:100:{digest}:missing-{seed}",
            9 => $"{identity}-a:100:digest-{identity}-a:{identity}-b",
            10 => $"{identity}:100:{digest}:2",
            _ => $"{identity}:100:{digest}:observation-{identity}",
        };
    }

    private static string StepFingerprint(ReconciliationStep step)
    {
        var observation = step.Observation is null ? "<missing>" :
            $"{step.Observation.Identity.Value}:{step.Observation.Kind}:{step.Observation.Generation}:{step.Observation.Digest}:{step.Observation.ObservationId}:{step.Observation.FreshnessSequence}:{step.Observation.Condition}";
        var trace = step.Trace.Single();
        var proofs = step.Output is ReconcileResourceIntent reconcile
            ? string.Join(',', reconcile.DependencyProofs.Select(proof =>
                $"{proof.Identity.Value}:{proof.Kind}:{proof.Generation}:{proof.Digest}:{proof.ObservationId}:{proof.FreshnessSequence}:{proof.Condition}"))
            : string.Empty;
        var observationProof = step.Output is ReconcileResourceIntent intent
            ? $"{intent.ObservationProof.Identity.Value}:{intent.ObservationProof.Kind}:{intent.ObservationProof.Generation}:{intent.ObservationProof.Digest}:{intent.ObservationProof.ObservationId}:{intent.ObservationProof.FreshnessSequence}:{intent.ObservationProof.Condition}"
            : string.Empty;
        return $"{step.Order}:{step.Desired.Identity.Value}:{step.Desired.Kind}:{step.Desired.Generation}:{step.Desired.Digest}:O:{observation}:X:{step.Output.GetType().Name}:{step.Output.Identity.Value}:{step.Output.Kind}:{step.Output.Generation}:{step.Output.Digest}:R:{trace.Reason}:{trace.RelatedResource?.Value}:H:{(step.Output is HoldResource hold ? hold.RootResource.Value : null)}:OP:{observationProof}:P:{proofs}";
    }
}

internal sealed record ReconciliationCorpusEntry(string Id, ulong Seed, int Variant, string Expected);

internal static class ReconciliationCorpus
{
    private const string ResourceName = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.ReconciliationReplayCorpus.v1.json";
    private const string Digest = "3fd45b41afee8ea2b1d4b2bd7cb61e7aef165a1b4518c84ebceb122b3962436c";

    internal static IReadOnlyList<ReconciliationCorpusEntry> Load()
    {
        using var stream = typeof(ReconciliationCorpus).Assembly.GetManifestResourceStream(ResourceName) ?? throw new InvalidDataException();
        return Parse(ReadBounded(stream), true);
    }

    internal static byte[] ReadBounded(Stream stream)
    {
        using var memory = new MemoryStream(); var buffer = new byte[1024]; var total = 0;
        while (true)
        {
            var read = stream.Read(buffer); if (read == 0) break; total += read;
            if (total > 8192) throw new InvalidDataException(); memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }

    internal static IReadOnlyList<ReconciliationCorpusEntry> Parse(byte[] bytes, bool enforceDigest)
    {
        if (bytes.Length > 8192 || enforceDigest && Convert.ToHexStringLower(SHA256.HashData(bytes)) != Digest)
            throw new InvalidDataException();
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        { MaxDepth = 4, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        var root = document.RootElement; Exact(root, "schema", "entries");
        if (root.GetProperty("schema").ValueKind != JsonValueKind.String ||
            root.GetProperty("schema").GetString() != "terrascale.reconciliation-replay.v1" ||
            root.GetProperty("entries").ValueKind != JsonValueKind.Array) throw new InvalidDataException();
        var result = new List<ReconciliationCorpusEntry>();
        foreach (var element in root.GetProperty("entries").EnumerateArray())
        {
            if (result.Count == 64) throw new InvalidDataException(); Exact(element, "id", "seed", "variant", "expected");
            result.Add(new(element.GetProperty("id").GetString()!, element.GetProperty("seed").GetUInt64(),
                element.GetProperty("variant").GetInt32(), element.GetProperty("expected").GetString()!));
        }
        if (result.Count == 0 || result.Select(entry => entry.Id).Distinct(StringComparer.Ordinal).Count() != result.Count ||
            result.Select(entry => entry.Seed).Distinct().Count() != result.Count ||
            result.Any(entry => entry.Seed is 0 or > 1_000_000 || !ValidId(entry.Id) || !Vocabulary(entry)))
            throw new InvalidDataException();
        return result;
    }

    private static bool Vocabulary(ReconciliationCorpusEntry entry) => (entry.Variant, entry.Expected) switch
    {
        (0, "ExactConvergence:ConvergedResource") or (1, "MissingObservation:ObserveResourceIntent") or
        (2, "StaleObservation:ObserveResourceIntent") or (3, "FailedObservation:HoldResource") or
        (4, "HeldObservation:HoldResource") or (5, "FutureObservation:HoldResource") or
        (6, "ConflictingObservation:HoldResource") or (7, "DriftEligible:ReconcileResourceIntent") or
        (8, "MissingDependency:HoldResource") or (9, "CyclicDependency:HoldResource") or
        (10, "DuplicateResource:InvalidPlan") or (11, "DuplicateObservation:InvalidPlan") => true,
        _ => false,
    };

    private static bool ValidId(string? value)
    {
        if (value is null || value.Length is < 1 or > 64 || value[0] == '-' || value[^1] == '-') return false;
        var hyphen = false;
        foreach (var character in value)
        {
            var current = character == '-';
            if (!(character is >= 'a' and <= 'z' or >= '0' and <= '9') && !current || current && hyphen) return false;
            hyphen = current;
        }
        return true;
    }

    private static void Exact(JsonElement element, params string[] names)
    {
        if (!element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(names.Order(StringComparer.Ordinal), StringComparer.Ordinal)) throw new InvalidDataException();
    }
}
