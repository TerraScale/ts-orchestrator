using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.ControlPlane.Tests.Properties;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CompletionGapAudit4CounterexampleTests
{
    [Test]
    public async Task Topology_observation_must_retain_the_semantic_planner_route()
    {
        var scope = TerraBaseTestData.Scope();
        var addEvidence = TerraBaseTestData.Topology(scope: scope,
            replication: TerraBaseReplication.Unknown) with
        {
            PostChangeReplication = TerraBaseProof.Unknown,
        };
        var removeEvidence = TerraBaseTestData.Topology(scope: scope) with
        {
            NoDatabaseReference = TerraBaseProof.Unknown,
        };

        var add = TerraBaseTopologyPlanner.PlanAdd(scope, addEvidence);
        var remove = TerraBaseTopologyPlanner.PlanRemove(scope, removeEvidence);

        await Assert.That(add.Action).IsEqualTo(TerraBaseAction.Observe);
        await Assert.That(remove.Action).IsEqualTo(TerraBaseAction.Observe);
        await Assert.That(add).IsNotEqualTo(remove);
    }

    [Test]
    public async Task Successful_add_must_retain_the_exact_accepted_topology_evidence()
    {
        var scope = TerraBaseTestData.Scope();
        var noLoss = TerraBaseTestData.Topology(scope: scope, loss: TerraBaseLossCount.None);
        var oneLoss = TerraBaseTestData.Topology(scope: scope, loss: TerraBaseLossCount.One);

        var first = TerraBaseTopologyPlanner.PlanAdd(scope, noLoss);
        var second = TerraBaseTopologyPlanner.PlanAdd(scope, oneLoss);

        await Assert.That(first.Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(second.Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(first).IsNotEqualTo(second);
    }

    [Test]
    public async Task Successful_remove_must_retain_the_exact_accepted_topology_evidence()
    {
        var scope = TerraBaseTestData.Scope();
        var follower = TerraBaseTestData.Topology(scope: scope, role: TerraBaseRole.Follower);
        var transferredLeader = TerraBaseTestData.Topology(scope: scope, role: TerraBaseRole.Leader,
            leadership: TerraBaseProof.Proven);

        var first = TerraBaseTopologyPlanner.PlanRemove(scope, follower);
        var second = TerraBaseTopologyPlanner.PlanRemove(scope, transferredLeader);

        await Assert.That(first.Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(second.Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(first).IsNotEqualTo(second);
    }

    [Test]
    public async Task Every_successful_topology_branch_retains_exact_evidence_and_fixed_kind()
    {
        var scope = TerraBaseTestData.Scope();
        var cases = BranchCases(scope);

        foreach (var item in cases)
        {
            var decision = item.Plan(scope, item.Evidence);
            await Assert.That(decision.Action).IsEqualTo(item.Action);
            await Assert.That(decision.Target).IsEqualTo(item.Target);
            await Assert.That(decision.Code).IsEqualTo(item.Code);
            var subject = (TerraBaseTopologyIntentSubject)decision.Subject!;
            await Assert.That(subject.PlanKind).IsEqualTo(item.Kind);
            await Assert.That(ReferenceEquals(subject.Evidence, item.Evidence)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Scope, item.Evidence.Scope)).IsTrue();
            await Assert.That(subject.MemberKind).IsEqualTo(item.Evidence.MemberKind);
            await Assert.That(subject.ReplicationPosition).IsEqualTo(item.Evidence.ReplicationPosition);
        }

        await Assert.That(cases.Count).IsEqualTo(11);
    }

    [Test]
    public async Task Every_scope_and_topology_evidence_leaf_is_independently_sensitive()
    {
        var scope = TerraBaseTestData.Scope();
        var baseline = TerraBaseTestData.Topology(scope: scope);
        var baselineSubject = ConstructSubject(TerraBaseTopologyPlanKind.Add, baseline);
        var scopeMutations = new[]
        {
            scope with { Region = TerraBaseTestData.Region("SFO") },
            scope with { Database = TerraBaseTestData.Db("db-b") },
            scope with { Member = TerraBaseTestData.Member("member-b") },
            scope with { Node = TerraBaseTestData.Node("node-b") },
            scope with { RetainedVolume = TerraBaseTestData.Volume("volume-b") },
            scope with { Fence = TerraBaseTestData.Fence("fence-b") },
            scope with { DatabaseGeneration = TerraBaseTestData.O(5) },
            scope with { TopologyGeneration = TerraBaseTestData.O(9) },
            scope with { AuthorityEpoch = TerraBaseTestData.O(4) },
            scope with { Operation = TerraBaseTestData.Op("operation-b") },
        };
        foreach (var mutation in scopeMutations)
        {
            var evidence = baseline with { Scope = mutation };
            var subject = ConstructSubject(TerraBaseTopologyPlanKind.Add, evidence);
            await Assert.That(subject).IsNotEqualTo(baselineSubject);
            await Assert.That(ReferenceEquals(subject.Evidence, evidence)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Scope, mutation)).IsTrue();
        }

        var evidenceMutations = new[]
        {
            baseline with { MemberKind = TerraBaseMemberKind.PermanentA },
            baseline with { MemberRole = TerraBaseRole.Leader },
            baseline with { LossCount = TerraBaseLossCount.One },
            baseline with { LeadershipTransferred = TerraBaseProof.Contradicted },
            baseline with { NoTopologyMutation = TerraBaseProof.Contradicted },
            baseline with { QuorumFloor = TerraBaseProof.Contradicted },
            baseline with { ReplicationFloor = TerraBaseProof.Contradicted },
            baseline with { SustainedSignal = TerraBaseProof.Contradicted },
            baseline with { Placement = TerraBaseProof.Contradicted },
            baseline with { Storage = TerraBaseProof.Contradicted },
            baseline with { Budget = TerraBaseProof.Contradicted },
            baseline with { UniqueMember = TerraBaseProof.Contradicted },
            baseline with { TopologyApplied = TerraBaseProof.Contradicted },
            baseline with { NoDatabaseReference = TerraBaseProof.Contradicted },
            baseline with { RecoveryPoint = TerraBaseProof.Contradicted },
            baseline with { Retention = TerraBaseProof.Contradicted },
            baseline with { VolumeDisposition = TerraBaseProof.Contradicted },
            baseline with { PostChangeReplication = TerraBaseProof.Contradicted },
            baseline with { Replication = TerraBaseReplication.Lagging },
            baseline with { ReplicationPosition = TerraBaseTestData.O(101) },
        };
        foreach (var mutation in evidenceMutations)
        {
            var subject = ConstructSubject(TerraBaseTopologyPlanKind.Add, mutation);
            await Assert.That(subject).IsNotEqualTo(baselineSubject);
            await Assert.That(Emit(subject)).IsNotEqualTo(Emit(baselineSubject));
        }

        await Assert.That(scopeMutations.Length).IsEqualTo(10);
        await Assert.That(evidenceMutations.Length).IsEqualTo(20);
    }

    [Test]
    public async Task Topology_replay_is_culture_stable_unique_and_evaluation_order_independent()
    {
        var first = UnderCulture("tr-TR", ReplayOneThousand);
        var second = UnderCulture("ar-SA", ReplayOneThousand);
        await Assert.That(first).IsEquivalentTo(second);
        await Assert.That(first.Count).IsEqualTo(1_000);
        await Assert.That(first.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(1_000);

        var scope = TerraBaseTestData.Scope();
        var cases = BranchCases(scope);
        var expected = cases.ToDictionary(static item => item.Name,
            item => item.Plan(scope, item.Evidence), StringComparer.Ordinal);
        IEnumerable<TopologyCase>[] permutations =
        [
            cases,
            cases.Reverse(),
            cases.Skip(4).Concat(cases.Take(4)),
            cases.OrderByDescending(static item => item.Name, StringComparer.Ordinal),
        ];
        foreach (var permutation in permutations)
        {
            foreach (var item in permutation)
            {
                await Assert.That(item.Plan(scope, item.Evidence)).IsEqualTo(expected[item.Name]);
            }
        }
        await Assert.That(typeof(TerraBaseTopologyEvidence).GetProperties()
            .Any(static property => typeof(System.Collections.IEnumerable).IsAssignableFrom(property.PropertyType)
                && property.PropertyType != typeof(string))).IsFalse();

        var corpus = DeliveryTerraBaseCorpus.LoadEmbedded();
        await Assert.That(corpus.Code).IsEqualTo(DeliveryTerraBaseCorpusCode.Accepted);
        await Assert.That(corpus.Entries.Count).IsEqualTo(4);
    }

    [Test]
    public async Task Every_topology_hold_is_subject_free()
    {
        var scope = TerraBaseTestData.Scope();
        TerraBaseDecision[] held =
        [
            TerraBaseTopologyPlanner.PlanAdd(scope, TerraBaseTestData.Topology(scope: scope,
                noMutation: TerraBaseProof.Unknown)),
            TerraBaseTopologyPlanner.PlanAdd(scope, TerraBaseTestData.Topology(scope: scope,
                loss: TerraBaseLossCount.TwoOrMore)),
            TerraBaseTopologyPlanner.PlanRemove(scope, TerraBaseTestData.Topology(scope: scope,
                kind: TerraBaseMemberKind.PermanentA)),
            TerraBaseTopologyPlanner.PlanRemove(scope, TerraBaseTestData.Topology(scope: scope,
                replication: TerraBaseReplication.Conflicting)),
        ];
        foreach (var decision in held)
        {
            await Assert.That(decision.Action).IsEqualTo(TerraBaseAction.Hold);
            await Assert.That(decision.Subject).IsNull();
            await Assert.That(decision.IsMutationAuthorized).IsFalse();
        }
    }

    [Test]
    public async Task TerraBase_output_construction_accessor_collection_and_clone_routes_are_closed()
    {
        var assembly = typeof(TerraBaseDecision).Assembly;
        var retainedTypes = new HashSet<Type>
        {
            typeof(TerraBaseDecision), typeof(TerraBaseIntentSubject), typeof(TerraBaseScopedIntentSubject),
            typeof(TerraBaseTopologyIntentSubject), typeof(TerraBaseRetainedVolumeIntentSubject),
            typeof(TerraBaseUpgradeIntentSubject), typeof(TerraBaseBackupRequestIntentSubject),
            typeof(TerraBaseBackupChainIntentSubject), typeof(TerraBaseRestoreIntentSubject),
            typeof(TerraBaseEvidenceScope), typeof(TerraBaseTopologyEvidence), typeof(TerraBaseWriterEvidence),
            typeof(TerraBaseUpgradeEvidence), typeof(TerraBaseBackupEvidence), typeof(TerraBaseBackupRequestEvidence),
            typeof(TerraBaseRestoreEvidence), typeof(TerraBaseTrace),
            typeof(IReadOnlyList<TerraBaseMemberId>), typeof(IReadOnlyList<TerraBaseBackupSegment>),
        };
        var routes = assembly.GetExportedTypes()
            .SelectMany(static type => type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => retainedTypes.Contains(method.ReturnType))
            .Select(static method => $"{method.DeclaringType!.Name}.{method.Name}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        await Assert.That(routes).IsEquivalentTo(new[]
        {
            "TerraBaseBackupChainIntentSubject.<Clone>$",
            "TerraBaseBackupChainIntentSubject.get_Scope",
            "TerraBaseBackupChainIntentSubject.get_Segments",
            "TerraBaseBackupEvidence.get_Scope",
            "TerraBaseBackupEvidence.get_Segments",
            "TerraBaseBackupPlanner.Accept",
            "TerraBaseBackupPlanner.Authorize",
            "TerraBaseBackupRequestEvidence.<Clone>$",
            "TerraBaseBackupRequestEvidence.get_ParentChain",
            "TerraBaseBackupRequestEvidence.get_Scope",
            "TerraBaseBackupRequestIntentSubject.<Clone>$",
            "TerraBaseBackupRequestIntentSubject.get_Scope",
            "TerraBaseDecision.get_Subject",
            "TerraBaseDecision.get_Trace",
            "TerraBaseEvidenceScope.<Clone>$",
            "TerraBaseIntentSubject.<Clone>$",
            "TerraBaseIntentSubject.get_Scope",
            "TerraBaseRestoreEvidence.<Clone>$",
            "TerraBaseRestoreEvidence.get_Chain",
            "TerraBaseRestoreEvidence.get_Scope",
            "TerraBaseRestoreIntentSubject.<Clone>$",
            "TerraBaseRestoreIntentSubject.get_Chain",
            "TerraBaseRestoreIntentSubject.get_Scope",
            "TerraBaseRestorePlanner.Plan",
            "TerraBaseRetainedVolumeIntentSubject.<Clone>$",
            "TerraBaseRetainedVolumeIntentSubject.get_Scope",
            "TerraBaseRetainedVolumePlanner.Plan",
            "TerraBaseScopedIntentSubject.<Clone>$",
            "TerraBaseScopedIntentSubject.get_Scope",
            "TerraBaseTopologyEvidence.<Clone>$",
            "TerraBaseTopologyEvidence.get_Scope",
            "TerraBaseTopologyIntentSubject.<Clone>$",
            "TerraBaseTopologyIntentSubject.get_Evidence",
            "TerraBaseTopologyIntentSubject.get_Scope",
            "TerraBaseTopologyPlanner.PlanAdd",
            "TerraBaseTopologyPlanner.PlanRemove",
            "TerraBaseTrace.<Clone>$",
            "TerraBaseTrace.get_Scope",
            "TerraBaseUpgradeEvidence.<Clone>$",
            "TerraBaseUpgradeEvidence.get_Scope",
            "TerraBaseUpgradeIntentSubject.<Clone>$",
            "TerraBaseUpgradeIntentSubject.get_Scope",
            "TerraBaseUpgradePlanner.Plan",
            "TerraBaseWriterEvidence.get_Scope",
            "TerraBaseWriterEvidence.get_Writers",
        });

        var protectedTypes = assembly.GetExportedTypes().Where(static type =>
            type == typeof(TerraBaseDecision) || typeof(TerraBaseIntentSubject).IsAssignableFrom(type)).ToArray();
        var accessors = protectedTypes.SelectMany(static type => type
                .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Select(property => $"{type.Name}.{property.Name}"))
            .Order(StringComparer.Ordinal)
            .ToArray();
        await Assert.That(accessors).IsEquivalentTo(new[]
        {
            "TerraBaseBackupChainIntentSubject.Scope", "TerraBaseBackupChainIntentSubject.Segments",
            "TerraBaseBackupChainIntentSubject.TerminalBackup", "TerraBaseBackupRequestIntentSubject.Backup",
            "TerraBaseBackupRequestIntentSubject.Destination", "TerraBaseBackupRequestIntentSubject.EncryptionKey",
            "TerraBaseBackupRequestIntentSubject.ParentBackup", "TerraBaseBackupRequestIntentSubject.ParentSequence",
            "TerraBaseBackupRequestIntentSubject.Scope", "TerraBaseBackupRequestIntentSubject.Sequence",
            "TerraBaseDecision.Action", "TerraBaseDecision.Code", "TerraBaseDecision.IsMutationAuthorized",
            "TerraBaseDecision.Subject", "TerraBaseDecision.Target", "TerraBaseDecision.Trace",
            "TerraBaseIntentSubject.Scope", "TerraBaseRestoreIntentSubject.Chain",
            "TerraBaseRestoreIntentSubject.Restore", "TerraBaseRestoreIntentSubject.Scope",
            "TerraBaseRestoreIntentSubject.SourceGeneration", "TerraBaseRestoreIntentSubject.TargetGeneration",
            "TerraBaseRetainedVolumeIntentSubject.NewAuthorityEpoch", "TerraBaseRetainedVolumeIntentSubject.Scope",
            "TerraBaseScopedIntentSubject.Scope", "TerraBaseTopologyIntentSubject.Evidence",
            "TerraBaseTopologyIntentSubject.MemberKind", "TerraBaseTopologyIntentSubject.PlanKind",
            "TerraBaseTopologyIntentSubject.ReplicationPosition", "TerraBaseTopologyIntentSubject.Scope",
            "TerraBaseUpgradeIntentSubject.Current", "TerraBaseUpgradeIntentSubject.Scope",
            "TerraBaseUpgradeIntentSubject.Target",
        });

        var inputConstructorCounts = new Dictionary<Type, int>
        {
            [typeof(TerraBaseEvidenceScope)] = 1,
            [typeof(TerraBaseTopologyEvidence)] = 1,
            [typeof(TerraBaseWriterEvidence)] = 1,
            [typeof(TerraBaseUpgradeEvidence)] = 1,
            [typeof(TerraBaseBackupEvidence)] = 1,
            [typeof(TerraBaseBackupRequestEvidence)] = 1,
            [typeof(TerraBaseRestoreEvidence)] = 1,
            [typeof(TerraBaseTrace)] = 1,
        };
        foreach (var (type, count) in inputConstructorCounts)
        {
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length).IsEqualTo(count);
        }

        await Assert.That(typeof(TerraBaseDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(TerraBaseDecision).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(static property => property.SetMethod?.IsPublic == true)).IsFalse();
        var empty = default(TerraBaseDecision);
        await Assert.That(empty.Action).IsEqualTo(TerraBaseAction.Uninitialized);
        await Assert.That(empty.Target).IsEqualTo(TerraBaseTarget.None);
        await Assert.That(empty.Code).IsEqualTo(TerraBaseCode.Uninitialized);
        await Assert.That(empty.Subject).IsNull();
        await Assert.That(empty.Trace).IsNull();
        await Assert.That(empty.IsMutationAuthorized).IsFalse();
        await Assert.That(empty with { }).IsEqualTo(empty);

        var scope = TerraBaseTestData.Scope();
        var evidence = TerraBaseTestData.Topology(scope: scope);
        var subject = (TerraBaseTopologyIntentSubject)TerraBaseTopologyPlanner.PlanAdd(scope, evidence).Subject!;
        var subjectTypes = protectedTypes.Where(static type => typeof(TerraBaseIntentSubject).IsAssignableFrom(type)).ToArray();
        foreach (var type in subjectTypes)
        {
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
            await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Any(static property => property.SetMethod?.IsPublic == true)).IsFalse();
            await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Any(static method => method.Name == "Deconstruct")).IsFalse();
        }
        var clone = (TerraBaseTopologyIntentSubject)typeof(TerraBaseTopologyIntentSubject)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Single(static method => method.Name == "<Clone>$").Invoke(subject, null)!;
        await Assert.That(clone).IsEqualTo(subject);
        await Assert.That(ReferenceEquals(clone, subject)).IsFalse();
        await Assert.That(ReferenceEquals(clone.Evidence, evidence)).IsTrue();
        await Assert.That(ReferenceEquals(clone.Scope, scope)).IsTrue();
    }

    private static IReadOnlyList<TopologyCase> BranchCases(TerraBaseEvidenceScope scope)
    {
        var completed = TerraBaseTestData.Topology(scope: scope);
        return
        [
            new("add", TerraBaseTopologyPlanKind.Add, completed with { TopologyApplied = TerraBaseProof.Unknown,
                Replication = TerraBaseReplication.Unknown, PostChangeReplication = TerraBaseProof.Unknown },
                TerraBaseAction.Add, TerraBaseTarget.Topology, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanAdd),
            new("add-observe-topology", TerraBaseTopologyPlanKind.Add, completed with
                { Replication = TerraBaseReplication.Unknown, PostChangeReplication = TerraBaseProof.Unknown },
                TerraBaseAction.Observe, TerraBaseTarget.Application, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanAdd),
            new("add-catchup", TerraBaseTopologyPlanKind.Add, completed with
                { Replication = TerraBaseReplication.Lagging, PostChangeReplication = TerraBaseProof.Unknown },
                TerraBaseAction.CatchUp, TerraBaseTarget.Member, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanAdd),
            new("add-observe-replication", TerraBaseTopologyPlanKind.Add, completed with
                { PostChangeReplication = TerraBaseProof.Unknown }, TerraBaseAction.Observe,
                TerraBaseTarget.Application, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanAdd),
            new("add-observe-contradicted", TerraBaseTopologyPlanKind.Add, completed with
                { PostChangeReplication = TerraBaseProof.Contradicted }, TerraBaseAction.Observe,
                TerraBaseTarget.Application, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanAdd),
            new("add-verify", TerraBaseTopologyPlanKind.Add, completed, TerraBaseAction.Verify,
                TerraBaseTarget.Member, TerraBaseCode.Completed, TerraBaseTopologyPlanner.PlanAdd),
            new("remove-transfer", TerraBaseTopologyPlanKind.Remove, completed with
                { TopologyApplied = TerraBaseProof.Unknown, MemberRole = TerraBaseRole.Leader,
                    LeadershipTransferred = TerraBaseProof.Unknown, NoDatabaseReference = TerraBaseProof.Unknown,
                    PostChangeReplication = TerraBaseProof.Unknown }, TerraBaseAction.Transfer,
                TerraBaseTarget.Topology, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanRemove),
            new("remove", TerraBaseTopologyPlanKind.Remove, completed with
                { TopologyApplied = TerraBaseProof.Unknown, NoDatabaseReference = TerraBaseProof.Unknown,
                    PostChangeReplication = TerraBaseProof.Unknown }, TerraBaseAction.Remove,
                TerraBaseTarget.Topology, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanRemove),
            new("remove-observe-reference", TerraBaseTopologyPlanKind.Remove, completed with
                { NoDatabaseReference = TerraBaseProof.Unknown }, TerraBaseAction.Observe,
                TerraBaseTarget.Application, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanRemove),
            new("remove-observe-replication", TerraBaseTopologyPlanKind.Remove, completed with
                { PostChangeReplication = TerraBaseProof.Unknown }, TerraBaseAction.Observe,
                TerraBaseTarget.Application, TerraBaseCode.NextStep, TerraBaseTopologyPlanner.PlanRemove),
            new("remove-verify", TerraBaseTopologyPlanKind.Remove, completed, TerraBaseAction.Verify,
                TerraBaseTarget.Topology, TerraBaseCode.Completed, TerraBaseTopologyPlanner.PlanRemove),
        ];
    }

    private static TerraBaseTopologyIntentSubject ConstructSubject(TerraBaseTopologyPlanKind kind,
        TerraBaseTopologyEvidence evidence) => (TerraBaseTopologyIntentSubject)typeof(TerraBaseTopologyIntentSubject)
        .GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
        .Single(static constructor => constructor.GetParameters().Length == 2).Invoke([kind, evidence]);

    private static TerraBaseDecision Emit(TerraBaseTopologyIntentSubject subject)
    {
        var trace = new TerraBaseTrace(subject.Scope, subject.ReplicationPosition, subject.Scope.TopologyGeneration);
        return (TerraBaseDecision)typeof(TerraBaseDecision).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(static method => method.Name == "Emit" && method.GetParameters().Length == 5)
            .Invoke(null, [TerraBaseAction.Verify, TerraBaseTarget.Topology, TerraBaseCode.Completed, trace, subject])!;
    }

    private static IReadOnlyList<string> ReplayOneThousand()
    {
        var output = new string[1_000];
        for (var index = 0; index < output.Length; index++)
        {
            var scope = TerraBaseTestData.Scope() with
            {
                DatabaseGeneration = TerraBaseTestData.O((ulong)index + 1),
                TopologyGeneration = TerraBaseTestData.O((ulong)index + 2),
                AuthorityEpoch = TerraBaseTestData.O((ulong)index + 3),
                Operation = TerraBaseTestData.Op($"topology-{index}"),
            };
            var item = BranchCases(scope)[index % 11];
            var decision = item.Plan(scope, item.Evidence);
            var subject = (TerraBaseTopologyIntentSubject)decision.Subject!;
            output[index] = string.Join('|', subject.PlanKind, subject.Operation(), decision.Action,
                subject.Scope.DatabaseGeneration.Value.ToString(CultureInfo.InvariantCulture),
                subject.Scope.TopologyGeneration.Value.ToString(CultureInfo.InvariantCulture),
                subject.Evidence.MemberRole, subject.Evidence.LossCount, subject.Evidence.PostChangeReplication);
        }
        return output;
    }

    private static T UnderCulture<T>(string cultureName, Func<T> action)
    {
        var previous = CultureInfo.CurrentCulture;
        var previousUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(cultureName);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }

    private sealed record TopologyCase(string Name, TerraBaseTopologyPlanKind Kind,
        TerraBaseTopologyEvidence Evidence, TerraBaseAction Action, TerraBaseTarget Target, TerraBaseCode Code,
        Func<TerraBaseEvidenceScope?, TerraBaseTopologyEvidence?, TerraBaseDecision> Plan);
}

internal static class TerraBaseTopologySubjectTestExtensions
{
    internal static string Operation(this TerraBaseTopologyIntentSubject subject) => subject.Scope.Operation.Value;
}
