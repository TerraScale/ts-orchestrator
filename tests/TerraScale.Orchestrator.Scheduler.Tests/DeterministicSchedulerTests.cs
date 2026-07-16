using TerraScale.Orchestrator.Scheduler;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class DeterministicSchedulerTests
{
    private readonly DeterministicScheduler scheduler = new();

    [Test]
    public async Task PublicSchedulerSurfaceCannotBecomeASecondProductPlacementAuthority()
    {
        // INV-013: product/database geography remains outside the host scheduler contract.
        var forbiddenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ProjectId", "ProjectRegions", "PlacementGeneration", "DatabaseId", "DatabaseRegions"
        };
        var assemblyTypes = typeof(DeterministicScheduler).Assembly.GetExportedTypes();
        var exposedNames = assemblyTypes
            .SelectMany(type => type.GetProperties().Select(property => property.Name)
                .Concat(type.GetConstructors().SelectMany(constructor => constructor.GetParameters())
                    .Select(parameter => parameter.Name ?? string.Empty)))
            .ToArray();

        await Assert.That(exposedNames.Any(forbiddenNames.Contains)).IsFalse();
    }

    [Test]
    public async Task EveryResourceDimensionAcceptsExactFitAndRejectsOneUnitShort()
    {
        foreach (var dimension in Enum.GetValues<ResourceDimension>())
        {
            var request = Vector(dimension, 10);
            var exact = Node("exact", request);
            var selected = scheduler.Schedule(Workload(resources: request), [exact], Policy);

            await Assert.That(selected is PlacementSelected).IsTrue();
            await Assert.That(((PlacementSelected)selected).SelectedCandidateId).IsEqualTo("exact");
            var exactReason = selected.Candidates.Single().Reasons.Single(reason => reason.Check == CheckFor(dimension));
            await Assert.That(exactReason.Outcome).IsEqualTo(CheckOutcome.Passed);

            var shortNode = Node("short", Vector(dimension, 9));
            var rejected = scheduler.Schedule(Workload(resources: request), [shortNode], Policy);
            await Assert.That(rejected is Unschedulable).IsTrue();
            var shortReason = rejected.Candidates.Single().Reasons.Single(reason => reason.Check == CheckFor(dimension));
            await Assert.That(shortReason.Outcome).IsEqualTo(CheckOutcome.Rejected);
        }
    }

    [Test]
    public async Task ResourceQuantitiesAndSafetyCapsMustBeNonNegative()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ResourceVector(-1, 0, 0, 0, 0, 0, 0, 0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new AllocationSafetyCap(-1, 1))).IsTrue();
    }

    [Test]
    public async Task CheckedResourceArithmeticRejectsOverflowAndUnderflow()
    {
        var maximum = new ResourceVector(long.MaxValue, 0, 0, 0, 0, 0, 0, 0);
        var one = new ResourceVector(1, 0, 0, 0, 0, 0, 0, 0);

        await Assert.That(Throws<OverflowException>(() => maximum.AddChecked(one))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => ResourceVector.Zero.SubtractChecked(one))).IsTrue();
    }

    [Test]
    public async Task PortCollisionIsExplicitAndAllOtherChecksStillRun()
    {
        var node = Node("node-a", Abundant, occupiedPorts: [443, 8443]);
        var result = scheduler.Schedule(Workload(requiredPorts: [8443, 9000]), [node], Policy);
        var trace = result.Candidates.Single();

        await Assert.That(result is Unschedulable).IsTrue();
        await Assert.That(trace.Reasons.Count).IsEqualTo(22);
        await Assert.That(trace.Reasons.Single(reason => reason.Check == PlacementCheck.Ports).Detail).Contains("8443");
        await Assert.That(trace.Reasons.Single(reason => reason.Check == PlacementCheck.HugePages).Outcome).IsEqualTo(CheckOutcome.Passed);
    }

    [Test]
    public async Task ArchitectureNodeClassLabelsZonesAndFailureDomainAreHardConstraints()
    {
        var node = new NodeCandidate(
            "node-a", "compact", "x64", "fd-2", Abundant,
            labels: new Dictionary<string, string> { ["disk"] = "standard" },
            trustZones: ["public"], networkZones: ["edge"], secretZones: ["none"]);
        var workload = new WorkloadRequest(
            "api", "arm64", Tiny,
            requiredNodeClass: "isolated",
            requiredLabels: new Dictionary<string, string> { ["disk"] = "balanced", ["role"] = "api" },
            requiredTrustZones: ["trusted"], requiredNetworkZones: ["private"], requiredSecretZones: ["vault"],
            allowedFailureDomains: ["fd-1"]);

        var trace = scheduler.Schedule(workload, [node], Policy).Candidates.Single();
        var rejected = trace.Reasons.Where(reason => reason.Outcome == CheckOutcome.Rejected).Select(reason => reason.Check).ToArray();

        await Assert.That(rejected).IsEquivalentTo(new[]
        {
            PlacementCheck.Architecture, PlacementCheck.NodeClass, PlacementCheck.Labels,
            PlacementCheck.TrustZones, PlacementCheck.NetworkZones, PlacementCheck.SecretZones,
            PlacementCheck.FailureDomain,
        });
        await Assert.That(string.Join(',', trace.Reasons.Select(reason => reason.Check))).IsEqualTo(string.Join(',', ExpectedTraceOrder));
    }

    [Test]
    public async Task AffinityAndAntiAffinityFactsAreCallerSuppliedHardConstraints()
    {
        var node = Node("node-a", Abundant, affinityFacts: ["rack:r1", "workload:database"]);
        var workload = Workload(requiredAffinityFacts: ["rack:r2"], prohibitedAffinityFacts: ["workload:database"]);
        var trace = scheduler.Schedule(workload, [node], Policy).Candidates.Single();

        await Assert.That(trace.Reasons.Single(reason => reason.Check == PlacementCheck.Affinity).Outcome).IsEqualTo(CheckOutcome.Rejected);
        await Assert.That(trace.Reasons.Single(reason => reason.Check == PlacementCheck.AntiAffinity).Outcome).IsEqualTo(CheckOutcome.Rejected);
    }

    [Test]
    public async Task CallerVetoAndCallerSafetyCapAreExplicitAndIndependent()
    {
        var vetoed = Node("vetoed", Abundant, veto: new(CandidateVetoCode.StatefulSafetyHold));
        var capped = Node("capped", Abundant, safetyCap: new(7, 7));
        var result = scheduler.Schedule(Workload(), [vetoed, capped], Policy);

        await Assert.That(result is Unschedulable).IsTrue();
        var vetoTrace = result.Candidates.Single(trace => trace.CandidateId == "vetoed").Reasons
            .Single(reason => reason.Check == PlacementCheck.CallerVeto).Detail;
        await Assert.That(vetoTrace).IsEqualTo("code=StatefulSafetyHold");
        await Assert.That(vetoTrace).DoesNotContain("Controller has not approved a move.");
        await Assert.That(typeof(CandidateVeto).GetProperties().Any(property => property.PropertyType == typeof(string))).IsFalse();
        await Assert.That(typeof(CandidateVeto).GetConstructors().SelectMany(constructor => constructor.GetParameters())
            .Any(parameter => parameter.ParameterType == typeof(string))).IsFalse();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new CandidateVeto((CandidateVetoCode)999))).IsTrue();
        await Assert.That(result.Candidates.Single(trace => trace.CandidateId == "capped").Reasons
            .Single(reason => reason.Check == PlacementCheck.SafetyCap).Outcome).IsEqualTo(CheckOutcome.Rejected);
    }

    [Test]
    public async Task NoImplicitAllocationLimitExistsWhenCallerOmitsSafetyCap()
    {
        var node = Node("node-a", Tiny, safetyCap: null);
        var result = scheduler.Schedule(Workload(resources: Tiny), [node], Policy);

        await Assert.That(result is PlacementSelected).IsTrue();
        await Assert.That(result.Candidates.Single().Reasons.Single(reason => reason.Check == PlacementCheck.SafetyCap).Outcome)
            .IsEqualTo(CheckOutcome.Passed);
    }

    [Test]
    public async Task CallerWeightedLeastWasteSelectsTighterEligibleNode()
    {
        var roomy = Node("roomy", Scale(Tiny, 4));
        var tight = Node("tight", Scale(Tiny, 2));
        var result = (PlacementSelected)scheduler.Schedule(Workload(resources: Tiny), [roomy, tight], Policy);

        await Assert.That(result.SelectedCandidateId).IsEqualTo("tight");
        await Assert.That(result.Candidates.Single(trace => trace.CandidateId == "roomy").Reasons
            .Single(reason => reason.Check == PlacementCheck.Selection).Outcome).IsEqualTo(CheckOutcome.Rejected);
    }

    [Test]
    public async Task EqualScoresUseOrdinalCandidateIdTieBreak()
    {
        var result = (PlacementSelected)scheduler.Schedule(Workload(), [Node("z-node", Abundant), Node("A-node", Abundant)], Policy);

        await Assert.That(result.SelectedCandidateId).IsEqualTo("A-node");
        await Assert.That(string.Join(',', result.Candidates.Select(trace => trace.CandidateId))).IsEqualTo("A-node,z-node");
    }

    [Test]
    public async Task SelectionAndCompleteReasonOutputAreIndependentOfEveryInputPermutation()
    {
        var candidates = new[]
        {
            Node("c", Scale(Tiny, 3)),
            Node("a", Scale(Tiny, 2)),
            Node("b", Scale(Tiny, 2)),
        };
        string? baseline = null;

        foreach (var permutation in Permutations(candidates))
        {
            var result = (PlacementSelected)scheduler.Schedule(Workload(resources: Tiny), permutation, Policy);
            var serialized = Serialize(result);
            baseline ??= serialized;
            await Assert.That(result.SelectedCandidateId).IsEqualTo("a");
            await Assert.That(serialized).IsEqualTo(baseline);
        }
    }

    [Test]
    public async Task UnschedulableIsTypedAndContainsEveryCandidateInStableOrder()
    {
        var result = scheduler.Schedule(Workload(),
            [Node("z", ResourceVector.Zero), Node("a", ResourceVector.Zero)], Policy);

        await Assert.That(result is Unschedulable).IsTrue();
        await Assert.That(string.Join(',', result.Candidates.Select(trace => trace.CandidateId))).IsEqualTo("a,z");
        await Assert.That(result.Candidates.All(trace => trace.Reasons.Count == 22)).IsTrue();
    }

    [Test]
    public async Task EmptyCandidateSetReturnsTypedUnschedulableWithoutInventingCapacity()
    {
        var result = scheduler.Schedule(Workload(), [], Policy);

        await Assert.That(result is Unschedulable).IsTrue();
        await Assert.That(result.Candidates).IsEmpty();
    }

    [Test]
    public async Task ConstructorSnapshotsMutableCollectionsAndSchedulingMutatesNothing()
    {
        var labels = new Dictionary<string, string> { ["role"] = "api" };
        var ports = new HashSet<int> { 443 };
        var facts = new HashSet<string> { "rack:r1" };
        var node = Node("node-a", Abundant, occupiedPorts: ports, labels: labels, affinityFacts: facts);
        var workloadLabels = new Dictionary<string, string> { ["role"] = "api" };
        var workloadPorts = new HashSet<int> { 8443 };
        var workload = Workload(requiredPorts: workloadPorts, requiredLabels: workloadLabels, requiredAffinityFacts: ["rack:r1"]);

        labels["role"] = "changed";
        ports.Add(8443);
        facts.Clear();
        workloadLabels["role"] = "changed";
        workloadPorts.Add(443);

        var before = (node.Labels["role"], node.OccupiedPorts.Count, node.AffinityFacts.Count,
            workload.RequiredLabels["role"], workload.RequiredPorts.Count);
        var result = scheduler.Schedule(workload, [node], Policy);
        var after = (node.Labels["role"], node.OccupiedPorts.Count, node.AffinityFacts.Count,
            workload.RequiredLabels["role"], workload.RequiredPorts.Count);

        await Assert.That(result is PlacementSelected).IsTrue();
        await Assert.That(after).IsEqualTo(before);
    }

    [Test]
    public async Task InvalidPortsAndDuplicateCandidateIdsFailClosed()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Node("bad", Abundant, occupiedPorts: [0]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Workload(requiredPorts: [65536]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Workload(requiredPorts: [443, 443]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Workload(requiredAffinityFacts: ["rack:r1", "rack:r1"]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => scheduler.Schedule(Workload(), [Node("same", Abundant), Node("same", Abundant)], Policy))).IsTrue();
    }

    [Test]
    public async Task OptionalNodeClassDistinguishesAbsentFromSuppliedBlank()
    {
        var absent = new WorkloadRequest("api", "arm64", Tiny, requiredNodeClass: null);

        await Assert.That(absent.RequiredNodeClass is null).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new WorkloadRequest("api", "arm64", Tiny, requiredNodeClass: ""))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new WorkloadRequest("api", "arm64", Tiny, requiredNodeClass: " \t\r\n"))).IsTrue();
    }

    [Test]
    public async Task EveryOptionalStringCollectionRejectsSuppliedWhitespace()
    {
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, requiredTrustZones: [" "]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, requiredNetworkZones: ["\n"]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, requiredSecretZones: ["\t"]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, allowedFailureDomains: [""]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, requiredAffinityFacts: [" "]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new WorkloadRequest(
            "api", "arm64", Tiny, prohibitedAffinityFacts: [" "]))).IsTrue();
    }

    [Test]
    public async Task ZeroRequestFitsZeroCapacityAndProducesExactZeroScore()
    {
        var result = (PlacementSelected)scheduler.Schedule(
            Workload(resources: ResourceVector.Zero), [Node("zero", ResourceVector.Zero)], Policy);

        await Assert.That(result.SelectedCandidateId).IsEqualTo("zero");
        await Assert.That(result.Candidates.Single().Score!.WeightedWaste.IsZero).IsTrue();
    }

    [Test]
    public async Task CallerPolicyControlsWeightsAndTieBreakOrderWithoutProductionDefault()
    {
        var cpuFirst = new LeastWastePolicy(
        [
            new(ResourceDimension.Cpu, 1), new(ResourceDimension.Memory, 0),
            new(ResourceDimension.BlockIo, 0), new(ResourceDimension.EphemeralDisk, 0),
            new(ResourceDimension.Bandwidth, 0), new(ResourceDimension.Pids, 0),
            new(ResourceDimension.FileDescriptors, 0), new(ResourceDimension.HugePages, 0),
        ]);
        var cpuTight = Node("cpu-tight", new(2, 100, 1, 1, 1, 1, 1, 1));
        var memoryTight = Node("memory-tight", new(100, 2, 1, 1, 1, 1, 1, 1));
        var result = (PlacementSelected)scheduler.Schedule(Workload(), [memoryTight, cpuTight], cpuFirst);

        await Assert.That(result.SelectedCandidateId).IsEqualTo("cpu-tight");
        await Assert.That(result.Candidates.Single(trace => trace.CandidateId == "cpu-tight").Reasons
            .Single(reason => reason.Check == PlacementCheck.Score).Detail).Contains("Cpu:1*1=1");
        await Assert.That(Throws<ArgumentException>(() => new LeastWastePolicy(
            [new(ResourceDimension.Cpu, 1)]))).IsTrue();
    }

    [Test]
    public async Task NearMaximumValuesAndWeightsUseExactUnboundedScoreArithmetic()
    {
        var maximumPolicy = new LeastWastePolicy(Enum.GetValues<ResourceDimension>()
            .Select(dimension => new ScoreDimension(dimension, long.MaxValue)));
        var maximum = new ResourceVector(long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue,
            long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue);
        var result = (PlacementSelected)scheduler.Schedule(
            Workload(resources: ResourceVector.Zero), [Node("maximum", maximum)], maximumPolicy);
        var score = result.Candidates.Single().Score!;

        await Assert.That(score.WeightedWaste > long.MaxValue).IsTrue();
        await Assert.That(score.Components.Count).IsEqualTo(8);
    }

    [Test]
    public async Task MaximumCallerCountIsComparedWithoutIncrementOverflow()
    {
        var node = Node("at-cap", Abundant, safetyCap: new(long.MaxValue, long.MaxValue));
        var result = scheduler.Schedule(Workload(), [node], Policy);

        await Assert.That(result is Unschedulable).IsTrue();
        await Assert.That(result.Candidates.Single().Reasons.Single(reason => reason.Check == PlacementCheck.SafetyCap).Detail)
            .Contains(long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static ResourceVector Tiny { get; } = new(1, 1, 1, 1, 1, 1, 1, 1);

    private static ResourceVector Abundant { get; } = new(100, 100, 100, 100, 100, 100, 100, 100);

    private static LeastWastePolicy Policy { get; } = new(Enum.GetValues<ResourceDimension>()
        .Select(dimension => new ScoreDimension(dimension, 1)));

    private static PlacementCheck[] ExpectedTraceOrder { get; } =
    [
        PlacementCheck.CallerVeto, PlacementCheck.Architecture, PlacementCheck.NodeClass, PlacementCheck.Labels,
        PlacementCheck.TrustZones, PlacementCheck.NetworkZones, PlacementCheck.SecretZones, PlacementCheck.FailureDomain,
        PlacementCheck.Affinity, PlacementCheck.AntiAffinity, PlacementCheck.Ports, PlacementCheck.SafetyCap,
        PlacementCheck.Cpu, PlacementCheck.Memory, PlacementCheck.BlockIo, PlacementCheck.EphemeralDisk,
        PlacementCheck.Bandwidth, PlacementCheck.Pids, PlacementCheck.FileDescriptors, PlacementCheck.HugePages,
        PlacementCheck.Score, PlacementCheck.Selection,
    ];

    private static NodeCandidate Node(
        string id,
        ResourceVector available,
        IEnumerable<int>? occupiedPorts = null,
        IReadOnlyDictionary<string, string>? labels = null,
        IEnumerable<string>? affinityFacts = null,
        AllocationSafetyCap? safetyCap = null,
        CandidateVeto? veto = null) =>
        new(id, "compact", "arm64", "fd-1", available, occupiedPorts, labels,
            ["trusted"], ["private"], ["vault"], affinityFacts, safetyCap, veto);

    private static WorkloadRequest Workload(
        ResourceVector? resources = null,
        IEnumerable<int>? requiredPorts = null,
        IReadOnlyDictionary<string, string>? requiredLabels = null,
        IEnumerable<string>? requiredAffinityFacts = null,
        IEnumerable<string>? prohibitedAffinityFacts = null) =>
        new("api", "arm64", resources ?? Tiny, requiredPorts, requiredLabels: requiredLabels,
            requiredTrustZones: ["trusted"], requiredNetworkZones: ["private"], requiredSecretZones: ["vault"],
            requiredAffinityFacts: requiredAffinityFacts, prohibitedAffinityFacts: prohibitedAffinityFacts);

    private static ResourceVector Vector(ResourceDimension dimension, long value) => dimension switch
    {
        ResourceDimension.Cpu => new(value, 0, 0, 0, 0, 0, 0, 0),
        ResourceDimension.Memory => new(0, value, 0, 0, 0, 0, 0, 0),
        ResourceDimension.BlockIo => new(0, 0, value, 0, 0, 0, 0, 0),
        ResourceDimension.EphemeralDisk => new(0, 0, 0, value, 0, 0, 0, 0),
        ResourceDimension.Bandwidth => new(0, 0, 0, 0, value, 0, 0, 0),
        ResourceDimension.Pids => new(0, 0, 0, 0, 0, value, 0, 0),
        ResourceDimension.FileDescriptors => new(0, 0, 0, 0, 0, 0, value, 0),
        ResourceDimension.HugePages => new(0, 0, 0, 0, 0, 0, 0, value),
        _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
    };

    private static ResourceVector Scale(ResourceVector value, long multiplier) => new(
        checked(value.Cpu * multiplier), checked(value.Memory * multiplier), checked(value.BlockIo * multiplier),
        checked(value.EphemeralDisk * multiplier), checked(value.Bandwidth * multiplier), checked(value.Pids * multiplier),
        checked(value.FileDescriptors * multiplier), checked(value.HugePages * multiplier));

    private static PlacementCheck CheckFor(ResourceDimension dimension) => dimension switch
    {
        ResourceDimension.Cpu => PlacementCheck.Cpu,
        ResourceDimension.Memory => PlacementCheck.Memory,
        ResourceDimension.BlockIo => PlacementCheck.BlockIo,
        ResourceDimension.EphemeralDisk => PlacementCheck.EphemeralDisk,
        ResourceDimension.Bandwidth => PlacementCheck.Bandwidth,
        ResourceDimension.Pids => PlacementCheck.Pids,
        ResourceDimension.FileDescriptors => PlacementCheck.FileDescriptors,
        ResourceDimension.HugePages => PlacementCheck.HugePages,
        _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
    };

    private static IEnumerable<NodeCandidate[]> Permutations(NodeCandidate[] values)
    {
        for (var first = 0; first < values.Length; first++)
        {
            for (var second = 0; second < values.Length; second++)
            {
                if (second == first)
                {
                    continue;
                }

                var third = 3 - first - second;
                yield return [values[first], values[second], values[third]];
            }
        }
    }

    private static string Serialize(PlacementSelected result) => string.Join('|', result.Candidates.Select(trace =>
        $"{trace.CandidateId}:{trace.Eligible}:{trace.Score?.WeightedWaste}:{string.Join(',', trace.Reasons.Select(reason => $"{reason.Check}/{reason.Outcome}/{reason.Detail}"))}"));

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }
}
