using System.Collections.ObjectModel;
using System.Numerics;

namespace TerraScale.Orchestrator.Scheduler;

/// <summary>
/// Pure regional constrained least-waste placement. Project geography and stateful
/// move safety are deliberately caller-owned constraints/vetoes (`INV-013`).
/// </summary>
public sealed class DeterministicScheduler
{
    public ScheduleResult Schedule(
        WorkloadRequest workload,
        IEnumerable<NodeCandidate> candidates,
        LeastWastePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(workload);
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(policy);

        var suppliedCandidates = SchedulerInputSnapshot.Copy(candidates, SchedulerTechnicalInputLimits.MaximumCandidateCount, nameof(candidates), "Candidate input");
        if (suppliedCandidates.Any(candidate => candidate is null))
        {
            throw new ArgumentException("Candidate collections cannot contain null.", nameof(candidates));
        }

        Array.Sort(suppliedCandidates, static (left, right) => StringComparer.Ordinal.Compare(left.Id, right.Id));
        for (var index = 1; index < suppliedCandidates.Length; index++)
        {
            if (StringComparer.Ordinal.Equals(suppliedCandidates[index - 1].Id, suppliedCandidates[index].Id))
            {
                throw new ArgumentException("Candidate IDs must be unique.", nameof(candidates));
            }
        }

        var evaluations = suppliedCandidates.Select(candidate => Evaluate(workload, candidate, policy)).ToArray();
        var selected = evaluations
            .Where(evaluation => evaluation.Score is not null)
            .Order(ScoreComparer.Instance)
            .FirstOrDefault();

        var traces = evaluations
            .Select(evaluation => FinishTrace(evaluation, selected))
            .ToArray();
        var immutableTraces = new ReadOnlyCollection<CandidateTrace>(traces);

        return selected is null
            ? new Unschedulable(workload.Id, immutableTraces)
            : new PlacementSelected(workload.Id, selected.Candidate.Id, immutableTraces);
    }

    private static Evaluation Evaluate(WorkloadRequest workload, NodeCandidate candidate, LeastWastePolicy policy)
    {
        var reasons = new List<PlacementReason>(22);

        Add(reasons, PlacementCheck.CallerVeto, candidate.Veto is null,
            candidate.Veto is null ? "No caller veto." : $"code={candidate.Veto.Code}");
        Add(reasons, PlacementCheck.Architecture,
            string.Equals(candidate.Architecture, workload.Architecture, StringComparison.Ordinal),
            $"required={workload.Architecture}; actual={candidate.Architecture}");
        Add(reasons, PlacementCheck.NodeClass,
            workload.RequiredNodeClass is null || string.Equals(candidate.NodeClass, workload.RequiredNodeClass, StringComparison.Ordinal),
            workload.RequiredNodeClass is null
                ? "No node class required."
                : $"required={workload.RequiredNodeClass}; actual={candidate.NodeClass}");

        var missingLabels = workload.RequiredLabels
            .Where(required => !candidate.Labels.TryGetValue(required.Key, out var value) ||
                               !string.Equals(value, required.Value, StringComparison.Ordinal))
            .Select(required => $"{required.Key}={required.Value}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        Add(reasons, PlacementCheck.Labels, missingLabels.Length == 0,
            missingLabels.Length == 0 ? "All required labels match." : $"missing/mismatched={string.Join(',', missingLabels)}");

        AddSubsetCheck(reasons, PlacementCheck.TrustZones, "trust", workload.RequiredTrustZones, candidate.TrustZones);
        AddSubsetCheck(reasons, PlacementCheck.NetworkZones, "network", workload.RequiredNetworkZones, candidate.NetworkZones);
        AddSubsetCheck(reasons, PlacementCheck.SecretZones, "secret", workload.RequiredSecretZones, candidate.SecretZones);

        var failureDomainAllowed = workload.AllowedFailureDomains.Count == 0 ||
                                   workload.AllowedFailureDomains.Contains(candidate.FailureDomain);
        Add(reasons, PlacementCheck.FailureDomain, failureDomainAllowed,
            workload.AllowedFailureDomains.Count == 0
                ? "No failure-domain restriction."
                : $"actual={candidate.FailureDomain}; allowed={Join(workload.AllowedFailureDomains)}");

        AddSubsetCheck(reasons, PlacementCheck.Affinity, "affinity", workload.RequiredAffinityFacts, candidate.AffinityFacts);
        var antiAffinityConflicts = workload.ProhibitedAffinityFacts.Intersect(candidate.AffinityFacts, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToArray();
        Add(reasons, PlacementCheck.AntiAffinity, antiAffinityConflicts.Length == 0,
            antiAffinityConflicts.Length == 0 ? "No anti-affinity conflict." : $"conflicts={string.Join(',', antiAffinityConflicts)}");

        var portConflicts = workload.RequiredPorts.Intersect(candidate.OccupiedPorts).Order().ToArray();
        Add(reasons, PlacementCheck.Ports, portConflicts.Length == 0,
            portConflicts.Length == 0 ? "All requested ports are free." : $"conflicts={string.Join(',', portConflicts)}");
        Add(reasons, PlacementCheck.SafetyCap,
            candidate.SafetyCap is null || candidate.SafetyCap.CanAdmit,
            candidate.SafetyCap is null
                ? "No caller-provided safety cap."
                : $"current={candidate.SafetyCap.CurrentAllocations}; maximum={candidate.SafetyCap.MaximumAllocations}");

        var available = candidate.Available.OrderedValues().ToArray();
        var requested = workload.Resources.OrderedValues().ToArray();
        for (var index = 0; index < available.Length; index++)
        {
            var passes = available[index].Value >= requested[index].Value;
            Add(reasons, ToCheck(available[index].Dimension), passes,
                $"required={requested[index].Value}; available={available[index].Value}");
        }

        if (reasons.Any(reason => reason.Outcome == CheckOutcome.Rejected))
        {
            reasons.Add(new(PlacementCheck.Score, CheckOutcome.NotApplicable, "Hard constraints rejected the candidate."));
            return new(candidate, null, reasons);
        }

        var remaining = candidate.Available.SubtractChecked(workload.Resources);
        var score = CalculateWaste(policy, remaining);
        reasons.Add(new(PlacementCheck.Score, CheckOutcome.Passed,
            $"weightedWaste={score.WeightedWaste}; components={Format(score.Components)}; " +
            $"componentTieBreakOrder={string.Join(',', policy.Dimensions.Select(item => item.Dimension))}"));
        return new(candidate, score, reasons);
    }

    private static CandidateTrace FinishTrace(Evaluation evaluation, Evaluation? selected)
    {
        var reasons = new List<PlacementReason>(evaluation.Reasons);
        if (evaluation.Score is null)
        {
            reasons.Add(new(PlacementCheck.Selection, CheckOutcome.NotApplicable, "Candidate was ineligible."));
        }
        else if (ReferenceEquals(evaluation, selected))
        {
            reasons.Add(new(PlacementCheck.Selection, CheckOutcome.Passed,
                $"Selected by tuple (weightedWaste, orderedRemaining, candidateId)=({evaluation.Score.WeightedWaste}," +
                $"{string.Join(',', evaluation.Score.Components.Select(component => component.Remaining))},{evaluation.Candidate.Id})."));
        }
        else
        {
            reasons.Add(new(PlacementCheck.Selection, CheckOutcome.Rejected, "Eligible but ranked after the selected candidate."));
        }

        return new(
            evaluation.Candidate.Id,
            evaluation.Score is not null,
            evaluation.Score,
            new ReadOnlyCollection<PlacementReason>(reasons));
    }

    private static WasteScore CalculateWaste(LeastWastePolicy policy, ResourceVector remaining)
    {
        var remainingByDimension = remaining.OrderedValues().ToDictionary(item => item.Dimension, item => item.Value);
        var components = policy.Dimensions.Select(item => new WasteComponent(
            item.Dimension,
            remainingByDimension[item.Dimension],
            item.Weight,
            (BigInteger)remainingByDimension[item.Dimension] * item.Weight)).ToArray();
        var total = BigInteger.Zero;
        foreach (var component in components)
        {
            total += component.WeightedWaste;
        }

        return new(total, remaining, new ReadOnlyCollection<WasteComponent>(components));
    }

    private static void AddSubsetCheck(
        ICollection<PlacementReason> reasons,
        PlacementCheck check,
        string name,
        IReadOnlySet<string> required,
        IReadOnlySet<string> actual)
    {
        var missing = required.Except(actual, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        Add(reasons, check, missing.Length == 0,
            missing.Length == 0 ? $"All required {name} facts match." : $"missing={string.Join(',', missing)}");
    }

    private static void Add(ICollection<PlacementReason> reasons, PlacementCheck check, bool passed, string detail) =>
        reasons.Add(new(check, passed ? CheckOutcome.Passed : CheckOutcome.Rejected, detail));

    private static PlacementCheck ToCheck(ResourceDimension dimension) => dimension switch
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

    private static string Join(IEnumerable<string> values) => string.Join(',', values.Order(StringComparer.Ordinal));

    private static string Format(IEnumerable<WasteComponent> components) => string.Join(',',
        components.Select(component => $"{component.Dimension}:{component.Remaining}*{component.Weight}={component.WeightedWaste}"));

    private sealed record Evaluation(NodeCandidate Candidate, WasteScore? Score, IReadOnlyList<PlacementReason> Reasons);

    private sealed class ScoreComparer : IComparer<Evaluation>
    {
        public static ScoreComparer Instance { get; } = new();

        public int Compare(Evaluation? left, Evaluation? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            if (right is null)
            {
                return 1;
            }

            if (left.Score is not { } leftScore || right.Score is not { } rightScore)
            {
                throw new ArgumentException("Only eligible evaluations can be ranked.");
            }

            var comparison = leftScore.WeightedWaste.CompareTo(rightScore.WeightedWaste);
            if (comparison != 0)
            {
                return comparison;
            }

            for (var index = 0; index < leftScore.Components.Count; index++)
            {
                comparison = leftScore.Components[index].Remaining.CompareTo(rightScore.Components[index].Remaining);
                if (comparison != 0)
                {
                    return comparison;
                }
            }

            return StringComparer.Ordinal.Compare(left.Candidate.Id, right.Candidate.Id);
        }
    }
}
