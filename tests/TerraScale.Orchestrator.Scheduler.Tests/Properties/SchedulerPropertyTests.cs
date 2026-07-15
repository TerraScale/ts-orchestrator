using System.Globalization;
using System.Numerics;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

public sealed class SchedulerPropertyTests
{
    private readonly DeterministicScheduler scheduler=new();

    [Test]
    public async Task Valid_cases_are_deterministic_permutation_and_culture_invariant_for_one_thousand_explicit_seeds()
    {
        for(ulong seed=1;seed<=PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);var baseline=PropertySerialization.Schedule(scheduler.Schedule(property.Workload,property.Candidates,property.Policy));
            foreach(var candidates in new[]{property.Candidates.Reverse().ToArray(),property.Candidates.Skip(1).Append(property.Candidates[0]).ToArray()})
            foreach(var cultureName in new[]{"tr-TR","ar-SA"})
            {
                var original=CultureInfo.CurrentCulture;try{CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo(cultureName);
                    await Assert.That(PropertySerialization.Schedule(scheduler.Schedule(property.Workload,candidates,property.Policy))).IsEqualTo(baseline);}
                finally{CultureInfo.CurrentCulture=original;}
            }
        }
    }

    [Test]
    public async Task Selected_candidates_conserve_every_resource_and_never_exceed_capacity()
    {
        for(ulong seed=10_001;seed<10_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);var result=scheduler.Schedule(property.Workload,property.Candidates,property.Policy);
            await Assert.That(result).IsTypeOf<PlacementSelected>();var selected=(PlacementSelected)result;
            var oracle=SchedulerIndependentOracle.Select(property);await Assert.That(selected.SelectedCandidateId).IsEqualTo(oracle.CandidateId);
            var candidate=property.Candidates.Single(item=>item.Id==selected.SelectedCandidateId);var trace=selected.Candidates.Single(item=>item.CandidateId==selected.SelectedCandidateId);
            var expected=SchedulerIndependentOracle.NaturalRemaining(candidate,property.Workload);
            await Assert.That(SchedulerIndependentOracle.Values(trace.Score!.Remaining).SequenceEqual(expected)).IsTrue();
            await Assert.That(trace.Score.WeightedWaste).IsEqualTo(oracle.WeightedWaste);
            await Assert.That(trace.Score.Components.Select(component=>component.Remaining).SequenceEqual(oracle.OrderedRemaining)).IsTrue();
            await Assert.That(trace.Score.Components.All(component=>component.Remaining>=0&&component.WeightedWaste==(BigInteger)component.Remaining*component.Weight)).IsTrue();
            await Assert.That(trace.Reasons.Where(reason=>reason.Check is>=PlacementCheck.Cpu and<=PlacementCheck.HugePages)
                .All(reason=>reason.Outcome==CheckOutcome.Passed)).IsTrue();
        }
    }

    [Test]
    public async Task Randomized_invalid_cases_reject_each_hard_constraint_and_are_mutation_sensitive()
    {
        var hits=Enum.GetValues<SchedulerViolation>().ToDictionary(value=>value,_=>0);
        for(ulong seed=20_001;seed<20_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Invalid(seed);hits[property.Violation]++;
            var result=scheduler.Schedule(property.Case.Workload,property.Case.Candidates,property.Case.Policy);
            await Assert.That(result).IsTypeOf<Unschedulable>();var trace=result.Candidates.Single();
            await Assert.That(trace.Eligible).IsFalse();
            await Assert.That(trace.Reasons.Single(reason=>reason.Check==property.Check).Outcome).IsEqualTo(CheckOutcome.Rejected);
            await Assert.That(trace.Score is null).IsTrue();
        }
        await Assert.That(hits.Values.All(count=>count>=50)).IsTrue();
    }

    [Test]
    public async Task Typed_caller_safety_holds_always_prevent_selection()
    {
        var vetoes=Enum.GetValues<CandidateVetoCode>();
        for(ulong seed=30_001;seed<30_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);var veto=vetoes[(int)(seed%(ulong)vetoes.Length)];
            var result=scheduler.Schedule(property.Workload,[SchedulerPropertyGenerator.Vetoed(property.Workload,veto)],property.Policy);
            await Assert.That(result).IsTypeOf<Unschedulable>();
            var reason=result.Candidates.Single().Reasons.Single(item=>item.Check==PlacementCheck.CallerVeto);
            await Assert.That(reason.Outcome).IsEqualTo(CheckOutcome.Rejected);await Assert.That(reason.Detail).Contains(veto.ToString());
        }
    }

    [Test]
    public async Task Checked_resource_arithmetic_is_conservative_and_overflow_safe()
    {
        for(ulong seed=35_001;seed<35_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);var amount=(long)(seed%1_000);
            var expanded=SchedulerPropertyGenerator.Add(property.Workload.Resources,amount);
            await Assert.That(expanded.SubtractChecked(property.Workload.Resources)).IsEqualTo(new ResourceVector(amount,amount,amount,amount,amount,amount,amount,amount));
            await Assert.That(property.Workload.Resources.AddChecked(new(amount,amount,amount,amount,amount,amount,amount,amount))).IsEqualTo(expanded);
        }
    }

    [Test]
    public async Task Randomized_invalid_generators_reach_every_public_scheduler_validation_family()
    {
        var hits=Enum.GetValues<SchedulerValidatorFamily>().ToDictionary(value=>value,_=>0);
        for(ulong seed=36_001;seed<36_001+PropertyLimits.FeatureCases;seed++)
        {
            var invalid=SchedulerPropertyGenerator.InvalidValidator(seed);hits[invalid.Family]++;
            await Assert.That(invalid.Rejected).IsTrue();
        }
        await Assert.That(hits.Values.All(count=>count>=50)).IsTrue();
    }

    [Test]
    public async Task Generator_diversity_covers_candidate_counts_dimensions_weights_tradeoffs_and_winners()
    {
        var candidateCounts=new HashSet<int>();var winners=new HashSet<string>(StringComparer.Ordinal);var weightValues=Enum.GetValues<ResourceDimension>()
            .ToDictionary(dimension=>dimension,_=>new HashSet<long>());var dimensionValues=Enumerable.Range(0,8).Select(_=>new HashSet<long>()).ToArray();var tradeoffs=0;
        for(ulong seed=37_001;seed<37_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);candidateCounts.Add(property.Candidates.Length);var oracle=SchedulerIndependentOracle.Select(property);winners.Add(oracle.CandidateId);
            foreach(var dimension in property.Policy.Dimensions)weightValues[dimension.Dimension].Add(dimension.Weight);
            foreach(var candidate in property.Candidates){var values=SchedulerIndependentOracle.NaturalRemaining(candidate,property.Workload);for(var index=0;index<8;index++)dimensionValues[index].Add(values[index]);}
            if(SchedulerIndependentOracle.HasCrossDimensionTradeoff(property))tradeoffs++;
        }
        await Assert.That(candidateCounts).IsEquivalentTo(new[]{2,3,4,5});
        await Assert.That(weightValues.Values.All(values=>values.SetEquals(new long[]{1,2,3,4,5}))).IsTrue();
        await Assert.That(dimensionValues.All(values=>values.Count>=25)).IsTrue();
        await Assert.That(tradeoffs).IsGreaterThanOrEqualTo(900);await Assert.That(winners.Count).IsGreaterThanOrEqualTo(4);
    }

    [Test]
    public async Task Equal_score_and_component_ties_use_ordinal_candidate_identity()
    {
        for(ulong seed=38_001;seed<38_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=SchedulerPropertyGenerator.Valid(seed);var candidates=SchedulerPropertyGenerator.TiedCandidates(property.Workload);
            var selected=(PlacementSelected)scheduler.Schedule(property.Workload,seed%2==0?candidates:candidates.Reverse(),property.Policy);
            await Assert.That(selected.SelectedCandidateId).IsEqualTo("node-a");
        }
    }
}
