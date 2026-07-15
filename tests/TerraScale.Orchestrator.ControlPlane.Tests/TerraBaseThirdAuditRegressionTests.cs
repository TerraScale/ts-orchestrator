using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseThirdAuditRegressionTests
{
    [Test]
    public async Task Post_apply_upgrade_outputs_retain_exact_release_pair()
    {
        var scope=TerraBaseTestData.Scope();
        static TerraBaseUpgradeEvidence Evidence(TerraBaseEvidenceScope scope,TerraBaseReleaseId current,TerraBaseReleaseId target,bool complete)=>
            new(scope,current,target,TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,
                TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,
                TerraBaseProof.Proven,complete?TerraBaseProof.Proven:TerraBaseProof.Unknown,
                complete?TerraBaseProof.Proven:TerraBaseProof.Unknown,complete?TerraBaseProof.Proven:TerraBaseProof.Unknown,
                TerraBaseProof.Unknown,TerraBaseProof.Unknown);
        var currentA=TerraBaseTestData.Release("current-a");var targetA=TerraBaseTestData.Release("target-a");
        var currentB=TerraBaseTestData.Release("current-b");var targetB=TerraBaseTestData.Release("target-b");
        TerraBaseDecision Decide(TerraBaseReleaseId current,TerraBaseReleaseId target,bool complete)=>
            TerraBaseUpgradePlanner.Plan(scope,current,target,Evidence(scope,current,target,complete));
        foreach(var complete in new[]{false,true})
        {
            var exact=Decide(currentA,targetA,complete);var replay=Decide(currentA,targetA,complete);
            var changedCurrent=Decide(currentB,targetA,complete);var changedTarget=Decide(currentA,targetB,complete);
            await Assert.That(exact.Action).IsEqualTo(complete?TerraBaseAction.Verify:TerraBaseAction.Observe);
            await Assert.That(exact.Code).IsEqualTo(complete?TerraBaseCode.Completed:TerraBaseCode.NextStep);
            await Assert.That(exact.Subject).IsTypeOf<TerraBaseUpgradeIntentSubject>();
            var subject=(TerraBaseUpgradeIntentSubject)exact.Subject!;
            await Assert.That(ReferenceEquals(subject.Scope,scope)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Current,currentA)).IsTrue();
            await Assert.That(ReferenceEquals(subject.Target,targetA)).IsTrue();
            await Assert.That(changedCurrent).IsNotEqualTo(exact);
            await Assert.That(changedTarget).IsNotEqualTo(exact);
            await Assert.That(replay).IsEqualTo(exact);
            await Assert.That(replay.GetHashCode()).IsEqualTo(exact.GetHashCode());
        }
    }

    [Test]
    public async Task Upgrade_holds_never_expose_release_pair_subject()
    {
        var scope=TerraBaseTestData.Scope();var current=TerraBaseTestData.Release("current");var target=TerraBaseTestData.Release("target");
        var incompatible=new TerraBaseUpgradeEvidence(scope,current,target,TerraBaseUpgradeCompatibility.Incompatible,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Unknown,TerraBaseProof.Unknown);
        var mismatched=incompatible with{Compatibility=TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,Target=TerraBaseTestData.Release("other")};
        foreach(var hold in new[]{TerraBaseUpgradePlanner.Plan(scope,current,target,incompatible),TerraBaseUpgradePlanner.Plan(scope,current,target,mismatched)})
        {
            await Assert.That(hold.Action).IsEqualTo(TerraBaseAction.Hold);
            await Assert.That(hold.Subject).IsNull();
        }
    }
}
