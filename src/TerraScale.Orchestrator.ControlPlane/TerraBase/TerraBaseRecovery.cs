namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

public sealed record TerraBaseBackupSubject(TerraBaseCellId Cell,TerraBaseDatabaseId Database,
    TerraBaseOrdinal DatabaseGeneration,TerraBaseOrdinal TopologyGeneration);
public sealed record TerraBaseBackupSegment(TerraBaseBackupSubject Subject,TerraBaseBackupId Backup,
    TerraBaseOrdinal Sequence,TerraBaseOrdinal? ParentSequence,bool IsFull,TerraBaseDigestRef Digest,
    TerraBaseObjectRef Object,TerraBaseKeyRef EncryptionKey);

public sealed class TerraBaseBackupEvidence
{
    private readonly TerraBaseBackupSegment[] _segments;
    public TerraBaseBackupEvidence(TerraBaseEvidenceScope scope,IEnumerable<TerraBaseBackupSegment?>? segments,
        TerraBaseProof applicationConsistent,TerraBaseProof digestVerified,TerraBaseProof objectVerified,int maximum)
    {
        Scope=scope;ApplicationConsistent=applicationConsistent;DigestVerified=digestVerified;ObjectVerified=objectVerified;
        var values=segments?.ToArray()??[];IsValid=scope is not null&&scope.Valid&&maximum>0&&values.Length>0&&values.Length<=maximum&&values.All(x=>x is not null);
        _segments=values.Where(x=>x is not null).Cast<TerraBaseBackupSegment>().ToArray();
    }
    public TerraBaseEvidenceScope Scope{get;} public TerraBaseProof ApplicationConsistent{get;} public TerraBaseProof DigestVerified{get;} public TerraBaseProof ObjectVerified{get;} public bool IsValid{get;}
    public IReadOnlyList<TerraBaseBackupSegment> Segments=>Array.AsReadOnly(_segments);
}

public static class TerraBaseBackupPlanner
{
    public static TerraBaseDecision Accept(TerraBaseEvidenceScope expected,TerraBaseBackupEvidence? evidence)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(evidence is null||!evidence.IsValid||evidence.Scope!=expected)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(evidence.ApplicationConsistent!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ApplicationConsistencyRequired,trace);
        if(evidence.DigestVerified!=TerraBaseProof.Proven||evidence.ObjectVerified!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.DigestProofMissing,trace);
        var subject=new TerraBaseBackupSubject(expected.Cell,expected.Database,expected.DatabaseGeneration,expected.TopologyGeneration);
        var ordered=evidence.Segments.OrderBy(x=>x.Sequence.Value).ToArray();
        if(ordered.Any(x=>x.Subject!=subject||x.Digest is null||x.Object is null||x.EncryptionKey is null))return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(!ordered[0].IsFull||ordered[0].ParentSequence is not null)return TerraBaseDecision.Hold(TerraBaseCode.ChainGap,trace);
        for(var i=1;i<ordered.Length;i++)if(ordered[i].IsFull||ordered[i].Sequence.Value!=ordered[i-1].Sequence.Value+1||ordered[i].ParentSequence!=ordered[i-1].Sequence)
            return TerraBaseDecision.Hold(TerraBaseCode.ChainGap,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.Backup,TerraBaseTarget.BackupChain,TerraBaseCode.Completed,trace);
    }
}

public sealed record TerraBaseRestoreEvidence(TerraBaseEvidenceScope Scope,TerraBaseRestoreId Restore,
    TerraBaseOrdinal SourceGeneration,TerraBaseOrdinal TargetGeneration,TerraBaseProof SideBySide,
    TerraBaseProof RestoreApplied,TerraBaseProof ChainAccepted,TerraBaseProof DigestsVerified,TerraBaseProof TopologyVerified,
    TerraBaseProof QueryVerified,TerraBaseProof PromotionAuthorized);
public static class TerraBaseRestorePlanner
{
    public static TerraBaseDecision Plan(TerraBaseEvidenceScope expected,TerraBaseRestoreEvidence? e)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(e is null||e.Scope!=expected)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(e.SideBySide!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.SideBySideRequired,trace);
        if(e.SourceGeneration.Value<expected.DatabaseGeneration.Value||e.TargetGeneration.Value<=expected.DatabaseGeneration.Value)
            return TerraBaseDecision.Hold(TerraBaseCode.AntiRollback,trace);
        if(e.RestoreApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Restore,TerraBaseTarget.RestoreCandidate,TerraBaseCode.NextStep,trace);
        if(e.ChainAccepted!=TerraBaseProof.Proven||e.DigestsVerified!=TerraBaseProof.Proven||e.TopologyVerified!=TerraBaseProof.Proven||e.QueryVerified!=TerraBaseProof.Proven)
            return TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.RestoreCandidate,TerraBaseCode.NextStep,trace);
        if(e.PromotionAuthorized!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.PromotionProofMissing,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.RestoreCandidate,TerraBaseCode.Completed,trace);
    }
}
