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
    public TerraBaseEvidenceScope Scope{get;} public TerraBaseProof ApplicationConsistent{get;} public TerraBaseProof DigestVerified{get;}
    public TerraBaseProof ObjectVerified{get;} public bool IsValid{get;}
    public IReadOnlyList<TerraBaseBackupSegment> Segments=>Array.AsReadOnly(_segments);
}

public sealed record TerraBaseBackupRequestEvidence(TerraBaseEvidenceScope Scope,TerraBaseBackupId Backup,
    TerraBaseOrdinal Sequence,TerraBaseOrdinal? ParentSequence,TerraBaseBackupId? ParentBackup,
    TerraBaseBackupEvidence? ParentChain,bool IsFull,TerraBaseObjectRef Destination,
    TerraBaseKeyRef EncryptionKey,TerraBaseProof ApplicationConsistencyReady,TerraBaseProof NoConflictingOperation);

public sealed record TerraBaseBackupChainIntentSubject:TerraBaseIntentSubject
{
    private readonly TerraBaseBackupSegment[] _segments;
    internal TerraBaseBackupChainIntentSubject(TerraBaseEvidenceScope scope,IEnumerable<TerraBaseBackupSegment> segments)
    {Scope=scope;_segments=segments.ToArray();}
    public override TerraBaseEvidenceScope Scope{get;}
    public IReadOnlyList<TerraBaseBackupSegment> Segments=>Array.AsReadOnly(_segments);
    public TerraBaseBackupId TerminalBackup=>_segments[^1].Backup;
    public bool Equals(TerraBaseBackupChainIntentSubject? other)=>other is not null&&Scope==other.Scope&&_segments.SequenceEqual(other._segments);
    public override int GetHashCode()
    {
        var hash=new HashCode(); hash.Add(Scope); foreach(var segment in _segments)hash.Add(segment); return hash.ToHashCode();
    }
    public override string ToString()=>"<terrabase-backup-chain-intent>";
}

public static class TerraBaseBackupPlanner
{
    public static TerraBaseDecision Authorize(TerraBaseEvidenceScope expected,TerraBaseBackupRequestEvidence? request)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(request is null||request.Scope!=expected)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(request.Backup is null||!request.Sequence.IsValid||request.Destination is null||request.EncryptionKey is null
            ||(request.IsFull&&(request.ParentSequence is not null||request.ParentBackup is not null||request.ParentChain is not null))
            ||(!request.IsFull&&(request.ParentSequence is null||!request.ParentSequence.Value.IsValid||request.ParentBackup is null||request.ParentChain is null)))
            return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(request.ApplicationConsistencyReady!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ApplicationConsistencyRequired,trace);
        if(request.NoConflictingOperation!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ConflictingTopologyMutation,trace);
        if(!request.IsFull)
        {
            var parentCode=Validate(expected,request.ParentChain,false,out var parent);
            if(parentCode!=TerraBaseCode.Completed)return TerraBaseDecision.Hold(parentCode,trace);
            if(parent[^1].Sequence!=request.ParentSequence||parent[^1].Backup!=request.ParentBackup
                ||request.Sequence.Value!=request.ParentSequence!.Value.Value+1)
                return TerraBaseDecision.Hold(TerraBaseCode.ChainGap,trace);
        }
        return TerraBaseDecision.Emit(TerraBaseAction.Backup,TerraBaseTarget.BackupChain,TerraBaseCode.NextStep,trace,
            new TerraBaseBackupRequestIntentSubject(expected,request.Backup,request.Sequence,request.ParentSequence,request.ParentBackup,request.Destination,request.EncryptionKey));
    }

    public static TerraBaseDecision Accept(TerraBaseEvidenceScope expected,TerraBaseBackupEvidence? evidence)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        var code=Validate(expected,evidence,true,out var ordered);
        if(code!=TerraBaseCode.Completed)return TerraBaseDecision.Hold(code,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.BackupChain,TerraBaseCode.Completed,trace,
            new TerraBaseBackupChainIntentSubject(expected,ordered));
    }

    internal static TerraBaseCode Validate(TerraBaseEvidenceScope expected,TerraBaseBackupEvidence? evidence,
        bool exactOperation,out TerraBaseBackupSegment[] ordered)
    {
        ordered=[];
        if(evidence is null||!evidence.IsValid)return TerraBaseCode.WrongEvidenceScope;
        if(exactOperation ? evidence.Scope!=expected : evidence.Scope.Cell!=expected.Cell||evidence.Scope.Database!=expected.Database
            ||evidence.Scope.DatabaseGeneration!=expected.DatabaseGeneration||evidence.Scope.TopologyGeneration!=expected.TopologyGeneration)
            return TerraBaseCode.WrongEvidenceScope;
        if(evidence.ApplicationConsistent!=TerraBaseProof.Proven)return TerraBaseCode.ApplicationConsistencyRequired;
        if(evidence.DigestVerified!=TerraBaseProof.Proven||evidence.ObjectVerified!=TerraBaseProof.Proven)return TerraBaseCode.DigestProofMissing;
        var subject=new TerraBaseBackupSubject(expected.Cell,expected.Database,expected.DatabaseGeneration,expected.TopologyGeneration);
        ordered=evidence.Segments.OrderBy(x=>x.Sequence.Value).ToArray();
        if(ordered.Any(x=>x.Subject is null||x.Subject!=subject||x.Backup is null||!x.Sequence.IsValid
            ||(x.ParentSequence is not null&&!x.ParentSequence.Value.IsValid)||x.Digest is null||x.Object is null||x.EncryptionKey is null))
            return TerraBaseCode.WrongEvidenceScope;
        if(ordered.Select(x=>x.Backup).Distinct().Count()!=ordered.Length||ordered.Select(x=>x.Sequence).Distinct().Count()!=ordered.Length)
            return TerraBaseCode.ChainGap;
        if(!ordered[0].IsFull||ordered[0].ParentSequence is not null)return TerraBaseCode.ChainGap;
        for(var i=1;i<ordered.Length;i++)if(ordered[i].IsFull||ordered[i].Sequence.Value!=ordered[i-1].Sequence.Value+1||ordered[i].ParentSequence!=ordered[i-1].Sequence)
            return TerraBaseCode.ChainGap;
        return TerraBaseCode.Completed;
    }
}

public sealed record TerraBaseRestoreEvidence(TerraBaseEvidenceScope Scope,TerraBaseRestoreId Restore,
    TerraBaseOrdinal SourceGeneration,TerraBaseOrdinal TargetGeneration,TerraBaseBackupEvidence Chain,
    TerraBaseProof SideBySide,TerraBaseProof RestoreApplied,TerraBaseProof TopologyVerified,
    TerraBaseProof QueryVerified,TerraBaseProof PromotionAuthorized);

public sealed record TerraBaseRestoreIntentSubject:TerraBaseIntentSubject
{
    internal TerraBaseRestoreIntentSubject(TerraBaseEvidenceScope scope,TerraBaseRestoreId restore,TerraBaseOrdinal source,
        TerraBaseOrdinal target,TerraBaseBackupChainIntentSubject chain){Scope=scope;Restore=restore;SourceGeneration=source;TargetGeneration=target;Chain=chain;}
    public override TerraBaseEvidenceScope Scope{get;} public TerraBaseRestoreId Restore{get;} public TerraBaseOrdinal SourceGeneration{get;}
    public TerraBaseOrdinal TargetGeneration{get;} public TerraBaseBackupChainIntentSubject Chain{get;}
    public override string ToString()=>"<terrabase-restore-intent>";
}

public static class TerraBaseRestorePlanner
{
    public static TerraBaseDecision Plan(TerraBaseEvidenceScope expected,TerraBaseRestoreId expectedRestore,
        TerraBaseBackupId expectedTerminalBackup,TerraBaseOrdinal expectedTargetGeneration,TerraBaseRestoreEvidence? e)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(e is null||e.Scope!=expected||e.Restore!=expectedRestore||e.TargetGeneration!=expectedTargetGeneration
            ||expectedTerminalBackup is null||!e.SourceGeneration.IsValid||!e.TargetGeneration.IsValid)
            return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(e.SideBySide!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.SideBySideRequired,trace);
        if(e.SourceGeneration.Value<expected.DatabaseGeneration.Value||e.TargetGeneration.Value<=expected.DatabaseGeneration.Value)
            return TerraBaseDecision.Hold(TerraBaseCode.AntiRollback,trace);
        if(e.SourceGeneration!=expected.DatabaseGeneration)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        var chainCode=TerraBaseBackupPlanner.Validate(expected,e.Chain,false,out var ordered);
        if(chainCode!=TerraBaseCode.Completed)return TerraBaseDecision.Hold(chainCode,trace);
        if(ordered[^1].Backup!=expectedTerminalBackup)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        var chainSubject=new TerraBaseBackupChainIntentSubject(e.Chain.Scope,ordered);
        var subject=new TerraBaseRestoreIntentSubject(expected,e.Restore,e.SourceGeneration,e.TargetGeneration,chainSubject);
        if(e.RestoreApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Restore,TerraBaseTarget.RestoreCandidate,TerraBaseCode.NextStep,trace,subject);
        if(e.TopologyVerified!=TerraBaseProof.Proven||e.QueryVerified!=TerraBaseProof.Proven)
            return TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.RestoreCandidate,TerraBaseCode.NextStep,trace,subject);
        if(e.PromotionAuthorized!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.PromotionProofMissing,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.RestoreCandidate,TerraBaseCode.Completed,trace,subject);
    }
}
