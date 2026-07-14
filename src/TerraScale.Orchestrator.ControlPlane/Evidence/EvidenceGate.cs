namespace TerraScale.Orchestrator.ControlPlane.Evidence;

public enum EvidenceSignatureVerificationOutcome{Unknown=0,Valid=1,Invalid=2}

public sealed record EvidenceSignedMaterial(EvidenceSha256 PayloadDigest,EvidenceSigningProfileId SigningProfile,
    EvidenceSigningIdentityId SigningIdentity,EvidenceSignatureId SignatureIdentity,EvidenceGeneration Generation,EvidenceSequence ExpirySequence)
{public override string ToString()=>"<evidence-signed-material>";}

public sealed class EvidenceSignedEnvelope
{
    public EvidenceSignedEnvelope(EvidenceSignedMaterial material,EvidenceOpaqueSignature signature)
    {Material=material;Signature=signature;IsWellFormed=material is not null&&material.PayloadDigest is not null&&material.SigningProfile is not null
        &&material.SigningIdentity is not null&&material.SignatureIdentity is not null&&material.Generation.IsValid&&material.ExpirySequence.IsValid&&signature is {IsValid:true};}
    public EvidenceSignedMaterial Material{get;}public EvidenceOpaqueSignature Signature{get;}public bool IsWellFormed{get;}
    public override string ToString()=>"<signed-evidence-envelope>";
}

public interface IEvidenceSignatureVerifier
{
    EvidenceSignatureVerificationOutcome Verify(EvidenceSignedMaterial material,EvidenceOpaqueSignature signature);
}

public sealed class EvidenceGateContext
{
    public EvidenceGateContext(EvidenceManifestId expectedManifest,EvidenceSubject expectedSubject,EvidenceSha256 expectedPayloadDigest,EvidenceSigningProfileId expectedSigningProfile,
        EvidenceSigningIdentityId expectedSigningIdentity,EvidenceSignatureId expectedSignatureIdentity,EvidenceGeneration expectedGeneration,
        EvidenceSequence expectedExpirySequence,EvidenceSequence currentSequence,EvidenceGateTarget target,IEvidenceSignatureVerifier verifier)
    {ExpectedManifest=expectedManifest;ExpectedSubject=expectedSubject;ExpectedPayloadDigest=expectedPayloadDigest;ExpectedSigningProfile=expectedSigningProfile;ExpectedSigningIdentity=expectedSigningIdentity;
        ExpectedSignatureIdentity=expectedSignatureIdentity;ExpectedGeneration=expectedGeneration;ExpectedExpirySequence=expectedExpirySequence;CurrentSequence=currentSequence;Target=target;Verifier=verifier;
        IsWellFormed=expectedManifest is not null&&expectedSubject is {IsWellFormed:true}&&expectedPayloadDigest is not null&&expectedSigningProfile is not null&&expectedSigningIdentity is not null
            &&expectedSignatureIdentity is not null&&expectedGeneration.IsValid&&expectedExpirySequence.IsValid&&currentSequence.IsValid&&Enum.IsDefined(target)&&target!=EvidenceGateTarget.Unknown&&verifier is not null;}
    public EvidenceManifestId ExpectedManifest{get;}public EvidenceSubject ExpectedSubject{get;}public EvidenceSha256 ExpectedPayloadDigest{get;}public EvidenceSigningProfileId ExpectedSigningProfile{get;}
    public EvidenceSigningIdentityId ExpectedSigningIdentity{get;}public EvidenceSignatureId ExpectedSignatureIdentity{get;}public EvidenceGeneration ExpectedGeneration{get;}
    public EvidenceSequence ExpectedExpirySequence{get;}public EvidenceSequence CurrentSequence{get;}public EvidenceGateTarget Target{get;}public IEvidenceSignatureVerifier Verifier{get;}public bool IsWellFormed{get;}
}

public sealed record EvidenceNumericTrace(EvidenceGeneration Generation,EvidenceSequence CurrentSequence,EvidenceSequence ExpirySequence,
    ulong DomainCount,ulong TestBinaryCount)
{public override string ToString()=>"<evidence-numeric-trace>";}
public sealed record EvidenceDecisionSubject
{internal EvidenceDecisionSubject(EvidenceSha256 digest)=>PayloadDigest=digest;public EvidenceSha256 PayloadDigest{get;}public override string ToString()=>"<evidence-decision-subject>";}

public sealed record EvidenceDecision
{
    private EvidenceDecision(EvidenceAction action,EvidenceCode code,EvidenceDecisionSubject? subject,EvidenceNumericTrace? trace)
    {Action=action;Code=code;Subject=subject;Trace=trace;}
    public EvidenceAction Action{get;}public EvidenceCode Code{get;}public EvidenceDecisionSubject? Subject{get;}public EvidenceNumericTrace? Trace{get;}
    public bool IsAuthorized=>Action is EvidenceAction.AllowDependencyConformance or EvidenceAction.AllowL1SCredentialRelease;
    internal static EvidenceDecision Hold(EvidenceCode code,EvidenceNumericTrace? trace=null)=>new(EvidenceAction.Hold,code,null,trace);
    internal static EvidenceDecision Allow(EvidenceAction action,EvidenceSha256 digest,EvidenceNumericTrace trace)=>new(action,EvidenceCode.Allowed,new(digest),trace);
    public override string ToString()=>"<evidence-decision>";
}

public static class PreDeploymentEvidenceGate
{
    public static EvidenceDecision Verify(EvidenceManifest? manifest,EvidencePolicy? policy,EvidenceSignedEnvelope? envelope,EvidenceGateContext? context)
    {
        if(manifest is not {IsWellFormed:true}||policy is not {IsWellFormed:true}||envelope is not {IsWellFormed:true}||context is not {IsWellFormed:true})
            return EvidenceDecision.Hold(EvidenceCode.InvalidInput);
        var trace=new EvidenceNumericTrace(envelope.Material.Generation,context.CurrentSequence,envelope.Material.ExpirySequence,
            (ulong)manifest.Subject.Suites.Count,(ulong)manifest.Subject.TestBinaries.Count);
        if(manifest.Identity!=context.ExpectedManifest||!manifest.Subject.ExactEquals(context.ExpectedSubject)||!manifest.CanonicalPayloadDigest.Equals(context.ExpectedPayloadDigest)
            ||!envelope.Material.PayloadDigest.Equals(manifest.CanonicalPayloadDigest))return EvidenceDecision.Hold(EvidenceCode.WrongSubject,trace);
        var policyResult=EvidencePolicyEvaluator.Evaluate(manifest,policy);if(!policyResult.IsAccepted)return EvidenceDecision.Hold(policyResult.Code,trace);
        if(envelope.Material.SigningProfile!=context.ExpectedSigningProfile)return EvidenceDecision.Hold(EvidenceCode.WrongSigningProfile,trace);
        if(envelope.Material.SigningIdentity!=context.ExpectedSigningIdentity)return EvidenceDecision.Hold(EvidenceCode.WrongSigningIdentity,trace);
        if(envelope.Material.SignatureIdentity!=context.ExpectedSignatureIdentity)return EvidenceDecision.Hold(EvidenceCode.WrongSignature,trace);
        if(envelope.Material.Generation.Value<context.ExpectedGeneration.Value)return EvidenceDecision.Hold(EvidenceCode.StaleGeneration,trace);
        if(envelope.Material.Generation.Value>context.ExpectedGeneration.Value)return EvidenceDecision.Hold(EvidenceCode.FutureGeneration,trace);
        if(envelope.Material.ExpirySequence.Value<context.ExpectedExpirySequence.Value)return EvidenceDecision.Hold(EvidenceCode.StaleExpiry,trace);
        if(envelope.Material.ExpirySequence.Value>context.ExpectedExpirySequence.Value)return EvidenceDecision.Hold(EvidenceCode.FutureExpiry,trace);
        if(context.CurrentSequence.Value>envelope.Material.ExpirySequence.Value)return EvidenceDecision.Hold(EvidenceCode.Expired,trace);
        EvidenceSignatureVerificationOutcome verification;
        try{verification=context.Verifier.Verify(envelope.Material,envelope.Signature);}
        catch(Exception exception)when(exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException){return EvidenceDecision.Hold(EvidenceCode.SignatureVerificationFailed,trace);}
        if(verification==EvidenceSignatureVerificationOutcome.Invalid)return EvidenceDecision.Hold(EvidenceCode.InvalidSignature,trace);
        if(verification!=EvidenceSignatureVerificationOutcome.Valid)return EvidenceDecision.Hold(EvidenceCode.SignatureVerificationFailed,trace);
        if(context.Target==EvidenceGateTarget.L1SCredentialRelease&&manifest.Lane!=EvidenceLane.Full)
            return EvidenceDecision.Hold(EvidenceCode.FeatureLaneCannotRelease,trace);
        var action=context.Target==EvidenceGateTarget.DependencyConformance?EvidenceAction.AllowDependencyConformance:EvidenceAction.AllowL1SCredentialRelease;
        return EvidenceDecision.Allow(action,manifest.CanonicalPayloadDigest,trace);
    }
}
