using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SecurityThirdAuditRegressionTests
{
    [Test]
    public async Task Accepted_authorization_intent_retains_exact_selected_provenance()
    {
        var operation=new SecurityOperationId("operation");var principalId=new SecurityPrincipalId("principal");var cell=new SecurityCellId("gru");
        var evidencePrincipalGeneration=new SecurityGeneration(5);var expectedPrincipalGeneration=new SecurityGeneration(5);var currentPrincipalGeneration=new SecurityGeneration(5);
        var grantPolicyGeneration=new SecurityGeneration(3);var policyGeneration=new SecurityGeneration(3);var currentPolicyGeneration=new SecurityGeneration(3);
        var evidenceRevocationGeneration=new SecurityGeneration(7);var currentRevocationGeneration=new SecurityGeneration(7);
        var scope=new SecurityResourceScope(SecurityResourceKind.Certificate,cell,SecurityEnvironment.Production,null);
        var principal=new SecurityPrincipal(principalId,SecurityPrincipalKind.Node,SecurityRole.Agent,cell,evidencePrincipalGeneration);
        var evidence=new PrincipalAuthorizationEvidence(principal,evidenceRevocationGeneration,RevocationStatus.Current,EvidenceStatus.Valid);
        var grant=new AuthorizationGrant(grantPolicyGeneration,SecurityPrincipalKind.Node,SecurityRole.Agent,AuthorizationCapability.RenewIdentity,scope);
        var request=new AuthorizationRequest(operation,principalId,expectedPrincipalGeneration,currentPrincipalGeneration,AuthorizationCapability.RenewIdentity,scope,
            policyGeneration,currentPolicyGeneration,currentRevocationGeneration,[evidence],[grant],EvidenceStatus.Valid);
        var decision=SecurityDecisionEngine.Authorize(request);
        await Assert.That(decision.Authorized).IsTrue();
        var intent=(AuthorizeCapabilityIntent)decision.Intent;
        await Assert.That(ReferenceEquals(intent.OperationId,operation)).IsTrue();
        await Assert.That(ReferenceEquals(intent.PrincipalId,principalId)).IsTrue();
        await Assert.That(ReferenceEquals(intent.ResourceScope,scope)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Evidence,evidence)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Evidence.Principal.Generation,evidencePrincipalGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Evidence.RevocationGeneration,evidenceRevocationGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Grant,grant)).IsTrue();
        await Assert.That(ReferenceEquals(intent.Grant.PolicyGeneration,grantPolicyGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.ExpectedPrincipalGeneration,expectedPrincipalGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.CurrentPrincipalGeneration,currentPrincipalGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.PolicyGeneration,policyGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.CurrentPolicyGeneration,currentPolicyGeneration)).IsTrue();
        await Assert.That(ReferenceEquals(intent.CurrentRevocationGeneration,currentRevocationGeneration)).IsTrue();
    }

    [Test]
    public async Task Accepted_authorization_intent_is_sensitive_to_every_provenance_group_and_semantically_replay_stable()
    {
        var operation=new SecurityOperationId("operation");var principalId=new SecurityPrincipalId("principal");var cell=new SecurityCellId("gru");
        var scope=new SecurityResourceScope(SecurityResourceKind.Certificate,cell,SecurityEnvironment.Production,null);
        static (SecurityGeneration Principal,SecurityGeneration Policy,SecurityGeneration Revocation) Generations(ulong p=5,ulong policy=3,ulong revocation=7)=>
            (new(p),new(policy),new(revocation));
        var numbers=Generations();
        AuthorizeCapabilityIntent Intent(SecurityPrincipalKind kind,SecurityRole role,(SecurityGeneration Principal,SecurityGeneration Policy,SecurityGeneration Revocation) values)=>
            (AuthorizeCapabilityIntent)Decide(operation,principalId,cell,scope,kind,role,values.Principal,values.Policy,values.Revocation).Decision.Intent;
        var exact=Intent(SecurityPrincipalKind.Node,SecurityRole.Agent,numbers);
        var semanticReplay=Intent(SecurityPrincipalKind.Node,SecurityRole.Agent,Generations());
        var variants=new[]{
            Intent(SecurityPrincipalKind.Workload,SecurityRole.Agent,numbers),
            Intent(SecurityPrincipalKind.Node,SecurityRole.WorkloadService,numbers),
            Intent(SecurityPrincipalKind.Node,SecurityRole.Agent,Generations(p:6)),
            Intent(SecurityPrincipalKind.Node,SecurityRole.Agent,Generations(policy:4)),
            Intent(SecurityPrincipalKind.Node,SecurityRole.Agent,Generations(revocation:8)),
        };
        foreach(var variant in variants)await Assert.That(variant).IsNotEqualTo(exact);
        await Assert.That(semanticReplay).IsEqualTo(exact);
        await Assert.That(semanticReplay.GetHashCode()).IsEqualTo(exact.GetHashCode());
    }

    [Test]
    public async Task Authorization_intent_provenance_is_closed_and_redacted()
    {
        var type=typeof(AuthorizeCapabilityIntent);
        await Assert.That(type.GetConstructors(BindingFlags.Public|BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties().All(property=>property.SetMethod is null)).IsTrue();
        await Assert.That(type.GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.Static).Where(method=>method.Name=="Deconstruct")).IsEmpty();
        var publicReturning=type.Assembly.GetExportedTypes()
            .SelectMany(candidate=>candidate.GetMethods(BindingFlags.Public|BindingFlags.Instance|BindingFlags.Static|BindingFlags.DeclaredOnly))
            .Where(method=>method.ReturnType==type).ToArray();
        await Assert.That(publicReturning.Where(method=>method.Name!="<Clone>$"&&!method.IsSpecialName)).IsEmpty();
        await Assert.That(publicReturning.Count(method=>method.Name=="<Clone>$"&&method.GetParameters().Length==0)).IsEqualTo(1);
        var values=Decide(new("operation"),new("principal"),new("gru"),
            new(SecurityResourceKind.Certificate,new("gru"),SecurityEnvironment.Production,null),SecurityPrincipalKind.Node,SecurityRole.Agent,new(5),new(3),new(7));
        await Assert.That(values.Decision.Intent.ToString()).IsEqualTo("<authorize-capability-intent>");
        await Assert.That(values.Decision.Intent.ToString()).DoesNotContain("principal");
    }

    private static (PrincipalAuthorizationEvidence Evidence,AuthorizationGrant Grant,SecurityDecision Decision) Decide(
        SecurityOperationId operation,SecurityPrincipalId principalId,SecurityCellId cell,SecurityResourceScope scope,
        SecurityPrincipalKind kind,SecurityRole role,SecurityGeneration generation,SecurityGeneration policy,SecurityGeneration revocation)
    {
        var principal=new SecurityPrincipal(principalId,kind,role,cell,generation);
        var evidence=new PrincipalAuthorizationEvidence(principal,revocation,RevocationStatus.Current,EvidenceStatus.Valid);
        var grant=new AuthorizationGrant(policy,kind,role,AuthorizationCapability.RenewIdentity,scope);
        var request=new AuthorizationRequest(operation,principalId,generation,generation,AuthorizationCapability.RenewIdentity,scope,
            policy,policy,revocation,[evidence],[grant],EvidenceStatus.Valid);
        return(evidence,grant,SecurityDecisionEngine.Authorize(request));
    }
}

