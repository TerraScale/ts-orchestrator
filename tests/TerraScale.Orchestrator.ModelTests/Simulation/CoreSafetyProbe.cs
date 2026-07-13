using TerraScale.Orchestrator.ControlPlane.Compute;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Authority;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

public static class CoreSafetyProbe
{
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    public static bool AuthorityRequiresObservedCasBeforeMutationPermit()
    {
        var baseline = new AuthorityObservation("regional-authority", 0, 0, "genesis", null);
        var command = new AcquireAuthority("regional-authority", "candidate-a", "request-a", "lease-a", baseline,
            new AuthorityHealth(Start, TimeSpan.Zero, true, true), TimeSpan.FromMinutes(5));
        var decision = AuthorityEngine.Decide([], command);
        return decision.MutationPermit is null && decision.Intents.Single() is CompareAndSetLeaseIntent;
    }

    public static bool OperationCannotDispatchWithoutDurablePreparation()
    {
        var decision = OperationEngine.Decide([], new RecordDispatch("operation-1", 1, Start, "executor-1", 1));
        return decision.Intents.Count == 0 && decision.Errors.Count > 0;
    }

    public static bool ProviderCannotMutateWithoutRegionalAuthority()
    {
        var cell = new ProviderCellId("gru");
        var compartment = new ProviderCompartmentId("gru-compartment");
        var resource = new TerraScale.Orchestrator.ControlPlane.Providers.ProviderResourceId("node-1");
        var generation = new ProviderGeneration(7);
        var context = new ProviderOperationContext(new("operation-1"), cell, compartment, new(5),
            ProviderResourceKind.Node, ProviderAction.TerminateNode, new ExistingProviderResource(resource), generation,
            ProviderObservedState.Running, ProviderTerminalState.Terminated,
            [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation],
            new(DeadlineEvidenceStatus.Valid, new(1)), new("idempotency-1"), [ProviderCompensation.ObserveOnly],
            new TerminateNodeProviderParameters());
        var request = new ProviderAuthorizationRequest(context, null,
            [new ProviderOwnershipRecord(resource, cell, compartment, generation)], [],
            ProviderObservationCompleteness.Complete,
            [new ProviderResourceObservation(resource, generation, ProviderObservedState.Running)], [],
            [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation], null,
            new(ProviderCallStatus.NotCalled, null));
        var decision = ProviderOwnershipEngine.Authorize(request);
        return !decision.Authorized && decision.Intents.Count == 0;
    }

    public static bool ComputeUnknownOutcomeObservesWithoutSecondCreate()
    {
        var binding = new ComputeBinding(new("gru"), new("app"), new("template"), new("shape"), new("domain"),
            new("artifact"), new("digest"), new("demand"), new("operation"), new("provider"), 1, 1);
        var resources = new TerraScale.Orchestrator.ControlPlane.Compute.ResourceEnvelope(1, 1024, 10, 100);
        var plan = new ScaleOutPlan(binding, resources, 1, new("plan"));
        var persisted = new PersistedScaleOutPlan(plan, new("persisted"));
        var authorization = new CapacityAuthorization(binding, resources, 1, new("budget"), new("quota"),
            new("capacity"), new("cost"), new("placement"), true, true, true, true, true);
        var demand = new DemandEvidence(binding, ComputeTrigger.FailedHostReplacement, 5, 5, 1, true, false, true);
        var observation = new ProviderCreateEvidence(binding, new("create-key"), ProviderCreateStatus.OutcomeUnknown,
            null, new("work-request"), new("observation"));
        var decision = ComputeEngine.DecideScaleOut(new(binding, ScaleOutState.RequestRecorded, demand, plan,
            persisted, authorization, observation, null, 6, 64));
        return decision.Errors.Count == 0 && decision.Intents.Count == 1 &&
            decision.Intents[0] is ObserveCreateIntent && decision.Intents.All(static item => item is not RequestCreateIntent);
    }

    public static bool DuplicateDeliveryIsIdempotent()
    {
        var source = new SourceRevision(new("source"), new("develop"), new("commit"), new("tree"), new("manifest"),
            1, new("digest"), new("signature"), [new(new("dependency"), 1, new("dependency-digest"))]);
        var decision = DeliveryEngine.DecideSource(new(source, source, null, 64));
        return decision.Errors.Count == 0 && decision.Intents.Count == 0 &&
            decision.Trace.Single().Code == DeliveryTraceCode.Idempotent;
    }

    public static bool UntrustedDeliveryCannotAcquireProductionAuthority()
    {
        var job = new JobRequest(new("pipeline"), new("job"), JobKind.ProductValidation, new("tree"), 1, 1, 2,
            new("idempotency"), [TrustZone.ProductionRelease], [RunnerCapability.ProductionDeploy], 1, 2, false);
        var runner = new RunnerEvidence(new("runner"), TrustZone.ProductionRelease, 1, true,
            [RunnerCapability.ProductionDeploy]);
        var decision = DeliveryEngine.DecideJob(job, [runner], 64);
        return decision.Errors.Any(static error => error.Code == DeliveryErrorCode.TrustZoneDenied) &&
            decision.Intents.Single() is HoldDeliveryIntent;
    }
}
