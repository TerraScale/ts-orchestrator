using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Evidence;
using TerraScale.Orchestrator.ControlPlane.Networking;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class AcceptedOutputConstructionClosureTests
{
    private static readonly HashSet<string> ReviewedAcceptedOutputFactories = new(StringComparer.Ordinal)
    {
        "instance TerraScale.Orchestrator.ControlPlane.Providers.ProviderAuthorizationDecision.CaptureDurableAuthorization() -> TerraScale.Orchestrator.ControlPlane.Providers.DurableProviderAuthorization",
        "static TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEngine.Decide(System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEvent>,TerraScale.Orchestrator.ControlPlane.Authority.AuthorityCommand) -> TerraScale.Orchestrator.ControlPlane.Authority.AuthorityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEngine.Replay(System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEvent>) -> TerraScale.Orchestrator.ControlPlane.Authority.AuthorityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Budgets.BudgetAuthorizationEngine.Evaluate(TerraScale.Orchestrator.ControlPlane.Budgets.BudgetPolicy,TerraScale.Orchestrator.ControlPlane.Budgets.BudgetProposal,System.Collections.Generic.IEnumerable<TerraScale.Orchestrator.ControlPlane.Budgets.BudgetUsageObservation>,System.Collections.Generic.IEnumerable<TerraScale.Orchestrator.ControlPlane.Budgets.NodeClassUsageObservation>,System.Collections.Generic.IEnumerable<TerraScale.Orchestrator.ControlPlane.Budgets.PriceEvidenceObservation>) -> TerraScale.Orchestrator.ControlPlane.Budgets.BudgetDecision",
        "static TerraScale.Orchestrator.ControlPlane.Compute.ComputeEngine.DecideScaleIn(TerraScale.Orchestrator.ControlPlane.Compute.ScaleInRequest) -> TerraScale.Orchestrator.ControlPlane.Compute.ComputeDecision",
        "static TerraScale.Orchestrator.ControlPlane.Compute.ComputeEngine.DecideScaleOut(TerraScale.Orchestrator.ControlPlane.Compute.ScaleOutRequest) -> TerraScale.Orchestrator.ControlPlane.Compute.ComputeDecision",
        "static TerraScale.Orchestrator.ControlPlane.Compute.ComputeEngine.DecideSurvival(TerraScale.Orchestrator.ControlPlane.Compute.SurvivalRequest) -> TerraScale.Orchestrator.ControlPlane.Compute.ComputeDecision",
        "static TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryEngine.DecideJob(TerraScale.Orchestrator.ControlPlane.Delivery.JobRequest,System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Delivery.RunnerEvidence>,System.Int32) -> TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryDecision",
        "static TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryEngine.DecidePromotion(TerraScale.Orchestrator.ControlPlane.Delivery.PromotionRequest) -> TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryDecision",
        "static TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryEngine.DecideRollout(TerraScale.Orchestrator.ControlPlane.Delivery.RolloutRequest) -> TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryDecision",
        "static TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryEngine.DecideSource(TerraScale.Orchestrator.ControlPlane.Delivery.SourceDecisionRequest) -> TerraScale.Orchestrator.ControlPlane.Delivery.DeliveryDecision",
        "static TerraScale.Orchestrator.ControlPlane.Evidence.PreDeploymentEvidenceGate.Verify(TerraScale.Orchestrator.ControlPlane.Evidence.EvidenceManifest,TerraScale.Orchestrator.ControlPlane.Evidence.EvidencePolicy,TerraScale.Orchestrator.ControlPlane.Evidence.EvidenceSignedEnvelope,TerraScale.Orchestrator.ControlPlane.Evidence.EvidenceGateContext) -> TerraScale.Orchestrator.ControlPlane.Evidence.EvidenceDecision",
        "static TerraScale.Orchestrator.ControlPlane.Messaging.MessagingPolicyEngine.DecideCompatibility(System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Messaging.CompatibilityFeature>,TerraScale.Orchestrator.ControlPlane.Messaging.CompatibilityPolicy) -> TerraScale.Orchestrator.ControlPlane.Messaging.MessagingDecision",
        "static TerraScale.Orchestrator.ControlPlane.Messaging.MessagingPolicyEngine.DecidePartition(TerraScale.Orchestrator.ControlPlane.Messaging.PartitionRequest) -> TerraScale.Orchestrator.ControlPlane.Messaging.MessagingDecision",
        "static TerraScale.Orchestrator.ControlPlane.Messaging.MessagingPolicyEngine.DecideReplacement(TerraScale.Orchestrator.ControlPlane.Messaging.ReplacementRequest) -> TerraScale.Orchestrator.ControlPlane.Messaging.MessagingDecision",
        "static TerraScale.Orchestrator.ControlPlane.Messaging.MessagingPolicyEngine.DecideTopology(TerraScale.Orchestrator.ControlPlane.Messaging.MessagingTopologyPolicy) -> TerraScale.Orchestrator.ControlPlane.Messaging.MessagingDecision",
        "static TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanEmergencyWithdrawal(TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointScope,TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointEvidence) -> TerraScale.Orchestrator.ControlPlane.Networking.NetworkDecision",
        "static TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanRegister(TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointScope,TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointEvidence) -> TerraScale.Orchestrator.ControlPlane.Networking.NetworkDecision",
        "static TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointPlanner.PlanRemoval(TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointScope,TerraScale.Orchestrator.ControlPlane.Networking.NetworkEndpointEvidence) -> TerraScale.Orchestrator.ControlPlane.Networking.NetworkDecision",
        "static TerraScale.Orchestrator.ControlPlane.Networking.NetworkRoutePlanner.Plan(TerraScale.Orchestrator.ControlPlane.Networking.NetworkRouteScope,TerraScale.Orchestrator.ControlPlane.Networking.NetworkOrdinal,TerraScale.Orchestrator.ControlPlane.Networking.NetworkOrdinal,TerraScale.Orchestrator.ControlPlane.Networking.NetworkRouteEvidence) -> TerraScale.Orchestrator.ControlPlane.Networking.NetworkDecision",
        "static TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecisionEngine.EvaluateAlertRouting(TerraScale.Orchestrator.ControlPlane.Observability.AlertRoutingRequest) -> TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecisionEngine.EvaluateGrafanaProjection(TerraScale.Orchestrator.ControlPlane.Observability.GrafanaProjectionRequest) -> TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecisionEngine.EvaluateRegionalHealth(TerraScale.Orchestrator.ControlPlane.Observability.RegionalHealthRequest) -> TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecisionEngine.EvaluateTelemetryAdmission(TerraScale.Orchestrator.ControlPlane.Observability.TelemetryAdmissionRequest) -> TerraScale.Orchestrator.ControlPlane.Observability.ObservabilityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Operations.OperationEngine.Decide(System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Operations.OperationEvent>,TerraScale.Orchestrator.ControlPlane.Operations.OperationCommand) -> TerraScale.Orchestrator.ControlPlane.Operations.OperationDecision",
        "static TerraScale.Orchestrator.ControlPlane.Operations.OperationEngine.Replay(System.Collections.Generic.IReadOnlyList<TerraScale.Orchestrator.ControlPlane.Operations.OperationEvent>) -> TerraScale.Orchestrator.ControlPlane.Operations.OperationDecision",
        "static TerraScale.Orchestrator.ControlPlane.Providers.ProviderOwnershipEngine.Authorize(TerraScale.Orchestrator.ControlPlane.Providers.ProviderAuthorizationRequest) -> TerraScale.Orchestrator.ControlPlane.Providers.ProviderAuthorizationDecision",
        "static TerraScale.Orchestrator.ControlPlane.Providers.ProviderOwnershipEngine.EvaluateHandoff(TerraScale.Orchestrator.ControlPlane.Providers.HandoffRequest) -> TerraScale.Orchestrator.ControlPlane.Providers.HandoffDecision",
        "static TerraScale.Orchestrator.ControlPlane.Reconciliation.ReconciliationEngine.Plan(TerraScale.Orchestrator.ControlPlane.Reconciliation.ReconciliationRequest) -> TerraScale.Orchestrator.ControlPlane.Reconciliation.ReconciliationPlan",
        "static TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeDecisionEngine.EvaluateLifecycle(TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeLifecycleRequest) -> TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeDecision",
        "static TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeDecisionEngine.EvaluateSelfUpdate(TerraScale.Orchestrator.ControlPlane.Runtime.SelfUpdateRequest) -> TerraScale.Orchestrator.ControlPlane.Runtime.RuntimeDecision",
        "static TerraScale.Orchestrator.ControlPlane.Security.SecurityDecisionEngine.Authorize(TerraScale.Orchestrator.ControlPlane.Security.AuthorizationRequest) -> TerraScale.Orchestrator.ControlPlane.Security.SecurityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Security.SecurityDecisionEngine.EvaluateCertificate(TerraScale.Orchestrator.ControlPlane.Security.CertificateLifecycleRequest) -> TerraScale.Orchestrator.ControlPlane.Security.SecurityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Security.SecurityDecisionEngine.EvaluateEnrollment(TerraScale.Orchestrator.ControlPlane.Security.EnrollmentRequest) -> TerraScale.Orchestrator.ControlPlane.Security.SecurityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Security.SecurityDecisionEngine.EvaluateLease(TerraScale.Orchestrator.ControlPlane.Security.SecretLeaseRequest) -> TerraScale.Orchestrator.ControlPlane.Security.SecurityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Security.SecurityDecisionEngine.EvaluateSurvivalSecrets(TerraScale.Orchestrator.ControlPlane.Security.SurvivalSecretRequest) -> TerraScale.Orchestrator.ControlPlane.Security.SecurityDecision",
        "static TerraScale.Orchestrator.ControlPlane.Storage.StorageAttachmentPlanner.Plan(TerraScale.Orchestrator.ControlPlane.Storage.StorageVolumeRecord,TerraScale.Orchestrator.ControlPlane.Storage.StorageAuthorityContext,TerraScale.Orchestrator.ControlPlane.Storage.StorageNodeId,TerraScale.Orchestrator.ControlPlane.Storage.StorageReattachEvidence) -> TerraScale.Orchestrator.ControlPlane.Storage.StorageDecision",
        "static TerraScale.Orchestrator.ControlPlane.Storage.StorageCreatePlanner.Plan(TerraScale.Orchestrator.ControlPlane.Storage.StorageVolumeRecord,TerraScale.Orchestrator.ControlPlane.Storage.StorageAuthorityContext,TerraScale.Orchestrator.ControlPlane.Storage.StorageCreateCheckpoint,TerraScale.Orchestrator.ControlPlane.Storage.StorageFormatEvidence) -> TerraScale.Orchestrator.ControlPlane.Storage.StorageDecision",
        "static TerraScale.Orchestrator.ControlPlane.Storage.StorageDeletionPlanner.Plan(TerraScale.Orchestrator.ControlPlane.Storage.StorageVolumeRecord,TerraScale.Orchestrator.ControlPlane.Storage.StorageAuthorityContext,TerraScale.Orchestrator.ControlPlane.Storage.StorageDeletionEvidence) -> TerraScale.Orchestrator.ControlPlane.Storage.StorageDecision",
        "static TerraScale.Orchestrator.ControlPlane.Storage.StorageExpansionPlanner.Plan(TerraScale.Orchestrator.ControlPlane.Storage.StorageVolumeRecord,TerraScale.Orchestrator.ControlPlane.Storage.StorageAuthorityContext,TerraScale.Orchestrator.ControlPlane.Storage.StorageExpansionEvidence) -> TerraScale.Orchestrator.ControlPlane.Storage.StorageDecision",
        "static TerraScale.Orchestrator.ControlPlane.Storage.StorageFormatPlanner.Plan(TerraScale.Orchestrator.ControlPlane.Storage.StorageVolumeRecord,TerraScale.Orchestrator.ControlPlane.Storage.StorageAuthorityContext,TerraScale.Orchestrator.ControlPlane.Storage.StorageFormatEvidence) -> TerraScale.Orchestrator.ControlPlane.Storage.StorageDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseBackupPlanner.Accept(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseBackupEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseBackupPlanner.Authorize(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseBackupRequestEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseRestorePlanner.Plan(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseRestoreId,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseBackupId,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseOrdinal,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseRestoreEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseRetainedVolumePlanner.Plan(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseWriterEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseTopologyPlanner.PlanAdd(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseTopologyEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseTopologyPlanner.PlanRemove(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseTopologyEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
        "static TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseUpgradePlanner.Plan(TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseEvidenceScope,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseReleaseId,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseReleaseId,TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseUpgradeEvidence) -> TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseDecision",
    };

    [Test]
    public async Task Accepted_outputs_have_no_external_constructor_or_unreviewed_factory()
    {
        var assembly = typeof(PreDeploymentEvidenceGate).Assembly;
        var protectedTypes = assembly.GetExportedTypes().Where(IsAcceptedOutput).ToArray();
        var constructorViolations = protectedTypes
            .Where(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0)
            .Select(type => type.FullName!).Order(StringComparer.Ordinal).ToArray();
        await Assert.That(constructorViolations).IsEmpty();

        var factoryInventory = assembly.GetExportedTypes().SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(method => !method.IsSpecialName && method.Name != "<Clone>$")
                .Where(method => IsAcceptedOutput(method.ReturnType)))
            .Select(FactoryKey).ToHashSet(StringComparer.Ordinal);
        await Assert.That(factoryInventory.Count).IsEqualTo(ReviewedAcceptedOutputFactories.Count);
        await Assert.That(factoryInventory.Except(ReviewedAcceptedOutputFactories).Order(StringComparer.Ordinal)).IsEmpty();
        await Assert.That(ReviewedAcceptedOutputFactories.Except(factoryInventory).Order(StringComparer.Ordinal)).IsEmpty();

        var mutabilityViolations = protectedTypes
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(property => property.SetMethod?.IsPublic == true)
                .Select(property => $"{type.FullName}.{property.Name}"))
            .Order(StringComparer.Ordinal).ToArray();
        await Assert.That(mutabilityViolations).IsEmpty();

        var deconstructionViolations = protectedTypes
            .Where(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Any(method => method.Name == "Deconstruct"))
            .Select(type => type.FullName!).Order(StringComparer.Ordinal).ToArray();
        await Assert.That(deconstructionViolations).IsEmpty();

        await Assert.That(protectedTypes.Any(type => type.Name == "AuthorityDecision")).IsTrue();
        await Assert.That(protectedTypes.Any(type => type.Name == "OperationDecision")).IsTrue();
        await Assert.That(protectedTypes.Any(type => type.Name == "MutationAuthorityPermit")).IsTrue();
        await Assert.That(protectedTypes.Count(type => type.Name.EndsWith("Intent", StringComparison.Ordinal))).IsGreaterThan(20);
    }

    [Test]
    public async Task Input_dtos_are_excluded_and_accepted_evidence_is_construction_closed()
    {
        await Assert.That(IsAcceptedOutput(typeof(EvidenceSignedEnvelope))).IsFalse();
        await Assert.That(IsAcceptedOutput(typeof(ReconciliationRequest))).IsFalse();
        await Assert.That(IsAcceptedOutput(typeof(ProviderCallEvidence))).IsFalse();
        await Assert.That(IsAcceptedOutput(typeof(DependencyProof))).IsTrue();
        await Assert.That(IsAcceptedOutput(typeof(ReconciliationObservationProof))).IsTrue();
    }

    private static bool IsAcceptedOutput(Type type) =>
        type.Name.EndsWith("Decision", StringComparison.Ordinal)
        || type.Name.EndsWith("Permit", StringComparison.Ordinal)
        || type.Name.EndsWith("Intent", StringComparison.Ordinal)
        || typeof(ReconciliationOutput).IsAssignableFrom(type)
        || type == typeof(DependencyProof)
        || type == typeof(ReconciliationObservationProof)
        || type == typeof(ReconciliationStep)
        || type == typeof(ReconciliationPlan)
        || typeof(NetworkIntentSubject).IsAssignableFrom(type)
        || typeof(TerraBaseIntentSubject).IsAssignableFrom(type)
        || type == typeof(DurableProviderAuthorization);

    private static string FactoryKey(MethodInfo method) =>
        $"{(method.IsStatic ? "static" : "instance")} {method.DeclaringType!.FullName}.{method.Name}({string.Join(",", method.GetParameters().Select(parameter => TypeKey(parameter.ParameterType)))}) -> {TypeKey(method.ReturnType)}";

    private static string TypeKey(Type type)
    {
        if (type.IsByRef) return $"{TypeKey(type.GetElementType()!)}&";
        if (type.IsArray) return $"{TypeKey(type.GetElementType()!)}[]";
        if (type.IsGenericParameter) return $"`{type.GenericParameterPosition}:{type.Name}";
        if (!type.IsGenericType) return type.FullName ?? type.Name;
        var definitionName = type.GetGenericTypeDefinition().FullName!;
        return $"{definitionName[..definitionName.IndexOf('`')]}<{string.Join(",", type.GetGenericArguments().Select(TypeKey))}>";
    }
}
