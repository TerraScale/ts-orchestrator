using TerraScale.Orchestrator.ControlPlane.Runtime;
using System.Reflection;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class RuntimeFourthAuditRegressionTests
{
    [Test]
    public async Task Authorized_response_lost_observation_distinguishes_executor_node()
    {
        var first = RuntimeDecisionEngine.EvaluateLifecycle(Request(new("node-a")));
        var second = RuntimeDecisionEngine.EvaluateLifecycle(Request(new("node-b")));

        await Assert.That(first.Authorized).IsTrue();
        await Assert.That(second.Authorized).IsTrue();
        await Assert.That(first.Intent).IsTypeOf<ObserveExecutorIntent>();
        await Assert.That(second.Intent).IsTypeOf<ObserveExecutorIntent>();
        await Assert.That(first.Intent).IsNotEqualTo(second.Intent);
    }

    [Test]
    public async Task Executor_observation_fingerprint_is_sensitive_to_every_request_property()
    {
        var baseline = RuntimeObservationAuditData.Request(1, 0);
        var other = RuntimeObservationAuditData.Request(2, 0);
        var expected = RuntimeLifecycleObservationFingerprint.Create(baseline);
        var variants = new[]
        {
            new RuntimeLifecycleRequest(other.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, other.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, other.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, other.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                other.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, other.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, other.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, other.Admission, baseline.Action,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, LifecycleAction.Stop,
                baseline.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                other.Observation, baseline.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, other.Health, baseline.Inventory),
            new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch, baseline.CurrentGeneration,
                baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec, baseline.Admission, baseline.Action,
                baseline.Observation, baseline.Health, other.Inventory),
        };

        foreach (var variant in variants)
            await Assert.That(RuntimeLifecycleObservationFingerprint.Create(variant)).IsNotEqualTo(expected);
    }

    [Test]
    public async Task Held_lifecycle_never_exposes_executor_observation_authority()
    {
        var request = RuntimeObservationAuditData.Request(7, 0);
        var deniedRequest = new RuntimeLifecycleRequest(request.OperationId, request.Epoch, request.CurrentEpoch,
            new RuntimeGeneration(request.CurrentGeneration.Value + 1), request.AdmissionPolicyGeneration,
            request.HealthTimeout, request.Spec, request.Admission, request.Action, request.Observation,
            request.Health, request.Inventory);
        var decision = RuntimeDecisionEngine.EvaluateLifecycle(deniedRequest);

        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(decision.Intent).IsTypeOf<HoldRuntimeIntent>();
        await Assert.That(decision.Intent).IsNotTypeOf<ObserveExecutorIntent>();
    }

    [Test]
    public async Task Executor_observation_is_opaque_snapshot_safe_and_construction_closed()
    {
        var baseline = RuntimeObservationAuditData.Request(9, 0);
        var health = baseline.Health.ToList();
        var request = new RuntimeLifecycleRequest(baseline.OperationId, baseline.Epoch, baseline.CurrentEpoch,
            baseline.CurrentGeneration, baseline.AdmissionPolicyGeneration, baseline.HealthTimeout, baseline.Spec,
            baseline.Admission, baseline.Action, baseline.Observation, health, baseline.Inventory);
        var intent = (ObserveExecutorIntent)RuntimeDecisionEngine.EvaluateLifecycle(request).Intent;
        health.Clear();
        var type = typeof(ObserveExecutorIntent);
        var exportedMethods = type.Assembly.GetExportedTypes()
            .SelectMany(candidate => candidate.GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.Instance | BindingFlags.DeclaredOnly)).ToArray();
        var exactRoutes = exportedMethods.Where(method => method.ReturnType == type)
            .Select(method => $"{method.DeclaringType!.Name}.{method.Name}").ToArray();
        var lifecycleRoutes = typeof(RuntimeDecisionEngine).GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.DeclaredOnly)
            .Where(method => method.ReturnType == typeof(RuntimeDecision) &&
                method.GetParameters().Select(parameter => parameter.ParameterType)
                    .SequenceEqual([typeof(RuntimeLifecycleRequest)]))
            .Select(method => method.Name).ToArray();

        await Assert.That(ReferenceEquals(intent.Request, request)).IsTrue();
        await Assert.That(intent.Request.Health.Count).IsEqualTo(3);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Any(method => method.Name == "Deconstruct")).IsFalse();
        await Assert.That(exactRoutes).IsEquivalentTo(["ObserveExecutorIntent.<Clone>$"]);
        await Assert.That(lifecycleRoutes).IsEquivalentTo([nameof(RuntimeDecisionEngine.EvaluateLifecycle)]);
        var clone = exactRoutes.Length == 1
            ? type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Single(method => method.Name == "<Clone>$").Invoke(intent, null)!
            : throw new InvalidOperationException("Observe intent clone inventory changed.");
        await Assert.That(clone).IsEqualTo(intent);
        await Assert.That(ReferenceEquals(clone, intent)).IsFalse();
        await Assert.That(intent.ToString()).DoesNotContain("secret-9");
    }

    private static RuntimeLifecycleRequest Request(RuntimeNodeId node)
    {
        var operation = new RuntimeOperationId("operation-1");
        var allocation = new RuntimeAllocationId("allocation-1");
        var digest = new RuntimeDigest(new string('a', 64));
        var payload = new NativeRuntimePayload(new("artifact-1"), digest, new("signature-1"), new("profile-1"),
            new("host-image-1"), new("runtime-1"), RuntimeArchitecture.LinuxArm64, NativeUnitDescriptor.TerraBase);
        var specification = new WorkloadRuntimeSpec(new("terrabase"), allocation, node, RuntimeRole.TerraBase,
            new(5), new("config-5"), payload, [], [], [new RuntimePort(8080)],
            [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness]);
        var admission = new RuntimeAdmission(RuntimeRole.TerraBase, RuntimeDriver.NativeSystemd,
            RuntimeArchitecture.LinuxArm64, new(2));
        var observation = new RuntimeObservation(operation, allocation, new(5), new(5), LifecyclePhase.Mounted,
            digest, ProcessStatus.Absent, ExecutorCallStatus.ResponseLost);
        var inventory = new RuntimeInventoryEvidence(operation, node, new(5), EvidenceCompleteness.Complete, []);
        return new(operation, new(5), new(5), new(5), new(2), new(30), specification, admission,
            LifecycleAction.Converge, observation, [], inventory);
    }
}
