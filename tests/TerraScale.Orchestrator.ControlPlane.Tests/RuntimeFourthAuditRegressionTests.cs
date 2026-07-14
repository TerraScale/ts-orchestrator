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
    public async Task Executor_observation_fingerprint_is_independently_sensitive_to_every_nested_leaf()
    {
        var original = RuntimeObservationAuditData.Request(1, 0);
        var spec = Spec(original.Spec, requiredHealth:
            [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness, HealthDimension.RolloutVerification]);
        var baseline = Request(original, spec: spec);
        var payload = (OciRuntimePayload)spec.Payload;
        var firstHealth = baseline.Health[0];
        var firstConflict = baseline.Inventory.Allocations[0];
        var expected = RuntimeLifecycleObservationFingerprint.Create(baseline);
        var variants = new List<RuntimeLifecycleRequest>
        {
            Request(baseline, spec: Spec(spec, workloadId: new("workload-other"))),
            Request(baseline, spec: Spec(spec, allocationId: new("allocation-other"))),
            Request(baseline, spec: Spec(spec, nodeId: new("node-other"))),
            Request(baseline, spec: Spec(spec, role: RuntimeRole.Api)),
            Request(baseline, spec: Spec(spec, generation: new(99))),
            Request(baseline, spec: Spec(spec, configId: new("config-other"))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, artifactId: new("artifact-other")))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, manifestDigest: Digest('b')))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, imageDigest: Digest('c')))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, signatureId: new("signature-other")))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, signingProfileId: new("profile-other")))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, hostImageId: new("host-other")))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, runtimeVersionId: new("runtime-other")))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, architecture: RuntimeArchitecture.LinuxX64))),
            Request(baseline, spec: Spec(spec, payload: Oci(payload, descriptor: OciRuntimeDescriptor.Api))),
            Request(baseline, spec: Spec(spec, payload: Native(payload))),
            Request(baseline, spec: Spec(spec, secretVersions: [new("secret-other")])),
            Request(baseline, spec: Spec(spec, secretVersions: [spec.SecretVersions[0], new("secret-extra")])),
            Request(baseline, spec: Spec(spec, volumes: [new(new("volume-other"), spec.Volumes[0].Retention)])),
            Request(baseline, spec: Spec(spec, volumes: [new(spec.Volumes[0].VolumeId, VolumeRetention.Ephemeral)])),
            Request(baseline, spec: Spec(spec, volumes: [spec.Volumes[0], new(new("volume-extra"), VolumeRetention.Retained)])),
            Request(baseline, spec: Spec(spec, ports: [new RuntimePort(9_999)])),
            Request(baseline, spec: Spec(spec, ports: [spec.Ports[0], new RuntimePort(9_998)])),
            Request(baseline, spec: Spec(spec, requiredHealth:
                [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness, HealthDimension.Startup])),
            Request(baseline, spec: Spec(spec, requiredHealth:
                [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness])),
            Request(baseline, admission: new(RuntimeRole.Api, baseline.Admission.Driver, baseline.Admission.Architecture, baseline.Admission.PolicyGeneration)),
            Request(baseline, admission: new(baseline.Admission.Role, RuntimeDriver.NativeSystemd, baseline.Admission.Architecture, baseline.Admission.PolicyGeneration)),
            Request(baseline, admission: new(baseline.Admission.Role, baseline.Admission.Driver, RuntimeArchitecture.LinuxX64, baseline.Admission.PolicyGeneration)),
            Request(baseline, admission: new(baseline.Admission.Role, baseline.Admission.Driver, baseline.Admission.Architecture, new(77))),
            Request(baseline, observation: Observation(baseline.Observation, operationId: new("operation-other"))),
            Request(baseline, observation: Observation(baseline.Observation, allocationId: new("allocation-other"))),
            Request(baseline, observation: Observation(baseline.Observation, epoch: new(77))),
            Request(baseline, observation: Observation(baseline.Observation, generation: new(77))),
            Request(baseline, observation: Observation(baseline.Observation, phase: LifecyclePhase.ArtifactFetched)),
            Request(baseline, observation: Observation(baseline.Observation, artifactDigest: Digest('d'))),
            Request(baseline, observation: Observation(baseline.Observation, processStatus: ProcessStatus.Running)),
            Request(baseline, observation: Observation(baseline.Observation, callStatus: ExecutorCallStatus.Completed)),
            Request(baseline, health: Health(baseline, Health(firstHealth, id: new("health-other")))),
            Request(baseline, health: Health(baseline, Health(firstHealth, operationId: new("operation-other")))),
            Request(baseline, health: Health(baseline, Health(firstHealth, allocationId: new("allocation-other")))),
            Request(baseline, health: Health(baseline, Health(firstHealth, generation: new(77)))),
            Request(baseline, health: Health(baseline, Health(firstHealth, dimension: HealthDimension.Startup))),
            Request(baseline, health: Health(baseline, Health(firstHealth, status: HealthStatus.Failed))),
            Request(baseline, health: baseline.Health.Take(2)),
            Request(baseline, inventory: Inventory(baseline.Inventory, operationId: new("operation-other"))),
            Request(baseline, inventory: InventoryNode(baseline.Inventory, new("node-other"))),
            Request(baseline, inventory: Inventory(baseline.Inventory, generation: new(77))),
            Request(baseline, inventory: Inventory(baseline.Inventory, completeness: EvidenceCompleteness.Incomplete)),
            Request(baseline, inventory: Inventory(baseline.Inventory, allocations: baseline.Inventory.Allocations.Take(1))),
        };

        foreach (var variant in variants)
            await Assert.That(RuntimeLifecycleObservationFingerprint.Create(variant)).IsNotEqualTo(expected);

        var conflictExpected = RuntimeLifecycleObservationFingerprint.Create(firstConflict);
        var conflictVariants = new[]
        {
            Conflict(firstConflict, allocationId: new("conflict-other")),
            Conflict(firstConflict, nodeId: new("node-other")),
            Conflict(firstConflict, ports: [new RuntimePort(8_001), firstConflict.Ports[1]]),
            Conflict(firstConflict, ports: firstConflict.Ports.Take(1)),
            Conflict(firstConflict, volumes: [new("conflict-volume-other"), firstConflict.Volumes[1]]),
            Conflict(firstConflict, volumes: firstConflict.Volumes.Take(1)),
        };
        foreach (var variant in conflictVariants)
            await Assert.That(RuntimeLifecycleObservationFingerprint.Create(variant)).IsNotEqualTo(conflictExpected);
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
        var outputTypes = new[] { type, typeof(RuntimeIntent), typeof(RuntimeDecision) };
        var outputRoutes = exportedMethods.Where(method => outputTypes.Contains(method.ReturnType))
            .Select(method => $"{method.DeclaringType!.Name}.{method.Name}").ToArray();
        var lifecycleRoutes = typeof(RuntimeDecisionEngine).GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.DeclaredOnly)
            .Where(method => method.ReturnType == typeof(RuntimeDecision) &&
                method.GetParameters().Select(parameter => parameter.ParameterType)
                    .SequenceEqual([typeof(RuntimeLifecycleRequest)]))
            .Select(method => method.Name).ToArray();

        await Assert.That(ReferenceEquals(intent.Request, request)).IsTrue();
        await Assert.That(intent.Request.Health.Count).IsEqualTo(3);
        await Assert.That(type.IsSealed).IsTrue();
        await Assert.That(typeof(RuntimeDecision).IsSealed).IsTrue();
        foreach (var protectedType in new[] { type, typeof(RuntimeIntent), typeof(RuntimeDecision) })
        {
            await Assert.That(protectedType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
            await Assert.That(protectedType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
            await Assert.That(protectedType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Any(method => method.Name == "Deconstruct")).IsFalse();
        }
        await Assert.That(outputRoutes).IsEquivalentTo(new[]
        {
            "ObserveExecutorIntent.<Clone>$", "RuntimeDecision.<Clone>$", "RuntimeDecision.get_Intent",
            "RuntimeDecisionEngine.EvaluateLifecycle", "RuntimeDecisionEngine.EvaluateSelfUpdate", "RuntimeIntent.<Clone>$",
        });
        await Assert.That(lifecycleRoutes).IsEquivalentTo([nameof(RuntimeDecisionEngine.EvaluateLifecycle)]);
        var clone = outputRoutes.Contains("ObserveExecutorIntent.<Clone>$", StringComparer.Ordinal)
            ? type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Single(method => method.Name == "<Clone>$").Invoke(intent, null)!
            : throw new InvalidOperationException("Observe intent clone inventory changed.");
        await Assert.That(clone).IsEqualTo(intent);
        await Assert.That(ReferenceEquals(clone, intent)).IsFalse();
        var decision = RuntimeDecisionEngine.EvaluateLifecycle(request);
        var decisionClone = typeof(RuntimeDecision).GetMethods(BindingFlags.Public | BindingFlags.Instance |
            BindingFlags.DeclaredOnly).Single(method => method.Name == "<Clone>$").Invoke(decision, null)!;
        await Assert.That(decisionClone).IsEqualTo(decision);
        await Assert.That(ReferenceEquals(decisionClone, decision)).IsFalse();
        await Assert.That(intent.ToString()).DoesNotContain("secret-9");
    }

    private static RuntimeLifecycleRequest Request(RuntimeLifecycleRequest value, WorkloadRuntimeSpec? spec = null,
        RuntimeAdmission? admission = null, RuntimeObservation? observation = null,
        IEnumerable<RuntimeHealthEvidence>? health = null, RuntimeInventoryEvidence? inventory = null) =>
        new(value.OperationId, value.Epoch, value.CurrentEpoch, value.CurrentGeneration, value.AdmissionPolicyGeneration,
            value.HealthTimeout, spec ?? value.Spec, admission ?? value.Admission, value.Action,
            observation ?? value.Observation, health ?? value.Health, inventory ?? value.Inventory);

    private static WorkloadRuntimeSpec Spec(WorkloadRuntimeSpec value, RuntimeWorkloadId? workloadId = null,
        RuntimeAllocationId? allocationId = null, RuntimeNodeId? nodeId = null, RuntimeRole? role = null,
        RuntimeGeneration? generation = null, RuntimeConfigId? configId = null, RuntimePayload? payload = null,
        IEnumerable<RuntimeSecretVersionId>? secretVersions = null, IEnumerable<RuntimeVolumeBinding>? volumes = null,
        IEnumerable<RuntimePort>? ports = null, IEnumerable<HealthDimension>? requiredHealth = null) =>
        new(workloadId ?? value.WorkloadId, allocationId ?? value.AllocationId, nodeId ?? value.NodeId,
            role ?? value.Role, generation ?? value.Generation, configId ?? value.ConfigId, payload ?? value.Payload,
            secretVersions ?? value.SecretVersions, volumes ?? value.Volumes, ports ?? value.Ports,
            requiredHealth ?? value.RequiredHealth);

    private static OciRuntimePayload Oci(OciRuntimePayload value, RuntimeArtifactId? artifactId = null,
        RuntimeDigest? manifestDigest = null, RuntimeDigest? imageDigest = null,
        RuntimeSignatureId? signatureId = null, RuntimeSigningProfileId? signingProfileId = null,
        RuntimeHostImageId? hostImageId = null, RuntimeVersionId? runtimeVersionId = null,
        RuntimeArchitecture? architecture = null, OciRuntimeDescriptor? descriptor = null) =>
        new(artifactId ?? value.ArtifactId, manifestDigest ?? value.Digest, imageDigest ?? value.ImageDigest,
            signatureId ?? value.SignatureId, signingProfileId ?? value.SigningProfileId,
            hostImageId ?? value.HostImageId, runtimeVersionId ?? value.RuntimeVersionId,
            architecture ?? value.Architecture, descriptor ?? value.Descriptor);

    private static NativeRuntimePayload Native(OciRuntimePayload value) => new(value.ArtifactId, value.Digest,
        value.SignatureId, value.SigningProfileId, value.HostImageId, value.RuntimeVersionId, value.Architecture,
        NativeUnitDescriptor.TerraBase);

    private static RuntimeObservation Observation(RuntimeObservation value, RuntimeOperationId? operationId = null,
        RuntimeAllocationId? allocationId = null, RuntimeEpoch? epoch = null, RuntimeGeneration? generation = null,
        LifecyclePhase? phase = null, RuntimeDigest? artifactDigest = null, ProcessStatus? processStatus = null,
        ExecutorCallStatus? callStatus = null) => new(operationId ?? value.OperationId,
        allocationId ?? value.AllocationId, epoch ?? value.Epoch, generation ?? value.Generation,
        phase ?? value.Phase, artifactDigest ?? value.ArtifactDigest, processStatus ?? value.ProcessStatus,
        callStatus ?? value.CallStatus);

    private static RuntimeHealthEvidence Health(RuntimeHealthEvidence value, RuntimeHealthId? id = null,
        RuntimeOperationId? operationId = null, RuntimeAllocationId? allocationId = null,
        RuntimeGeneration? generation = null, HealthDimension? dimension = null, HealthStatus? status = null) =>
        new(id ?? value.Id, operationId ?? value.OperationId, allocationId ?? value.AllocationId,
            generation ?? value.Generation, dimension ?? value.Dimension, status ?? value.Status);

    private static IEnumerable<RuntimeHealthEvidence> Health(RuntimeLifecycleRequest request,
        RuntimeHealthEvidence first) => request.Health.Select((item, index) => index == 0 ? first : item);

    private static RuntimeInventoryEvidence Inventory(RuntimeInventoryEvidence value,
        RuntimeOperationId? operationId = null, RuntimeNodeId? nodeId = null, RuntimeGeneration? generation = null,
        EvidenceCompleteness? completeness = null, IEnumerable<RuntimeConflictEvidence>? allocations = null) =>
        new(operationId ?? value.OperationId, nodeId ?? value.NodeId, generation ?? value.Generation,
            completeness ?? value.Completeness, allocations ?? value.Allocations);

    private static RuntimeInventoryEvidence InventoryNode(RuntimeInventoryEvidence value, RuntimeNodeId nodeId) =>
        new(value.OperationId, nodeId, value.Generation, value.Completeness,
            value.Allocations.Select(item => new RuntimeConflictEvidence(item.AllocationId, nodeId, item.Ports, item.Volumes)));

    private static RuntimeConflictEvidence Conflict(RuntimeConflictEvidence value,
        RuntimeAllocationId? allocationId = null, RuntimeNodeId? nodeId = null,
        IEnumerable<RuntimePort>? ports = null, IEnumerable<RuntimeVolumeId>? volumes = null) =>
        new(allocationId ?? value.AllocationId, nodeId ?? value.NodeId, ports ?? value.Ports, volumes ?? value.Volumes);

    private static RuntimeDigest Digest(char value) => new(new string(value, 64));

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
