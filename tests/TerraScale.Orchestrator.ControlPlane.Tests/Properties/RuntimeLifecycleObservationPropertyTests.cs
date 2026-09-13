using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Runtime;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class RuntimeLifecycleObservationPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Executor_observation_retains_complete_request_for_1000_culture_and_permutation_replays()
    {
        var before = CultureInfo.CurrentCulture;
        var beforeUi = CultureInfo.CurrentUICulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(seed % 2 == 0 ? "ar-SA" : "tr-TR");
                CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
                var request = RuntimeObservationAuditData.Request(seed, seed % 4);
                var decision = RuntimeDecisionEngine.EvaluateLifecycle(request);
                var intent = (ObserveExecutorIntent)decision.Intent;
                var replay = (ObserveExecutorIntent)RuntimeDecisionEngine.EvaluateLifecycle(
                    RuntimeObservationAuditData.Request(seed, seed % 4)).Intent;
                var permuted = (ObserveExecutorIntent)RuntimeDecisionEngine.EvaluateLifecycle(
                    RuntimeObservationAuditData.Request(seed, seed % 4, reverseEvidence: true)).Intent;

                await Assert.That(decision.Authorized).IsTrue();
                await Assert.That(ReferenceEquals(intent.Request, request)).IsTrue();
                await Assert.That(ReferenceEquals(intent.OperationId, request.OperationId)).IsTrue();
                await Assert.That(ReferenceEquals(intent.AllocationId, request.Spec.AllocationId)).IsTrue();
                await Assert.That(RuntimeLifecycleObservationFingerprint.Create(intent.Request))
                    .IsEqualTo(RuntimeLifecycleObservationFingerprint.Create(replay.Request));
                await Assert.That(RuntimeLifecycleObservationFingerprint.Create(intent.Request))
                    .IsEqualTo(RuntimeLifecycleObservationFingerprint.Create(permuted.Request));
                if (seed < Cases)
                    await Assert.That(RuntimeLifecycleObservationFingerprint.Create(intent.Request)).IsNotEqualTo(
                        RuntimeLifecycleObservationFingerprint.Create(RuntimeObservationAuditData.Request(seed + 1, seed % 4)));
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = before;
            CultureInfo.CurrentUICulture = beforeUi;
        }
    }
}

internal static class RuntimeLifecycleObservationFingerprint
{
    internal static string Create(RuntimeLifecycleRequest request)
    {
        using var value = new ZStringWriter();
        Add(value, request.OperationId.Value); Add(value, request.Epoch.Value); Add(value, request.CurrentEpoch.Value);
        Add(value, request.CurrentGeneration.Value); Add(value, request.AdmissionPolicyGeneration.Value);
        Add(value, request.HealthTimeout.Value);
        var spec = request.Spec;
        Add(value, spec.WorkloadId.Value); Add(value, spec.AllocationId.Value); Add(value, spec.NodeId.Value);
        Add(value, (int)spec.Role); Add(value, spec.Generation.Value); Add(value, spec.ConfigId.Value);
        var payload = spec.Payload;
        Add(value, payload.ArtifactId.Value); Add(value, payload.Digest.Sha256); Add(value, payload.ActivationDigest.Sha256);
        Add(value, payload.SignatureId.Value); Add(value, payload.SigningProfileId.Value); Add(value, payload.HostImageId.Value);
        Add(value, payload.RuntimeVersionId.Value); Add(value, (int)payload.Architecture); Add(value, (int)payload.Driver);
        Add(value, payload switch { NativeRuntimePayload native => (int)native.Descriptor, OciRuntimePayload oci => (int)oci.Descriptor, _ => 0 });
        AddMany(value, spec.SecretVersions.OrderBy(item => item.Value, StringComparer.Ordinal), item => item.Value);
        AddMany(value, spec.Volumes.OrderBy(item => item.VolumeId.Value, StringComparer.Ordinal),
            item => $"{item.VolumeId.Value}:{(int)item.Retention}");
        AddMany(value, spec.Ports.OrderBy(item => item.Value), item => item.Value.ToString(CultureInfo.InvariantCulture));
        AddMany(value, spec.RequiredHealth.Order(), item => ((int)item).ToString(CultureInfo.InvariantCulture));
        Add(value, (int)request.Admission.Role); Add(value, (int)request.Admission.Driver);
        Add(value, (int)request.Admission.Architecture); Add(value, request.Admission.PolicyGeneration.Value);
        Add(value, (int)request.Action);
        var observation = request.Observation;
        Add(value, observation.OperationId.Value); Add(value, observation.AllocationId.Value); Add(value, observation.Epoch.Value);
        Add(value, observation.Generation.Value); Add(value, (int)observation.Phase); Add(value, observation.ArtifactDigest.Sha256);
        Add(value, (int)observation.ProcessStatus); Add(value, (int)observation.CallStatus);
        AddMany(value, request.Health.OrderBy(item => item.Dimension).ThenBy(item => item.Id.Value, StringComparer.Ordinal),
            item => $"{item.Id.Value}:{item.OperationId.Value}:{item.AllocationId.Value}:{item.Generation.Value}:{(int)item.Dimension}:{(int)item.Status}");
        var inventory = request.Inventory;
        Add(value, inventory.OperationId.Value); Add(value, inventory.NodeId.Value); Add(value, inventory.Generation.Value);
        Add(value, (int)inventory.Completeness);
        var allocations = inventory.Allocations.OrderBy(item => item.AllocationId.Value, StringComparer.Ordinal).ToArray();
        Add(value, allocations.Length);
        foreach (var allocation in allocations) AddConflict(value, allocation);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    internal static string Create(RuntimeConflictEvidence evidence)
    {
        using var value = new ZStringWriter(); AddConflict(value, evidence);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    private static void AddConflict(ZStringWriter value, RuntimeConflictEvidence evidence)
    {
        Add(value, evidence.AllocationId.Value); Add(value, evidence.NodeId.Value);
        AddMany(value, evidence.Ports.OrderBy(port => port.Value),
            port => port.Value.ToString(CultureInfo.InvariantCulture));
        AddMany(value, evidence.Volumes.OrderBy(volume => volume.Value, StringComparer.Ordinal), volume => volume.Value);
    }

    private static void Add(ZStringWriter target, int value) => Add(target, value.ToString(CultureInfo.InvariantCulture));
    private static void Add(ZStringWriter target, ulong value) => Add(target, value.ToString(CultureInfo.InvariantCulture));
    private static void Add(ZStringWriter target, string value)
    {
        target.Write(value.Length.ToString(CultureInfo.InvariantCulture));
        target.Write(':');
        target.Write(value);
        target.Write(';');
    }
    private static void AddMany<T>(ZStringWriter target, IEnumerable<T> values, Func<T, string> project)
    {
        var snapshot = values.Select(project).ToArray(); Add(target, snapshot.Length);
        foreach (var item in snapshot) Add(target, item);
    }
}

internal static class RuntimeObservationAuditData
{
    internal static RuntimeLifecycleRequest Request(int seed, int variant, bool reverseEvidence = false)
    {
        var operation = new RuntimeOperationId($"operation-{seed}");
        var allocation = new RuntimeAllocationId($"allocation-{seed}");
        var node = new RuntimeNodeId($"node-{seed}");
        var epoch = new RuntimeEpoch((ulong)(100 + seed));
        var generation = new RuntimeGeneration((ulong)(1_000 + seed));
        var policy = new RuntimeGeneration((ulong)(2_000 + seed));
        var digest = Digest($"artifact-{seed}");
        RuntimePayload payload = seed % 2 == 0
            ? new NativeRuntimePayload(new($"artifact-{seed}"), digest, new($"signature-{seed}"), new($"profile-{seed}"),
                new($"host-{seed}"), new($"runtime-{seed}"), RuntimeArchitecture.LinuxArm64, NativeUnitDescriptor.TerraBase)
            : new OciRuntimePayload(new($"artifact-{seed}"), digest, Digest($"image-{seed}"), new($"signature-{seed}"),
                new($"profile-{seed}"), new($"host-{seed}"), new($"runtime-{seed}"), RuntimeArchitecture.LinuxArm64,
                OciRuntimeDescriptor.TerraBase);
        var spec = new WorkloadRuntimeSpec(new($"workload-{seed}"), allocation, node, RuntimeRole.TerraBase, generation,
            new($"config-{seed}"), payload, [new($"secret-{seed}")], [new(new($"volume-{seed}"), VolumeRetention.Retained)],
            [new RuntimePort((ushort)(1_000 + seed % 50_000))],
            [HealthDimension.Liveness, HealthDimension.LocalReadiness, HealthDimension.DependencyReadiness]);
        var admission = new RuntimeAdmission(RuntimeRole.TerraBase, payload.Driver, RuntimeArchitecture.LinuxArm64, policy);
        var (action, phase, process) = variant switch
        {
            0 => (LifecycleAction.Converge, LifecyclePhase.Mounted, ProcessStatus.Absent),
            1 => (LifecycleAction.Stop, LifecyclePhase.Serving, ProcessStatus.Running),
            2 => (LifecycleAction.Drain, LifecyclePhase.Serving, ProcessStatus.Running),
            _ => (LifecycleAction.Cleanup, LifecyclePhase.Stopped, ProcessStatus.Absent),
        };
        var observation = new RuntimeObservation(operation, allocation, epoch, generation, phase,
            payload.ActivationDigest, process, seed % 2 == 0 ? ExecutorCallStatus.Accepted : ExecutorCallStatus.ResponseLost);
        RuntimeHealthEvidence[] health =
        [
            new(new($"health-live-{seed}"), operation, allocation, generation, HealthDimension.Liveness, HealthStatus.Ready),
            new(new($"health-local-{seed}"), operation, allocation, generation, HealthDimension.LocalReadiness, HealthStatus.Ready),
            new(new($"health-dependency-{seed}"), operation, allocation, generation, HealthDimension.DependencyReadiness, HealthStatus.Ready),
        ];
        var ports = new[] { new RuntimePort((ushort)(50_001 + seed % 10_000)), new RuntimePort((ushort)(40_001 + seed % 10_000)) };
        var volumes = new[] { new RuntimeVolumeId($"other-volume-b-{seed}"), new RuntimeVolumeId($"other-volume-a-{seed}") };
        var firstConflict = new RuntimeConflictEvidence(new($"other-a-{seed}"), node,
            reverseEvidence ? ports.Reverse() : ports, reverseEvidence ? volumes.Reverse() : volumes);
        var secondConflict = new RuntimeConflictEvidence(new($"other-b-{seed}"), node,
            reverseEvidence ? ports : ports.Reverse(), reverseEvidence ? volumes : volumes.Reverse());
        var conflicts = reverseEvidence
            ? new[] { secondConflict, firstConflict }
            : new[] { firstConflict, secondConflict };
        var inventory = new RuntimeInventoryEvidence(operation, node, generation, EvidenceCompleteness.Complete,
            conflicts);
        return new(operation, epoch, epoch, generation, policy, new((ulong)(30 + seed % 30)), spec, admission, action,
            observation, reverseEvidence ? health.Reverse() : health, inventory);
    }

    private static RuntimeDigest Digest(string value) => new(Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant());
}

