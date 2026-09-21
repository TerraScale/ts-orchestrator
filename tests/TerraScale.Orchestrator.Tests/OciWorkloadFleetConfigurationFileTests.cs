using System.Text.Json;
using System.Reflection;
using NATS.Client.KeyValueStore;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Tests;

public sealed class OciWorkloadFleetConfigurationFileTests
{
    [Test]
    [Arguments(0)]
    [Arguments(9)]
    public async Task Provider_does_not_clamp_invalid_demand_into_permission_to_launch(int desired)
    {
        var root = Directory.CreateTempSubdirectory("ts-orch-demand-");
        try
        {
            var fleet = await WriteTestFleetAsync(root.FullName);
            var transport = new FakeWorkloadTransport();
            var store = DispatchProxy.Create<INatsKVStore, PutOnlyKvStore>();
            var driver = new OciWorkloadReplicaDriver(transport, fleet, store,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(desired, "sha256:" + new string('a', 64))), () => true, "gru");
            var policy = fleet.Policies.Single(value => value.WorkloadId == "ts-auth");
            var observation = await driver.ObserveAsync(policy, CancellationToken.None);
            var decision = new IndependentWorkloadAutoscaler([policy]).Tick([observation]).Single();
            await driver.ApplyAsync(decision, CancellationToken.None);
            await Assert.That(observation.DesiredReplicas).IsEqualTo(desired);
            await Assert.That(decision.Action).IsEqualTo(WorkloadScaleAction.Blocked);
            await Assert.That(transport.LaunchCalls).IsEqualTo(0);
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    public async Task Generic_fleet_cannot_retire_stateful_members_without_drain_proof()
    {
        var root = Directory.CreateTempSubdirectory("ts-orch-retirement-");
        try
        {
            var fleet = await WriteTestFleetAsync(root.FullName);
            var transport = new FakeWorkloadTransport();
            var store = DispatchProxy.Create<INatsKVStore, PutOnlyKvStore>();
            var driver = new OciWorkloadReplicaDriver(transport, fleet, store,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(3, "sha256:" + new string('a', 64))), () => true, "gru");
            var decision = new WorkloadScaleDecision("terrabase-server", "terrabase-member",
                3, 4, 4, 0, 3, WorkloadScaleAction.ScaleIn, 100, "ready-replicas-above-desired");
            await Assert.That(() => driver.ApplyAsync(decision, CancellationToken.None))
                .Throws<InvalidOperationException>();
            await Assert.That(transport.TerminateCalls).IsEqualTo(0);
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    public async Task Authority_expiring_during_operation_persistence_prevents_the_launch()
    {
        var root = Directory.CreateTempSubdirectory("ts-orch-authority-");
        try
        {
            var fleet = await WriteTestFleetAsync(root.FullName);
            var transport = new FakeWorkloadTransport();
            var store = DispatchProxy.Create<INatsKVStore, PutOnlyKvStore>();
            using var driver = new OciWorkloadReplicaDriver(transport, fleet, store,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(2, "sha256:" + new string('a', 64))),
                () => ((PutOnlyKvStore)store).TotalWrites == 0, "gru");
            var decision = new WorkloadScaleDecision("ts-auth", "authentication", 2, 1, 1, 0, 2,
                WorkloadScaleAction.ScaleOut, 50, "ready-replicas-below-desired");
            await Assert.That(() => driver.ApplyAsync(decision, CancellationToken.None)).Throws<InvalidOperationException>();
            await Assert.That(((PutOnlyKvStore)store).TotalWrites).IsEqualTo(1);
            await Assert.That(transport.LaunchCalls).IsEqualTo(0);
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    [NotInParallel("TerrabasePlacement")]
    public async Task Real_Nats_readiness_binds_node_cell_artifact_and_keeps_unready_vms_pending()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var root = Directory.CreateTempSubdirectory("ts-orch-readiness-");
        try
        {
            var fleet = await WriteTestFleetAsync(root.FullName);
            var policy = fleet.Policies.Single(value => value.WorkloadId == "ts-auth");
            var template = fleet.TemplateFor(policy);
            var launch = OciWorkloadRequestCompiler.Launch(template, "ts-auth", "authentication", "create-1", "gru").LaunchInstanceDetails;
            var instance = new Instance
            {
                Id = "ocid1.instance.oc1.sa-saopaulo-1.auth-1",
                CompartmentId = launch.CompartmentId,
                AvailabilityDomain = launch.AvailabilityDomain,
                FaultDomain = launch.FaultDomain,
                Shape = launch.Shape,
                ShapeConfig = new InstanceShapeConfig { Ocpus = launch.ShapeConfig.Ocpus, MemoryInGBs = launch.ShapeConfig.MemoryInGBs },
                ImageId = template.LaunchTemplate.ImageId,
                SourceDetails = launch.SourceDetails,
                Metadata = launch.Metadata,
                FreeformTags = launch.FreeformTags,
                LifecycleState = Instance.LifecycleStateEnum.Running
            };
            var transport = new FakeWorkloadTransport { ObservedInstance = instance };
            var digest = "sha256:" + new string('a', 64);
            using var driver = new OciWorkloadReplicaDriver(transport, fleet, server.Runtime,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(1, digest)), () => true, "gru");
            var report = new HostConvergenceObservation(2, "gru", instance.Id, "ts-auth", digest,
                "converged", "ts-auth.service", DateTimeOffset.UtcNow);
            var invalid = new[]
            {
                report with { Instance = "another-node" },
                report with { Cell = "fra" },
                report with { ArtifactKey = "terrabase-server" },
                report with { Digest = "sha256:" + new string('b', 64) },
                report with { ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-11) },
                report with { ObservedAt = DateTimeOffset.UtcNow.AddMinutes(1) },
                report with { SchemaVersion = 99 },
                report with { State = "failed" },
                report with { Error = "admission-denied" }
            };
            var scaler = new IndependentWorkloadAutoscaler([policy]);
            foreach (var candidate in invalid)
            {
                await server.Runtime.PutAsync($"host.{instance.Id}.ts-auth",
                    JsonSerializer.Serialize(candidate, HostConvergenceJsonContext.Default.HostConvergenceObservation));
                var observation = await driver.ObserveAsync(policy, CancellationToken.None);
                await Assert.That(observation.ReadyReplicas).IsEqualTo(0);
                await Assert.That(observation.PendingReplicas).IsEqualTo(1);
                // More than the confirmation window: unavailable readiness must
                // not become an unbounded stream of replacement VMs.
                for (var tick = 0; tick < 5; tick++)
                    await driver.ApplyAsync(scaler.Tick([observation]).Single(), CancellationToken.None);
            }
            await Assert.That(transport.LaunchCalls).IsEqualTo(0);
            await Assert.That(transport.TerminateCalls).IsEqualTo(0);
            await server.Runtime.PutAsync($"host.{instance.Id}.ts-auth",
                JsonSerializer.Serialize(report, HostConvergenceJsonContext.Default.HostConvergenceObservation));
            var ready = await driver.ObserveAsync(policy, CancellationToken.None);
            await Assert.That(ready.ReadyReplicas).IsEqualTo(1);
            await Assert.That(ready.PendingReplicas).IsEqualTo(0);
            instance.LifecycleState = Instance.LifecycleStateEnum.Stopped;
            await Assert.That((await driver.ObserveAsync(policy, CancellationToken.None)).ReadyReplicas).IsEqualTo(0);
            instance.LifecycleState = Instance.LifecycleStateEnum.Terminated;
            await Assert.That((await driver.ObserveAsync(policy, CancellationToken.None)).ObservedReplicas).IsEqualTo(0);
            instance.LifecycleState = Instance.LifecycleStateEnum.Running;
            instance.FreeformTags[OciWorkloadRequestCompiler.CellTag] = "fra";
            await Assert.That((await driver.ObserveAsync(policy, CancellationToken.None)).ObservedReplicas).IsEqualTo(0);
            instance.FreeformTags[OciWorkloadRequestCompiler.CellTag] = "gru";
            transport.DetailInstance = new Instance { Id = instance.Id };
            await Assert.That(async () => { _ = await driver.ObserveAsync(policy, CancellationToken.None); }).Throws<InvalidDataException>();
        }
        finally { root.Delete(recursive: true); }
    }

    private static async Task<OciWorkloadFleetConfigurationFile> WriteTestFleetAsync(string directory)
    {
        await File.WriteAllTextAsync(Path.Combine(directory, "bootstrap"), "#cloud-config\nruncmd: []\n");
        var path = Path.Combine(directory, "fleet.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            region = "GRU",
            endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
            workloads = new[]
            {
                Workload("ts-auth", "authentication", "bootstrap", 1, 8),
                Workload("terrabase-server", "terrabase-member", "bootstrap", 3, 12)
            }
        }));
        return OciWorkloadFleetConfigurationFile.Load(path)!;
    }

    [Test]
    [Arguments("GRU", "https://iaas.sa-saopaulo-1.oraclecloud.com/", true)]
    [Arguments("SFO", "https://iaas.us-sanjose-1.oraclecloud.com/", true)]
    [Arguments("FRA", "https://iaas.eu-frankfurt-1.oraclecloud.com/", true)]
    [Arguments("GRU", "https://iaas.us-sanjose-1.oraclecloud.com/", false)]
    [Arguments("SFO", "https://iaas.sa-saopaulo-1.oraclecloud.com/", false)]
    [Arguments("SFO", "https://iaas.us-ashburn-1.oraclecloud.com/", false)]
    [Arguments("GRU", "https://iaas.sa-saopaulo-1.oraclecloud.com:8443/", false)]
    [Arguments("GRU", "https://iaas.sa-saopaulo-1.oraclecloud.com/#fragment", false)]
    public async Task Fleet_endpoint_is_bound_to_the_logical_cell(string region, string endpoint, bool accepted)
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-region-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region,
                endpoint,
                workloads = new[] { Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8) }
            }));
            if (accepted)
                await Assert.That(OciWorkloadFleetConfigurationFile.Load(path)!.Region).IsEqualTo(region);
            else
                await Assert.That(() => OciWorkloadFleetConfigurationFile.Load(path)).Throws<InvalidDataException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task RequiresIndependentAuthAndTerraBasePolicies()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "terrabase.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[]
                {
                    Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8),
                    Workload("terrabase-server", "terrabase-member", "terrabase.cloud-init", 3, 12),
                }
            }));

            var fleet = OciWorkloadFleetConfigurationFile.Load(path)!;
            await Assert.That(fleet.Region).IsEqualTo("GRU");
            await Assert.That(fleet.Policies.Select(value => value.WorkloadId))
                .IsEquivalentTo(["terrabase-server", "ts-auth"]);
            await Assert.That(fleet.Policies.Single(value => value.WorkloadId == "ts-auth").MaxReplicas)
                .IsEqualTo(8);
            await Assert.That(fleet.Policies.Single(value => value.WorkloadId == "terrabase-server").MinReplicas)
                .IsEqualTo(3);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task RejectsPartialGenericCompositionAndCredentialBearingBootstrap()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nsecret: BEGIN USER NKEY SEED\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[] { Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8) }
            }));
            await Assert.That(() => OciWorkloadFleetConfigurationFile.Load(path))
                .Throws<InvalidDataException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task AuthOnlyFleet_is_valid_when_stateful_terrabase_placement_owns_members()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[] { Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8) }
            }));

            var fleet = OciWorkloadFleetConfigurationFile.Load(path)!;
            OciWorkloadFleetComposition.Validate(true, fleet);
            await Assert.That(fleet.Policies.Select(value => value.WorkloadId))
                .IsEquivalentTo(["ts-auth"]);
            await Assert.That(() => OciWorkloadFleetComposition.Validate(false, fleet))
                .Throws<InvalidOperationException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task Workloads_have_distinct_ownership_and_idempotency_domains()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "terrabase.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[]
                {
                    Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8),
                    Workload("terrabase-server", "terrabase-member", "terrabase.cloud-init", 3, 12),
                }
            }));
            var fleet = OciWorkloadFleetConfigurationFile.Load(path)!;
            var auth = OciWorkloadRequestCompiler.Launch(
                fleet.TemplateFor(fleet.Policies.Single(value => value.WorkloadId == "ts-auth")),
                "ts-auth", "authentication", "auth-key", "gru");
            var terrabase = OciWorkloadRequestCompiler.Launch(
                fleet.TemplateFor(fleet.Policies.Single(value => value.WorkloadId == "terrabase-server")),
                "terrabase-server", "terrabase-member", "terrabase-key", "gru");

            await Assert.That(auth.OpcRetryToken).IsNotEqualTo(terrabase.OpcRetryToken);
            await Assert.That(auth.LaunchInstanceDetails.FreeformTags[OciWorkloadRequestCompiler.WorkloadTag])
                .IsEqualTo("ts-auth");
            await Assert.That(terrabase.LaunchInstanceDetails.FreeformTags[OciWorkloadRequestCompiler.WorkloadTag])
                .IsEqualTo("terrabase-server");
            await Assert.That(auth.LaunchInstanceDetails.FreeformTags[OciWorkloadRequestCompiler.RoleTag])
                .IsNotEqualTo(terrabase.LaunchInstanceDetails.FreeformTags[OciWorkloadRequestCompiler.RoleTag]);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task StatefulTerraBasePlacementCannotShareOwnershipWithGenericWorkloadFleet()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "terrabase.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[]
                {
                    Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8),
                    Workload("terrabase-server", "terrabase-member", "terrabase.cloud-init", 3, 12),
                }
            }));

            var fleet = OciWorkloadFleetConfigurationFile.Load(path)!;
            await Assert.That(() => OciWorkloadFleetComposition.Validate(true, fleet))
                .Throws<InvalidOperationException>();
            OciWorkloadFleetComposition.Validate(false, fleet);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task Lost_launch_response_is_retried_with_the_same_provider_token_and_work_request_is_polled()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ts-orch-workload-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "auth.cloud-init"), "#cloud-config\nruncmd: []\n");
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "terrabase.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                region = "GRU",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                workloads = new[]
                {
                    Workload("ts-auth", "authentication", "auth.cloud-init", 1, 8),
                    Workload("terrabase-server", "terrabase-member", "terrabase.cloud-init", 3, 12),
                }
            }));
            var fleet = OciWorkloadFleetConfigurationFile.Load(path)!;
            var transport = new FakeWorkloadTransport();
            transport.FailFirstLaunch = true;
            var store = DispatchProxy.Create<INatsKVStore, PutOnlyKvStore>();
            var firstController = new OciWorkloadReplicaDriver(
                transport,
                fleet,
                store,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(2, "sha256:" + new string('a', 64))),
                () => true,
                "gru");
            var decision = new WorkloadScaleDecision(
                "ts-auth", "authentication", 2, 1, 1, 0, 2,
                WorkloadScaleAction.ScaleOut, 50, "ready-replicas-below-desired");

            await Assert.That(() => firstController.ApplyAsync(decision, CancellationToken.None))
                .Throws<InvalidOperationException>();
            // A controller restart loses the in-memory snapshot. The durable operation
            // record must still supply the original retry token before any new launch is
            // attempted.
            var restartedController = new OciWorkloadReplicaDriver(
                transport,
                fleet,
                store,
                (_, _) => Task.FromResult(new WorkloadReplicaIntent(2, "sha256:" + new string('a', 64))),
                () => true,
                "gru");
            await restartedController.ApplyAsync(decision, CancellationToken.None);

            await Assert.That(transport.LaunchCalls).IsEqualTo(2);
            await Assert.That(transport.LastRetryToken).IsNotNull();
            await Assert.That(transport.WorkRequestPolls).IsEqualTo(1);
            await Assert.That(transport.LastRetryToken).IsEqualTo(transport.FirstRetryToken);
            await Assert.That(((PutOnlyKvStore)store).TotalWrites).IsEqualTo(3);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private class PutOnlyKvStore : DispatchProxy
    {
        public int TotalWrites { get; private set; }
        private readonly Dictionary<string, string> Records = new(StringComparer.Ordinal);
        private ulong revision;

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name == "PutAsync")
            {
                TotalWrites++;
                Records[(string)args![0]!] = (string)args[1]!;
                revision++;
                return ValueTask.FromResult(1UL);
            }
            if (targetMethod?.Name == "GetKeysAsync")
                return KeysAsync(Records.Keys.ToArray());
            if (targetMethod?.Name == "GetEntryAsync")
            {
                var key = (string)args![0]!;
                if (!Records.TryGetValue(key, out var value))
                    return ValueTask.FromException<NatsKVEntry<string>>(NatsKVKeyNotFoundException.Default);
                return ValueTask.FromResult(new NatsKVEntry<string>("ORCH_RUNTIME", key)
                {
                    Value = value,
                    Revision = revision,
                    Operation = NatsKVOperation.Put
                });
            }
            throw new NotSupportedException(targetMethod?.Name);
        }

        private static async IAsyncEnumerable<string> KeysAsync(IEnumerable<string> keys)
        {
            foreach (var key in keys)
                yield return key;
            await Task.CompletedTask;
        }
    }

    private sealed class FakeWorkloadTransport : IOciCiRunnerComputeTransport, IOciWorkRequestTransport
    {
        public bool FailFirstLaunch { get; set; }
        public Instance? ObservedInstance { get; set; }
        public Instance? DetailInstance { get; set; }
        public int LaunchCalls { get; private set; }
        public int WorkRequestPolls { get; private set; }
        public int TerminateCalls { get; private set; }
        public string? LastRetryToken { get; private set; }
        public string? FirstRetryToken { get; private set; }
        public LaunchInstanceRequest? LaunchedRequest { get; private set; }

        public Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
            LaunchInstanceRequest request, CancellationToken cancellationToken)
        {
            LaunchCalls++;
            LaunchedRequest = request;
            FirstRetryToken ??= request.OpcRetryToken;
            LastRetryToken = request.OpcRetryToken;
            if (FailFirstLaunch)
            {
                FailFirstLaunch = false;
                throw new InvalidOperationException("simulated lost launch response");
            }
            return Task.FromResult(new Oci.CoreService.Responses.LaunchInstanceResponse
            {
                Instance = new Instance { Id = "ocid1.instance.oc1..auth-1" },
                OpcWorkRequestId = "ocid1.workrequest.oc1..auth-1",
            });
        }

        public Task<Oci.WorkrequestsService.Responses.GetWorkRequestResponse> GetWorkRequestAsync(
            string workRequestId, CancellationToken cancellationToken)
        {
            WorkRequestPolls++;
            return Task.FromResult(new Oci.WorkrequestsService.Responses.GetWorkRequestResponse
            {
                WorkRequest = new Oci.WorkrequestsService.Models.WorkRequest
                {
                    Status = Oci.WorkrequestsService.Models.WorkRequest.StatusEnum.Succeeded,
                },
            });
        }

        public Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
            ListInstancesRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new Oci.CoreService.Responses.ListInstancesResponse { Items = ObservedInstance is { } instance ? [instance] : [] });

        public Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
            GetInstanceRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new Oci.CoreService.Responses.GetInstanceResponse
            {
                Instance = DetailInstance ?? ObservedInstance,
                Etag = "etag-1"
            });

        public Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
            ListVnicAttachmentsRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
            GetVnicRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
            TerminateInstanceRequest request, CancellationToken cancellationToken)
        {
            TerminateCalls++;
            throw new NotSupportedException();
        }

        public void Dispose() { }
    }

    private static object Workload(string name, string role, string bootstrap, int minimum, int maximum) => new
    {
        workload = name,
        role,
        compartmentId = "ocid1.compartment.oc1..workload",
        availabilityDomain = "AD-1",
        faultDomain = "FAULT-DOMAIN-1",
        subnetId = "ocid1.subnet.oc1.sa-saopaulo-1..subnet",
        networkSecurityGroupIds = new[] { "ocid1.networksecuritygroup.oc1.sa-saopaulo-1..nsg" },
        imageId = "ocid1.image.oc1.sa-saopaulo-1..image",
        generation = 1,
        minReplicas = minimum,
        maxReplicas = maximum,
        scaleUpConfirmTicks = 2,
        scaleDownConfirmTicks = 4,
        bootstrapFile = bootstrap,
    };
}
