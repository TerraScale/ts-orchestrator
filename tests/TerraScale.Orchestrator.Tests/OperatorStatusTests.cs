using System.Reflection;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Tests;

public sealed class OperatorStatusTests
{
    [Test]
    public async Task Missing_or_suspended_desired_state_cannot_provision_a_policy_minimum()
    {
        var delivery = DispatchProxy.Create<INatsKVStore, StatusKv>();
        var bundles = DispatchProxy.Create<INatsObjStore, StatusObjects>();
        var reader = new NatsWorkloadDesiredReplicaReader(delivery, bundles, "gru");
        await Assert.That(await reader.ReadAsync("ts-auth", CancellationToken.None)).IsEqualTo(0);
        ((StatusKv)delivery).Records["gitops.cell.test"] = """{"cell":"gru","payloadObject":"admitted"}""";
        ((StatusObjects)bundles).Payload = Encoding.UTF8.GetBytes("""
            {"generation":11,"desiredWorkloads":[
              {"role":"Authentication","cells":["gru"],"replicas":2,"suspended":true},
              {"role":"TerraBaseMember","cells":["gru"],"replicas":5}]}
            """);
        await Assert.That(await reader.ReadAsync("ts-auth", CancellationToken.None)).IsEqualTo(0);
        await Assert.That(await reader.ReadAsync("terrabase-server", CancellationToken.None)).IsEqualTo(5);
    }

    [Test]
    [Arguments(0, "desired-state-not-published")]
    [Arguments(9, "desired-replicas-out-of-policy")]
    public async Task Runtime_projection_uses_independent_configured_bounds_and_blocks_invalid_demand(
        int authReplicas, string expectedNeed)
    {
        var delivery = DispatchProxy.Create<INatsKVStore, StatusKv>();
        ((StatusKv)delivery).Records["gitops.cell.test"] = """{"cell":"gru","payloadObject":"admitted"}""";
        var runtime = DispatchProxy.Create<INatsKVStore, StatusKv>();
        var bundles = DispatchProxy.Create<INatsObjStore, StatusObjects>();
        ((StatusObjects)bundles).Payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            generation = 11,
            desiredWorkloads = new[]
            {
                new { role = "Authentication", cells = new[] { "gru" }, replicas = authReplicas },
                new { role = "TerraBaseMember", cells = new[] { "gru" }, replicas = 5 }
            }
        }));
        var status = await NatsRuntime.BuildOperatorStatusAsync(
            delivery, bundles, runtime,
            new(OrchestratorCommand.Check, "gru", "nats://127.0.0.1:4222", 1),
            new("gru", 1, "local"), DateTimeOffset.UtcNow, CancellationToken.None,
            // A stale autoscaler decision must not override newly blocked demand.
            [new("ts-auth", "authentication", 2, 1, 1, 0, 2, WorkloadScaleAction.ScaleOut, 50, "ready-replicas-below-desired")],
            [new("ts-auth", "authentication", 2, 8), new("terrabase-server", "terrabase-member", 3, 12)]);

        var auth = status.Workloads.Single(value => value.Workload == "ts-auth");
        var terrabase = status.Workloads.Single(value => value.Workload == "terrabase-server");
        await Assert.That(auth.MinReplicas).IsEqualTo(2);
        await Assert.That(auth.MaxReplicas).IsEqualTo(8);
        await Assert.That(auth.PendingScaleAction).IsEqualTo("blocked");
        await Assert.That(auth.Needs.Contains(expectedNeed)).IsTrue();
        await Assert.That(terrabase.MinReplicas).IsEqualTo(3);
        await Assert.That(terrabase.MaxReplicas).IsEqualTo(12);
        await Assert.That(terrabase.DesiredReplicas).IsEqualTo(5);
        await Assert.That(terrabase.PendingScaleAction).IsEqualTo("scale-out");
    }

    [Test]
    public async Task Contract_keeps_ts_auth_and_terrabase_replica_targets_independent()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var document = new OperatorStatusDocument(
            1,
            "gru",
            "controller-1",
            false,
            observedAt,
            [
                new("ts-auth", "Authentication", 2, 1, 1, 50, "converging", 11, null, observedAt, ["ready-replicas:1/2"], 1, 8, "scale-out"),
                new("terrabase-server", "TerraBaseMember", 5, 3, 2, 40, "converging", 12, null, observedAt, ["ready-replicas:2/5"], 3, 12, "scale-out")
            ],
            [new("workload:ts-auth", "converging", 50, observedAt, null)],
            ["ts-auth:ready-replicas:1/2"]);

        document.Validate();

        await Assert.That(document.Workloads.Single(value => value.Workload == "ts-auth").DesiredReplicas)
            .IsEqualTo(2);
        await Assert.That(document.Workloads.Single(value => value.Workload == "terrabase-server").DesiredReplicas)
            .IsEqualTo(5);
        await Assert.That(document.Workloads.Single(value => value.Workload == "ts-auth").PendingScaleAction)
            .IsEqualTo("scale-out");
        await Assert.That(document.Workloads.Single(value => value.Workload == "terrabase-server").MinReplicas)
            .IsEqualTo(3);
        await Assert.That(document.Healthy).IsFalse();
    }

    [Test]
    public async Task Contract_rejects_unbounded_status_values()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var document = new OperatorStatusDocument(
            1,
            "gru",
            "controller-1",
            false,
            observedAt,
            [new(new string('x', 129), "Authentication", 1, 0, 0, 0, "pending", 1, null, null, [])],
            [],
            []);

        await Assert.That(() => document.Validate()).Throws<InvalidOperationException>();
    }

    private class StatusKv : DispatchProxy
    {
        internal Dictionary<string, string> Records { get; } = new(StringComparer.Ordinal);

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => targetMethod?.Name switch
        {
            "GetKeysAsync" => Keys(),
            "GetEntryAsync" => ValueTask.FromResult(new NatsKVEntry<string>("test", (string)args![0]!)
            {
                Value = Records[(string)args[0]!],
                Revision = 1,
                Operation = NatsKVOperation.Put
            }),
            _ => throw new NotSupportedException(targetMethod?.Name)
        };

        private async IAsyncEnumerable<string> Keys()
        {
            foreach (var key in Records.Keys) yield return key;
            await Task.CompletedTask;
        }
    }

    private class StatusObjects : DispatchProxy
    {
        internal byte[] Payload { get; set; } = [];

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => targetMethod?.Name switch
        {
            "GetBytesAsync" => ValueTask.FromResult(Payload),
            _ => throw new NotSupportedException(targetMethod?.Name)
        };
    }
}
