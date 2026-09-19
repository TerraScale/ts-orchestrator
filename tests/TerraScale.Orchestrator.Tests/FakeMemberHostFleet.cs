using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The scriptable in-memory member-host fleet: provisioning, health scripting, host
/// loss (vanish or provider-terminal), fenced retire, and a recorded call log. Drain
/// flips the member down on the next observation, exactly as a graceful host-agent
/// drain would surface.
/// </summary>
internal sealed class FakeMemberHostFleet : IMemberHostFleet
{
    private readonly object gate = new();
    private readonly Dictionary<string, Host> hosts = new(StringComparer.Ordinal);
    private int provisionSequence;

    /// <summary>The recorded fleet calls, in order: provision/cordon/drain/retire with their identities.</summary>
    public List<string> Calls { get; } = [];

    /// <summary>Scripted failures; each fleet call throws the scripted exception instead of mutating.</summary>
    public Exception? ProvisionFailure { get; set; }

    public Exception? CordonFailure { get; set; }

    public Exception? DrainFailure { get; set; }

    public Exception? RetireFailure { get; set; }

    /// <summary>Runs inside ObserveAsync — the hook that flips authority mid-tick in tests.</summary>
    public Action? OnObserve { get; set; }

    /// <summary>Adds one running, healthy host and returns its instance id.</summary>
    public string AddRunningHost(
        string database,
        string member,
        string region,
        bool up = true,
        long lag = 0,
        string role = "follower")
    {
        lock (gate)
        {
            var instanceId = $"ocid1.instance.fake.{++provisionSequence}";
            hosts[instanceId] = new Host(
                instanceId,
                database,
                member,
                region,
                MemberHostState.Running,
                Cordon: false,
                ETag: $"rev-{provisionSequence}",
                new MemberHealth(up, lag, role, PeerAckCount: 2, MinReplicas: 1));
            return instanceId;
        }
    }

    /// <summary>Simulates host loss: the instance vanishes from the listing entirely.</summary>
    public void RemoveHost(string instanceId)
    {
        lock (gate)
        {
            hosts.Remove(instanceId);
        }
    }

    /// <summary>Simulates a provider-terminal host: listed but Terminated.</summary>
    public void MarkTerminated(string instanceId)
    {
        lock (gate)
        {
            if (hosts.TryGetValue(instanceId, out var host))
                hosts[instanceId] = host with { State = MemberHostState.Terminated };
        }
    }

    public void SetHealth(string instanceId, bool up, long lag = 0, string role = "follower")
    {
        lock (gate)
        {
            if (hosts.TryGetValue(instanceId, out var host))
                hosts[instanceId] = host with
                {
                    MemberHealth = new MemberHealth(up, lag, role, host.MemberHealth.PeerAckCount, host.MemberHealth.MinReplicas),
                };
        }
    }

    public IReadOnlyList<string> Instances
    {
        get
        {
            lock (gate)
            {
                return hosts.Keys.Order(StringComparer.Ordinal).ToArray();
            }
        }
    }

    public Task<IReadOnlyList<MemberHostObservation>> ObserveAsync(CancellationToken cancellationToken)
    {
        OnObserve?.Invoke();
        lock (gate)
        {
            IReadOnlyList<MemberHostObservation> observations = hosts.Values
                .OrderBy(static host => host.InstanceId, StringComparer.Ordinal)
                .Select(static host => new MemberHostObservation(
                    new ProviderResourceId(host.InstanceId),
                    host.ETag,
                    host.MemberId,
                    host.Region,
                    host.State,
                    host.Cordon,
                    host.MemberHealth))
                .ToArray();
            return Task.FromResult(observations);
        }
    }

    public Task<ProviderResourceId> ProvisionAsync(MemberHostRequest request, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Calls.Add($"provision:{request.Database}.{request.MemberId}:{request.CreateKey}");
            if (ProvisionFailure is { } failure)
                throw failure;
            var instanceId = $"ocid1.instance.fake.{++provisionSequence}";
            hosts[instanceId] = new Host(
                instanceId,
                request.Database,
                request.MemberId,
                request.Region,
                MemberHostState.Running,
                Cordon: false,
                ETag: $"rev-{provisionSequence}",
                new MemberHealth(true, 0, "follower", PeerAckCount: 2, MinReplicas: 1));
            return Task.FromResult(new ProviderResourceId(instanceId));
        }
    }

    public Task CordonAsync(ProviderResourceId id, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Calls.Add($"cordon:{id.InstanceId}");
            if (CordonFailure is { } failure)
                throw failure;
            if (!hosts.TryGetValue(id.InstanceId, out var host))
                throw new InvalidOperationException("The cordoned instance is unknown to the fleet.");
            hosts[id.InstanceId] = host with { Cordon = true };
            return Task.CompletedTask;
        }
    }

    public Task DrainAsync(ProviderResourceId id, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Calls.Add($"drain:{id.InstanceId}");
            if (DrainFailure is { } failure)
                throw failure;
            if (!hosts.TryGetValue(id.InstanceId, out var host))
                throw new InvalidOperationException("The drained instance is unknown to the fleet.");
            hosts[id.InstanceId] = host with { MemberHealth = host.MemberHealth with { Up = false } };
            return Task.CompletedTask;
        }
    }

    public Task RetireAsync(ProviderResourceId id, string etag, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Calls.Add($"retire:{id.InstanceId}:{etag}");
            if (RetireFailure is { } failure)
                throw failure;
            if (!hosts.TryGetValue(id.InstanceId, out var host))
                throw new InvalidOperationException("The retired instance is unknown to the fleet.");
            if (!string.Equals(host.ETag, etag, StringComparison.Ordinal))
                throw new InvalidOperationException("The retired instance etag did not fence the exact instance.");
            hosts.Remove(id.InstanceId);
            return Task.CompletedTask;
        }
    }

    private sealed record Host(
        string InstanceId,
        string Database,
        string MemberId,
        string Region,
        MemberHostState State,
        bool Cordon,
        string ETag,
        MemberHealth MemberHealth);
}
