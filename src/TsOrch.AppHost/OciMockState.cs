using System.Globalization;

namespace TsOrch.AppHost;

internal sealed record class MockVolumeShrinkRejected(string VolumeId, long CurrentSize, long RequestedSize)
{
    public string Message => string.Create(CultureInfo.InvariantCulture, $"Volume '{VolumeId}' cannot shrink from {CurrentSize} GB to {RequestedSize} GB.");
}

internal readonly union MockVolumeResize(VolumeDocument, MockVolumeShrinkRejected);

internal sealed record class MockSecret(string SecretId, long Version, string Value, DateTimeOffset CreatedAt);

internal sealed class OciMockState(TimeProvider timeProvider)
{
    private const int MaxRecordedCalls = 1000;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, int> _pools = [with(StringComparer.Ordinal)];
    private readonly Dictionary<string, long> _volumes = [with(StringComparer.Ordinal)];
    private readonly Dictionary<string, string> _instances = [with(StringComparer.Ordinal)];
    private readonly Dictionary<string, MockSecret> _secrets = [with(StringComparer.Ordinal)];
    private readonly Queue<OciCallRecord> _calls = new();
    private long _sequence;

    public void SeedSecret(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        lock (_gate)
        {
            _secrets.TryAdd(name, new MockSecret(SecretId(name), 1, value, timeProvider.GetUtcNow()));
        }
    }

    public MockSecret? FindSecret(string name)
    {
        lock (_gate)
        {
            return _secrets.GetValueOrDefault(name);
        }
    }

    public MockSecret BumpSecret(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            var now = timeProvider.GetUtcNow();
            var next = _secrets.TryGetValue(name, out var current)
                ? current with { Version = current.Version + 1, Value = RotatedValue(name, current.Version + 1), CreatedAt = now }
                : new MockSecret(SecretId(name), 1, RotatedValue(name, 1), now);
            _secrets[name] = next;
            RecordLocked("POST", $"/_mock/secrets/{name}/bump", "BumpSecret", name, $"version={next.Version.ToString(CultureInfo.InvariantCulture)}");
            return next;
        }
    }

    public InstancePoolDocument GetPool(string poolId)
    {
        lock (_gate)
        {
            return new InstancePoolDocument(poolId, _pools.GetValueOrDefault(poolId), "RUNNING");
        }
    }

    public InstancePoolDocument UpdatePool(string path, string poolId, int size)
    {
        lock (_gate)
        {
            _pools[poolId] = size;
            RecordLocked("PUT", path, "UpdateInstancePool", poolId, $"size={size.ToString(CultureInfo.InvariantCulture)}");
            return new InstancePoolDocument(poolId, size, "RUNNING");
        }
    }

    public InstancePoolDocument DetachInstance(string path, string poolId, DetachInstanceDocument request)
    {
        lock (_gate)
        {
            var size = _pools.GetValueOrDefault(poolId);
            if (request.IsDecrementSize)
            {
                size = Math.Max(0, size - 1);
            }

            _pools[poolId] = size;
            _instances[request.InstanceId] = request.IsAutoTerminate ? "TERMINATED" : "DETACHED";
            RecordLocked(
                "POST",
                path,
                "DetachInstancePoolInstance",
                poolId,
                $"instanceId={request.InstanceId} isDecrementSize={Flag(request.IsDecrementSize)} isAutoTerminate={Flag(request.IsAutoTerminate)} size={size.ToString(CultureInfo.InvariantCulture)}");
            return new InstancePoolDocument(poolId, size, "RUNNING");
        }
    }

    public void TerminateInstance(string path, string instanceId, string preserveBootVolume)
    {
        lock (_gate)
        {
            _instances[instanceId] = "TERMINATED";
            RecordLocked("DELETE", path, "TerminateInstance", instanceId, $"preserveBootVolume={preserveBootVolume}");
        }
    }

    public InstanceDocument InstanceAction(string path, string instanceId, string action)
    {
        lock (_gate)
        {
            _instances[instanceId] = "RUNNING";
            RecordLocked("POST", path, "InstanceAction", instanceId, $"action={action}");
            return new InstanceDocument(instanceId, "RUNNING");
        }
    }

    public MockVolumeResize UpdateVolume(string path, string volumeId, long sizeInGBs)
    {
        lock (_gate)
        {
            if (_volumes.TryGetValue(volumeId, out var current) && sizeInGBs < current)
            {
                return new MockVolumeShrinkRejected(volumeId, current, sizeInGBs);
            }

            _volumes[volumeId] = sizeInGBs;
            RecordLocked("PUT", path, "UpdateVolume", volumeId, $"sizeInGBs={sizeInGBs.ToString(CultureInfo.InvariantCulture)}");
            return new VolumeDocument(volumeId, sizeInGBs, "AVAILABLE");
        }
    }

    public MockStateDocument Snapshot()
    {
        lock (_gate)
        {
            return new MockStateDocument(
                [.. _calls],
                new Dictionary<string, int>(_pools, StringComparer.Ordinal),
                new Dictionary<string, long>(_volumes, StringComparer.Ordinal),
                new Dictionary<string, string>(_instances, StringComparer.Ordinal),
                _secrets.ToDictionary(static entry => entry.Key, static entry => entry.Value.Version, StringComparer.Ordinal));
        }
    }

    private void RecordLocked(string method, string path, string operation, string target, string detail)
    {
        _sequence++;
        _calls.Enqueue(new OciCallRecord(
            _sequence,
            timeProvider.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
            method,
            path,
            operation,
            target,
            detail));
        while (_calls.Count > MaxRecordedCalls)
        {
            _calls.Dequeue();
        }
    }

    private static string SecretId(string name) => $"ocid1.vaultsecret.oc1.sa-saopaulo-1.local-{name}";

    private static string RotatedValue(string name, long version) =>
        $"local-{name}-v{version.ToString(CultureInfo.InvariantCulture)}";

    private static string Flag(bool value) => value ? "true" : "false";
}
