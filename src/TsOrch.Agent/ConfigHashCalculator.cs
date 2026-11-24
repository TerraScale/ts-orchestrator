using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TsOrch.Agent;

public static class ConfigHashCalculator
{
    public static string Compute(ServiceSpec service, IReadOnlyDictionary<string, long> secretVersions)
    {
        ArgumentNullException.ThrowIfNull(service);
        ArgumentNullException.ThrowIfNull(secretVersions);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, "image", service.Image);
        foreach (var (key, value) in service.Env.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            AppendField(hash, "env", key, value);
        }

        foreach (var (name, secret) in service.Secrets.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            if (!secretVersions.TryGetValue(name, out var version))
            {
                throw new ArgumentException($"Secret version for {name} is missing.", nameof(secretVersions));
            }

            AppendField(hash, "secret", name, secret.Vault, secret.Name, version.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var mount in service.Mounts.OrderBy(static mount => mount.Target, StringComparer.Ordinal).ThenBy(static mount => mount.Source, StringComparer.Ordinal))
        {
            AppendField(hash, "mount", mount.Source, mount.Target);
        }

        if (service.ConfigFiles is { } configFiles)
        {
            foreach (var file in configFiles)
            {
                AppendField(hash, "config-file", file.Target, file.Template);
            }
        }

        AppendField(
            hash,
            "limits",
            PriorityLabel(service.Priority),
            Invariant(service.CpuRequestMilli),
            Invariant(service.CpuLimitMilli),
            Invariant(service.MemRequestMiB),
            Invariant(service.MemLimitMiB),
            Invariant(service.PidsLimit));
        AppendField(hash, "args", [.. service.Args]);
        AppendField(hash, "port", Invariant(service.Port), service.ReadyPath);
        foreach (var udpPort in service.UdpPorts.Order())
        {
            AppendField(hash, "udp", Invariant(udpPort));
        }

        if (service.Postgres is { } postgres)
        {
            AppendField(hash, "postgres", Invariant(postgres.Port));
        }

        if (service.InternalPort is { } internalPort)
        {
            AppendField(hash, "internal-port", Invariant(internalPort));
        }

        if (service.ClusterPeers)
        {
            AppendField(hash, "cluster-peers", "true");
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string Invariant(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static string PriorityLabel(PriorityTier priority) => priority switch
    {
        PriorityTier.High => "high",
        PriorityTier.Normal => "normal",
        PriorityTier.Low => "low",
        _ => throw new UnreachableException(),
    };

    private static void AppendField(IncrementalHash hash, string tag, params ReadOnlySpan<string> parts)
    {
        AppendString(hash, tag);
        Span<byte> count = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(count, parts.Length);
        hash.AppendData(count);
        foreach (var part in parts)
        {
            AppendString(hash, part);
        }
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
