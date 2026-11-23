using System.Globalization;

namespace TsOrch.Agent;

public interface ISecretProvider
{
    Task<OrchResult<ResolvedSecret>> GetSecretAsync(SecretRef secret, CancellationToken cancellationToken);
}

public interface IHostIdentityProvider
{
    Task<OrchResult<HostIdentity>> ResolveIdentityAsync(CancellationToken cancellationToken);
}

public sealed record class ResolvedSecret(SecretRef Ref, long Version, string Value)
{
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{nameof(ResolvedSecret)} {{ Vault = {Ref.Vault}, Name = {Ref.Name}, Version = {Version} }}");
}

public sealed record class HostIdentity(
    string InstanceId,
    string Region,
    PoolKind PoolKind,
    string VcnIp,
    string Shape,
    string FaultDomain,
    IReadOnlyDictionary<string, string> Labels);
