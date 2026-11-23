using System.Collections.Frozen;
using TsOrch.Agent;
using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class AgentIdentityOverrides(string? NodeId, string? Region, PoolKind? PoolKind, string? VcnIp);

internal sealed class OciSecretProvider(OciVaultClient vault) : ISecretProvider
{
    public async Task<OrchResult<ResolvedSecret>> GetSecretAsync(SecretRef secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var fetched = await vault.GetSecretAsync(secret.Vault, secret.Name, cancellationToken);
        return fetched switch
        {
            VaultSecretBundle bundle => new ResolvedSecret(secret, bundle.VersionNumber, bundle.Value),
            OrchError error => error,
        };
    }
}

internal sealed class OciHostIdentityProvider(
    OciImdsClient imds,
    OrchHttp http,
    OciEnvironment environment,
    AgentIdentityOverrides overrides) : IHostIdentityProvider
{
    public const string StandaloneShape = "standalone";
    public const string StandaloneFaultDomain = "standalone";

    private static readonly FrozenDictionary<string, string> Labels = FrozenDictionary<string, string>.Empty;

    public async Task<OrchResult<HostIdentity>> ResolveIdentityAsync(CancellationToken cancellationToken)
    {
        var standalone = environment switch
        {
            OciCloud => overrides is { NodeId: not null, Region: not null, VcnIp: not null },
            OciMock => false,
        };
        return standalone ? Standalone() : await FromMetadataAsync(cancellationToken);
    }

    private OrchResult<HostIdentity> Standalone() =>
        overrides is { NodeId: { } nodeId, Region: { } region, VcnIp: { } vcnIp, PoolKind: { } poolKind }
            ? new HostIdentity(nodeId, region, poolKind, vcnIp, StandaloneShape, StandaloneFaultDomain, Labels)
            : new Validation($"{AgentCommand.PoolKindVariable} is required when the node identity is set without OCI instance metadata.");

    private async Task<OrchResult<HostIdentity>> FromMetadataAsync(CancellationToken cancellationToken)
    {
        var identityResult = await imds.GetIdentityAsync(cancellationToken);
        if (!identityResult.TryGetValue(out var identity, out var identityError))
        {
            return identityError;
        }

        var placementResult = overrides is { Region: { } region, PoolKind: { } poolKind }
            ? new OrchResult<ImdsNodeMetadata>(new ImdsNodeMetadata(region, poolKind))
            : await ReadNodeMetadataAsync(cancellationToken);
        if (!placementResult.TryGetValue(out var placement, out var placementError))
        {
            return placementError;
        }

        if ((overrides.Region ?? placement.Region) is not { } resolvedRegion)
        {
            return new Validation($"OCI instance metadata carries no ts_region; set {AgentCommand.RegionVariable}.");
        }

        if ((overrides.PoolKind ?? placement.Pool) is not { } resolvedPool)
        {
            return new Validation($"OCI instance metadata carries no ts_pool; set {AgentCommand.PoolKindVariable}.");
        }

        return new HostIdentity(identity.InstanceId, resolvedRegion, resolvedPool, identity.VcnIp, identity.Shape, identity.FaultDomain, Labels);
    }

    private async Task<OrchResult<ImdsNodeMetadata>> ReadNodeMetadataAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(imds.BaseUrl, "instance/metadata/"));
        request.Headers.Authorization = new("Bearer", "Oracle");
        return await http.SendJsonAsync(request, CliJsonContext.Default.ImdsNodeMetadata, OrchHttp.DefaultTimeout, cancellationToken);
    }
}
