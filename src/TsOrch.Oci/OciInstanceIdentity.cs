namespace TsOrch.Oci;

public sealed record class OciInstanceIdentity(
    string InstanceId,
    string Region,
    string CompartmentId,
    string FaultDomain,
    string Shape,
    string VcnIp,
    string RealmDomain,
    OciNodeMetadata Node);

public sealed record class OciNodeMetadata(
    string? Region,
    PoolKind? Pool,
    string? EnrollVault,
    string? EnrollSecretName,
    string? NetBirdUrl = null,
    string? NetBirdSetupKeySecret = null,
    string? DataVolumeId = null,
    string? InstancePoolId = null);
