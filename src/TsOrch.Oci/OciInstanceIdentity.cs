namespace TsOrch.Oci;

public sealed record class OciInstanceIdentity(
    string InstanceId,
    string Region,
    string CompartmentId,
    string FaultDomain,
    string Shape,
    string VcnIp,
    string RealmDomain);
