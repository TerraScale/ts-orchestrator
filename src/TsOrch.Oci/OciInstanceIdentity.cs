namespace TsOrch.Oci;

public sealed record class OciInstanceIdentity(
    string TenancyId,
    string CompartmentId,
    string Region,
    string InstanceId,
    string FaultDomain);
