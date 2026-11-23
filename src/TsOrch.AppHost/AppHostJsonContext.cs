using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace TsOrch.AppHost;

internal sealed record class ImdsRegionInfoDocument(string RealmKey, string RealmDomainComponent, string RegionKey, string RegionIdentifier);

internal sealed record class ImdsInstanceDocument(
    string Id,
    string DisplayName,
    string CompartmentId,
    string AvailabilityDomain,
    string FaultDomain,
    string Region,
    string CanonicalRegionName,
    string Shape,
    string State,
    ImdsRegionInfoDocument RegionInfo);

internal sealed record class ImdsVnicDocument(string VnicId, string PrivateIp, string MacAddr, string VirtualRouterIp, string SubnetCidrBlock);

internal sealed record class SecretBundleContentDocument(string ContentType, string Content);

internal sealed record class SecretBundleDocument(
    string SecretId,
    long VersionNumber,
    IReadOnlyList<string> Stages,
    string TimeCreated,
    SecretBundleContentDocument SecretBundleContent);

internal sealed record class OciErrorDocument(string Code, string Message);

internal sealed record class UpdateInstancePoolDocument(int Size);

internal sealed record class DetachInstanceDocument(string InstanceId, bool IsDecrementSize, bool IsAutoTerminate);

internal sealed record class UpdateVolumeDocument(long SizeInGBs);

internal sealed record class InstancePoolDocument(string Id, int Size, string LifecycleState);

internal sealed record class InstanceDocument(string Id, string LifecycleState);

internal sealed record class VolumeDocument(string Id, long SizeInGBs, string LifecycleState);

internal sealed record class SecretVersionDocument(string Name, long Version);

internal sealed record class HealthDocument(bool Ok, string Service);

internal sealed record class OciCallRecord(
    long Sequence,
    string At,
    string Method,
    string Path,
    string Operation,
    string Target,
    string Detail);

internal sealed record class MockStateDocument(
    IReadOnlyList<OciCallRecord> Calls,
    IReadOnlyDictionary<string, int> Pools,
    IReadOnlyDictionary<string, long> Volumes,
    IReadOnlyDictionary<string, string> Instances,
    IReadOnlyDictionary<string, long> Secrets);

internal sealed record class EcJwk(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("crv")] string Crv,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y,
    [property: JsonPropertyName("d")] string? D = null);

internal sealed record class EcJwkSet([property: JsonPropertyName("keys")] IReadOnlyList<EcJwk> Keys);

internal sealed record class MeDocument(bool Authenticated, bool LocalDev);

internal sealed record class SeedRequestDocument(
    JsonNode Fleet,
    IReadOnlyList<JsonNode> Services,
    bool ReplaceServices,
    IReadOnlyDictionary<string, string> InstancePoolIds);

internal sealed record class ChaosRequestDocument(
    string Kind,
    string? NodeId = null,
    string? Service = null,
    string? SecretName = null,
    double? RatePct = null,
    double? CpuPct = null,
    double? UsedPct = null,
    int? DurationSeconds = null,
    string? Project = null,
    string? Database = null,
    string? Region = null);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    RespectNullableAnnotations = true,
    WriteIndented = false)]
[JsonSerializable(typeof(ImdsInstanceDocument))]
[JsonSerializable(typeof(IReadOnlyList<ImdsVnicDocument>))]
[JsonSerializable(typeof(SecretBundleDocument))]
[JsonSerializable(typeof(OciErrorDocument))]
[JsonSerializable(typeof(UpdateInstancePoolDocument))]
[JsonSerializable(typeof(DetachInstanceDocument))]
[JsonSerializable(typeof(UpdateVolumeDocument))]
[JsonSerializable(typeof(InstancePoolDocument))]
[JsonSerializable(typeof(InstanceDocument))]
[JsonSerializable(typeof(VolumeDocument))]
[JsonSerializable(typeof(SecretVersionDocument))]
[JsonSerializable(typeof(HealthDocument))]
[JsonSerializable(typeof(MockStateDocument))]
[JsonSerializable(typeof(EcJwk))]
[JsonSerializable(typeof(EcJwkSet))]
[JsonSerializable(typeof(MeDocument))]
[JsonSerializable(typeof(SeedRequestDocument))]
[JsonSerializable(typeof(ChaosRequestDocument))]
internal sealed partial class AppHostJsonContext : JsonSerializerContext;
