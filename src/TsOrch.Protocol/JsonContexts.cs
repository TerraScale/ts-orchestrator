using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Protocol;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    AllowOutOfOrderMetadataProperties = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(FleetConfig))]
[JsonSerializable(typeof(ServiceSpec))]
[JsonSerializable(typeof(IReadOnlyList<ServiceSpec>))]
[JsonSerializable(typeof(NodeInfo))]
[JsonSerializable(typeof(PlacementInfo))]
[JsonSerializable(typeof(RolloutInfo))]
[JsonSerializable(typeof(EventRecord))]
[JsonSerializable(typeof(IReadOnlyList<EventRecord>))]
[JsonSerializable(typeof(TlsBundle))]
[JsonSerializable(typeof(MetricsPoint10s))]
[JsonSerializable(typeof(MetricsPoint1m))]
public sealed partial class FleetJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    AllowOutOfOrderMetadataProperties = true)]
[JsonSerializable(typeof(AgentMessage))]
[JsonSerializable(typeof(BackplaneMessage))]
public sealed partial class WireJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(EdgeRoutesSnapshot))]
[JsonSerializable(typeof(TlsBundle))]
[JsonSerializable(typeof(EdgeMetricsSnapshot))]
public sealed partial class EdgeJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    AllowOutOfOrderMetadataProperties = true)]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(SshChallengeRequest))]
[JsonSerializable(typeof(SshChallengeResponse))]
[JsonSerializable(typeof(SshVerifyRequest))]
[JsonSerializable(typeof(SshVerifyResponse))]
[JsonSerializable(typeof(NodeEnrollRequest))]
[JsonSerializable(typeof(NodeEnrollResponse))]
[JsonSerializable(typeof(DeployRequest))]
[JsonSerializable(typeof(RollbackRequest))]
[JsonSerializable(typeof(RolloutInfo))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(TopResponse))]
[JsonSerializable(typeof(IReadOnlyList<DiffItem>))]
[JsonSerializable(typeof(IReadOnlyList<ServiceSpec>))]
[JsonSerializable(typeof(IReadOnlyList<EventRecord>))]
[JsonSerializable(typeof(ExecRequest))]
[JsonSerializable(typeof(ExecResponse))]
[JsonSerializable(typeof(ChaosRequest))]
[JsonSerializable(typeof(AtlasTopology))]
[JsonSerializable(typeof(AtlasPlacement))]
[JsonSerializable(typeof(AtlasPublishRequest))]
[JsonSerializable(typeof(AtlasDiscoveryResponse))]
[JsonSerializable(typeof(AtlasResolveResponse))]
[JsonSerializable(typeof(AtlasKeysResponse))]
public sealed partial class ApiJsonContext : JsonSerializerContext;

public static class ProtocolJson
{
    public static JsonSerializerOptions CombinedOptions { get; } = new()
    {
        TypeInfoResolver = JsonTypeInfoResolver.Combine(
            ApiJsonContext.Default,
            WireJsonContext.Default,
            FleetJsonContext.Default,
            EdgeJsonContext.Default),
    };
}
