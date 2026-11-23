using System.Text.Json.Serialization;

namespace TsOrch.Agent;

public sealed record class NodeRegistration(string NodeId, string WsUrl);

public sealed record class ServiceImageHistory(string Active, string? Previous);

public sealed record class ImageState(
    IReadOnlyDictionary<string, ServiceImageHistory> Services,
    IReadOnlyList<string> Pulled);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    WriteIndented = true)]
[JsonSerializable(typeof(NodeRegistration))]
[JsonSerializable(typeof(ImageState))]
public sealed partial class AgentJsonContext : JsonSerializerContext;
