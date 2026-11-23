using System.Text.Json;
using System.Text.Json.Serialization;

namespace TsOrch.Cli;

internal sealed record class JsonRpcError(int Code, string Message);

internal sealed record class JsonRpcResponse(
    string Jsonrpc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] JsonElement? Id,
    JsonElement? Result = null,
    JsonRpcError? Error = null);

internal sealed record class McpToolsCapability(bool ListChanged);

internal sealed record class McpServerCapabilities(McpToolsCapability Tools);

internal sealed record class McpServerInfo(string Name, string Version);

internal sealed record class McpInitializeResult(string ProtocolVersion, McpServerCapabilities Capabilities, McpServerInfo ServerInfo, string Instructions);

internal sealed record class McpToolAnnotations(string Title, bool ReadOnlyHint, bool DestructiveHint, bool OpenWorldHint);

internal sealed record class McpTool(string Name, string Description, JsonElement InputSchema, McpToolAnnotations Annotations);

internal sealed record class McpToolsListResult(IReadOnlyList<McpTool> Tools);

internal sealed record class McpTextContent(string Type, string Text);

internal sealed record class McpToolCallResult(IReadOnlyList<McpTextContent> Content, bool IsError);

internal sealed record class McpEmptyResult;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(JsonRpcResponse))]
[JsonSerializable(typeof(McpInitializeResult))]
[JsonSerializable(typeof(McpToolsListResult))]
[JsonSerializable(typeof(McpToolCallResult))]
[JsonSerializable(typeof(McpEmptyResult))]
internal sealed partial class McpJsonContext : JsonSerializerContext;
