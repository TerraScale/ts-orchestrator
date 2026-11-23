using System.Text.Json;

namespace TsOrch.Cli;

internal sealed class McpServer(McpTools tools, CliConsole console)
{
    private const string JsonRpcVersion = "2.0";
    private const int ParseError = -32700;
    private const int InvalidRequest = -32600;
    private const int MethodNotFound = -32601;
    private const int InvalidParams = -32602;

    private static readonly IReadOnlyList<string> ProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"];

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (await console.In.ReadLineAsync(cancellationToken).AsTask().WaitAsync(cancellationToken) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (await HandleAsync(line, cancellationToken) is { } response)
            {
                await console.Out.WriteLineAsync(JsonSerializer.Serialize(response, McpJsonContext.Default.JsonRpcResponse).AsMemory(), cancellationToken);
                await console.Out.FlushAsync(cancellationToken);
            }
        }
    }

    private async Task<JsonRpcResponse?> HandleAsync(string line, CancellationToken cancellationToken)
    {
        if (Parse(line) is not { } message)
        {
            return Failure(null, ParseError, "The message is not valid JSON.");
        }

        JsonElement idValue = default;
        var hasId = message.ValueKind == JsonValueKind.Object && message.TryGetProperty("id", out idValue);
        if (hasId && idValue.ValueKind is not (JsonValueKind.String or JsonValueKind.Number or JsonValueKind.Null))
        {
            return Failure(null, InvalidRequest, "The request id must be a string, number, or null.");
        }

        JsonElement? id = hasId ? idValue : null;
        if (message.ValueKind != JsonValueKind.Object
            || !message.TryGetProperty("jsonrpc", out var version) || version.ValueKind != JsonValueKind.String || version.GetString() != JsonRpcVersion
            || !message.TryGetProperty("method", out var methodValue) || methodValue.ValueKind != JsonValueKind.String
            || methodValue.GetString() is not { Length: > 0 } method)
        {
            return Failure(id, InvalidRequest, "Expected a JSON-RPC 2.0 request object with a method.");
        }

        JsonElement? parameters = message.TryGetProperty("params", out var paramsValue) ? paramsValue : null;
        if (parameters is { ValueKind: not (JsonValueKind.Object or JsonValueKind.Array) })
        {
            return Failure(id, InvalidParams, "The params member must be an object or array.");
        }

        if (!hasId)
        {
            await console.Error.WriteLineAsync($"ts-orch mcp: notification {method}".AsMemory(), cancellationToken);
        }

        var response = method switch
        {
            "initialize" => Success(id, JsonSerializer.SerializeToElement(Initialize(parameters), McpJsonContext.Default.McpInitializeResult)),
            "ping" => Success(id, JsonSerializer.SerializeToElement(new McpEmptyResult(), McpJsonContext.Default.McpEmptyResult)),
            "tools/list" => Success(id, JsonSerializer.SerializeToElement(new McpToolsListResult(tools.Definitions), McpJsonContext.Default.McpToolsListResult)),
            "tools/call" => await CallToolAsync(id, parameters, cancellationToken),
            _ => Failure(id, MethodNotFound, $"Method '{method}' is not supported."),
        };
        return hasId ? response : null;
    }

    private async Task<JsonRpcResponse> CallToolAsync(JsonElement? id, JsonElement? parameters, CancellationToken cancellationToken)
    {
        if (parameters is not { ValueKind: JsonValueKind.Object } values
            || !values.TryGetProperty("name", out var nameValue)
            || nameValue.ValueKind != JsonValueKind.String
            || nameValue.GetString() is not { } name
            || !tools.Exists(name))
        {
            return Failure(id, InvalidParams, "tools/call needs the 'name' of a listed tool.");
        }

        JsonElement? arguments = values.TryGetProperty("arguments", out var argumentsValue) ? argumentsValue : null;
        await console.Error.WriteLineAsync($"ts-orch mcp: tools/call {name}".AsMemory(), cancellationToken);
        var result = await tools.CallAsync(name, arguments, cancellationToken);
        return Success(id, JsonSerializer.SerializeToElement(result, McpJsonContext.Default.McpToolCallResult));
    }

    private static McpInitializeResult Initialize(JsonElement? parameters)
    {
        var requested = parameters is { ValueKind: JsonValueKind.Object } values
            && values.TryGetProperty("protocolVersion", out var versionValue)
            && versionValue.ValueKind == JsonValueKind.String
                ? versionValue.GetString()
                : null;
        return new McpInitializeResult(
            requested is not null && ProtocolVersions.Contains(requested) ? requested : ProtocolVersions[0],
            new McpServerCapabilities(new McpToolsCapability(ListChanged: false)),
            new McpServerInfo("ts-orch", CliApp.Version),
            "Read-only TerraScale orchestrator diagnostics. Tools return backplane JSON or log text; none of them change fleet state.");
    }

    private static JsonElement? Parse(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static JsonRpcResponse Success(JsonElement? id, JsonElement result) => new(JsonRpcVersion, id, Result: result);

    private static JsonRpcResponse Failure(JsonElement? id, int code, string message) => new(JsonRpcVersion, id, Error: new JsonRpcError(code, message));
}
