using System.Text;
using System.Text.Json;

namespace TsOrch.Cli;

internal sealed class McpTools(OrchApi api)
{
    private const int MaxLogLines = 2_000;

    public IReadOnlyList<McpTool> Definitions { get; } =
    [
        Define(
            "status",
            "Fleet status: regions (health, Atlas DB counts, stateful/worker nodes, packing), nodes, services, placements and recent rollouts.",
            """{"type":"object","properties":{"region":{"type":"string","description":"Region label filter, e.g. gru"}},"additionalProperties":false}"""),
        Define(
            "logs",
            "Recent container log lines of a service, multiplexed from every node that runs it.",
            """{"type":"object","properties":{"service":{"type":"string","description":"Service name"},"node":{"type":"string","description":"Only this node id"},"tail":{"type":"integer","minimum":0,"maximum":2000,"description":"Lines per container (default 100)"}},"required":["service"],"additionalProperties":false}"""),
        Define(
            "metrics",
            "Node metrics history: 10 s points for the last hour or 1 m rollups for 48 hours (CPU, PSI, memory, disk, network, edge RPS/5xx/p95).",
            """{"type":"object","properties":{"region":{"type":"string"},"node":{"type":"string"},"window":{"type":"string","enum":["1h","48h"]}},"additionalProperties":false}"""),
        Define(
            "events",
            "Recent fleet events: deploys, canaries, rollbacks, scaling, node loss, failovers, OOM kills, secret rotation, TLS renewal.",
            """{"type":"object","properties":{"region":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":2000,"description":"Maximum events (default 100)"}},"additionalProperties":false}"""),
        Define(
            "diff",
            "Diff local service definition files against the live desired state (added, changed fields, removed).",
            """{"type":"object","properties":{"path":{"type":"string","description":"Service JSON file or directory (default deploy/services)"}},"additionalProperties":false}"""),
    ];

    public bool Exists(string name) => Definitions.Any(tool => tool.Name == name);

    public async Task<McpToolCallResult> CallAsync(string name, JsonElement? arguments, CancellationToken cancellationToken)
    {
        var outcome = name switch
        {
            "status" => await api.GetTextAsync(Query.Build("/api/status", ("region", Text(arguments, "region"))), cancellationToken),
            "logs" => await LogsAsync(arguments, cancellationToken),
            "metrics" => await MetricsAsync(arguments, cancellationToken),
            "events" => await EventsAsync(arguments, cancellationToken),
            "diff" => await DiffAsync(arguments, cancellationToken),
            _ => new NotFound($"Unknown tool '{name}'."),
        };
        return outcome switch
        {
            string text => new McpToolCallResult([new McpTextContent("text", text)], IsError: false),
            OrchError error => new McpToolCallResult([new McpTextContent("text", $"{error.Code}: {error.Message}")], IsError: true),
        };
    }

    private async Task<OrchResult<string>> LogsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (Text(arguments, "service") is not { } service)
        {
            return new Validation("logs needs a 'service' argument.");
        }

        if (!Integer(arguments, "tail", 100, 0, MaxLogLines).TryGetValue(out var tail, out var tailError))
        {
            return tailError;
        }

        var lines = new StringBuilder();
        var count = 0;
        var streamed = await api.StreamAsync(
            LogsCommand.Path(service, Text(arguments, "node"), tail, follow: false),
            CliJsonContext.Default.LogLine,
            (line, _) =>
            {
                if (count++ < MaxLogLines)
                {
                    lines.Append(line.NodeId).Append(" | ").AppendLine(line.Line);
                }

                return Task.CompletedTask;
            },
            cancellationToken);
        return streamed switch
        {
            Done => count == 0 ? $"No log lines returned for {service}." : lines.ToString(),
            OrchError error => error,
        };
    }

    private async Task<OrchResult<string>> MetricsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var window = Text(arguments, "window");
        if (window is not (null or "1h" or "48h"))
        {
            return new Validation("metrics 'window' must be '1h' or '48h'.");
        }

        return await api.GetTextAsync(
            Query.Build("/api/metrics", ("region", Text(arguments, "region")), ("node", Text(arguments, "node")), ("window", window)),
            cancellationToken);
    }

    private async Task<OrchResult<string>> EventsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (!Integer(arguments, "limit", 100, 1, 2_000).TryGetValue(out var limit, out var limitError))
        {
            return limitError;
        }

        return await api.GetTextAsync(EventsCommand.Path(Text(arguments, "region"), limit, follow: false), cancellationToken);
    }

    private async Task<OrchResult<string>> DiffAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var diff = await DiffCommand.FetchAsync(api, Text(arguments, "path") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        return diff switch
        {
            IReadOnlyList<DiffItem> items => JsonSerializer.Serialize(new DiffResponse(items), CliJsonContext.Default.DiffResponse),
            OrchError error => error,
        };
    }

    private static string? Text(JsonElement? arguments, string name) =>
        arguments is { ValueKind: JsonValueKind.Object } values
        && values.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
        && value.GetString() is { Length: > 0 } text
            ? text
            : null;

    private static OrchResult<int> Integer(JsonElement? arguments, string name, int fallback, int min, int max)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } values || !values.TryGetProperty(name, out var value))
        {
            return fallback;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number >= min && number <= max
            ? number
            : new Validation($"'{name}' must be an integer between {min} and {max}.");
    }

    private static McpTool Define(string name, string description, string schema)
    {
        using var document = JsonDocument.Parse(schema);
        return new McpTool(name, description, document.RootElement.Clone(), new McpToolAnnotations(name, ReadOnlyHint: true, DestructiveHint: false, OpenWorldHint: false));
    }
}
