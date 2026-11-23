using System.Globalization;
using System.Text;
using System.Text.Json;

namespace TsOrch.Cli;

internal sealed class McpTools(OrchApi api, TimeProvider timeProvider)
{
    private const int MaxLogLines = 2_000;

    public IReadOnlyList<McpTool> Definitions { get; } =
    [
        Define(
            "status",
            "Fleet status: regions (health, Atlas DB counts, stateful/worker nodes, packing), nodes, services, placements and recent rollouts.",
            """{"type":"object","properties":{"region":{"type":"string","description":"Region label filter, e.g. gru"}},"additionalProperties":false}"""),
        Define(
            "netbird_status",
            "NetBird local daemon status, IP, FQDN, peer count, and fleet enrollment readiness.",
            """{"type":"object","properties":{},"additionalProperties":false}"""),
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

    public async Task<McpToolCallResult> CallAsync(string name, JsonElement? arguments, CancellationToken cancellationToken) =>
        name switch
        {
            "status" => Render(await api.GetTextAsync(Query.Build("/api/status", ("region", Text(arguments, "region"))), cancellationToken)),
            "netbird_status" => await NetBirdStatusAsync(cancellationToken),
            "logs" => await LogsAsync(arguments, cancellationToken),
            "metrics" => await MetricsAsync(arguments, cancellationToken),
            "events" => await EventsAsync(arguments, cancellationToken),
            "diff" => await DiffAsync(arguments, cancellationToken),
            _ => Failure(CliDiagnostic.Missing($"Unknown tool '{name}'.")),
        };

    private static McpToolCallResult Render(BackplaneText outcome) => outcome switch
    {
        string text => Success(text),
        BackplaneProblem failure => Failure(CliDiagnostic.From(failure, unexpectedConflict: true)),
    };

    private static McpToolCallResult Success(string text) => new([new McpTextContent("text", text)], IsError: false);

    private static McpToolCallResult Failure(CliDiagnostic diagnostic) =>
        new([new McpTextContent("text", $"{diagnostic.Code}: {diagnostic.Message}")], IsError: true);

    private async Task<McpToolCallResult> NetBirdStatusAsync(CancellationToken cancellationToken)
    {
        var report = await new NetBirdStatus(api, timeProvider).ReadAsync(new NetBirdStatusOptions(), cancellationToken);
        return new McpToolCallResult([new McpTextContent("text", report.ToJson())], IsError: report.Local is null && report.Fleet is null);
    }

    private async Task<McpToolCallResult> LogsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        if (Text(arguments, "service") is not { } service)
        {
            return Failure(CliDiagnostic.Usage("logs needs a 'service' argument."));
        }

        return Integer(arguments, "tail", 100, 0, MaxLogLines) switch
        {
            int tail => await CollectLogsAsync(service, Text(arguments, "node"), tail, cancellationToken),
            InvalidMcpInteger invalid => Failure(CliDiagnostic.Usage(invalid.Message)),
        };
    }

    private async Task<McpToolCallResult> CollectLogsAsync(string service, string? node, int tail, CancellationToken cancellationToken)
    {
        var lines = new StringBuilder();
        var count = 0;
        var stream = await api.StreamAsync(
            LogsCommand.Path(service, node, tail, follow: false),
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
        return stream switch
        {
            BackplaneStreamCompleted => Success(count == 0 ? $"No log lines returned for {service}." : lines.ToString()),
            BackplaneProblem failure => Failure(CliDiagnostic.From(failure, unexpectedConflict: true)),
        };
    }

    private async Task<McpToolCallResult> MetricsAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var window = Text(arguments, "window");
        if (window is not (null or "1h" or "48h"))
        {
            return Failure(CliDiagnostic.Usage("metrics 'window' must be '1h' or '48h'."));
        }

        return Render(await api.GetTextAsync(
            Query.Build("/api/metrics", ("region", Text(arguments, "region")), ("node", Text(arguments, "node")), ("window", window)),
            cancellationToken));
    }

    private async Task<McpToolCallResult> EventsAsync(JsonElement? arguments, CancellationToken cancellationToken) =>
        Integer(arguments, "limit", 100, 1, 2_000) switch
        {
            int limit => Render(await api.GetTextAsync(EventsCommand.Path(Text(arguments, "region"), limit, follow: false), cancellationToken)),
            InvalidMcpInteger invalid => Failure(CliDiagnostic.Usage(invalid.Message)),
        };

    private async Task<McpToolCallResult> DiffAsync(JsonElement? arguments, CancellationToken cancellationToken)
    {
        var outcome = await DiffCommand.FetchAsync(api, Text(arguments, "path") ?? SpecFiles.DefaultServicesPath, cancellationToken);
        return outcome switch
        {
            IReadOnlyList<DiffItem> items => Success(JsonSerializer.Serialize(new DiffResponse(items), CliJsonContext.Default.DiffResponse)),
            CliFileReadProblem failure => Failure(CliFiles.Describe(failure)),
            ServiceDefinitionInvalid failure => Failure(SpecFiles.Describe(failure)),
            DuplicateServiceDefinition failure => Failure(SpecFiles.Describe(failure)),
            ServiceDefinitionsMissing failure => Failure(SpecFiles.Describe(failure)),
            BackplaneProblem failure => Failure(CliDiagnostic.From(failure)),
        };
    }

    private static string? Text(JsonElement? arguments, string name) =>
        arguments is { ValueKind: JsonValueKind.Object } values
        && values.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
        && value.GetString() is { Length: > 0 } text
            ? text
            : null;

    private static McpInteger Integer(JsonElement? arguments, string name, int fallback, int min, int max)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } values || !values.TryGetProperty(name, out var value))
        {
            return fallback;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number >= min && number <= max
            ? number
            : new InvalidMcpInteger(name, min, max);
    }

    private sealed record class InvalidMcpInteger(string Name, int Min, int Max)
    {
        public string Message => string.Create(CultureInfo.InvariantCulture, $"'{Name}' must be an integer between {Min} and {Max}.");
    }

    private readonly union McpInteger(int, InvalidMcpInteger);

    private static McpTool Define(string name, string description, string schema)
    {
        using var document = JsonDocument.Parse(schema);
        return new McpTool(name, description, document.RootElement.Clone(), new McpToolAnnotations(name, ReadOnlyHint: true, DestructiveHint: false, OpenWorldHint: false));
    }
}
