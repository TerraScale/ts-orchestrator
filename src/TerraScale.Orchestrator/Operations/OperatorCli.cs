using System.Text.Json;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Operations;

internal static class OperatorCli
{
    private static readonly JsonSerializerOptions OutputOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<int> ExecuteAsync(
        IReadOnlyList<string> arguments,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        if (arguments.FirstOrDefault() != "status")
        {
            throw new ArgumentException("operator requires 'status'.");
        }
        var values = ParseValues(arguments.Skip(1).ToArray());
        var cell = Value(values, "--cell", environment("TS_ORCH_CELL") ?? "local");
        var url = Value(values, "--nats-url", environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222");
        _ = OrchestratorOptions.Parse(
            ["check"],
            key => key switch
            {
                "TS_ORCH_CELL" => cell,
                "TS_ORCH_NATS_URL" => url,
                "TS_ORCH_REPLICAS" => "1",
                _ => null
            });

        await using var client = new NatsClient(new NatsOpts
        {
            Url = url,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(10)
        });
        await client.ConnectAsync();
        var response = await client.RequestAsync<string, string>(
            new NatsTopology(cell, 1).StatusSubject,
            "status",
            cancellationToken: cancellationToken);
        var status = JsonSerializer.Deserialize(
            response.Data ?? throw new InvalidOperationException("The regional controller returned no status."),
            RegionalControllerStatusJsonContext.Default.RegionalControllerStatus)
            ?? throw new InvalidOperationException("The regional controller returned no status.");
        status.Validate(cell);
        Console.WriteLine(JsonSerializer.Serialize(status, OutputOptions));
        return 0;
    }

    internal static IReadOnlyDictionary<string, string> ParseValues(IReadOnlyList<string> arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Count; index += 2)
        {
            if (index + 1 >= arguments.Count ||
                arguments[index] is not ("--cell" or "--nats-url") ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
            {
                throw new ArgumentException("operator status accepts [--cell <cell>] [--nats-url <nats-url>].");
            }
        }
        return values;
    }

    private static string Value(IReadOnlyDictionary<string, string> values, string key, string fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;
}
