using System.Globalization;

namespace TerraScale.Orchestrator.Tooling;

internal static class ToolDispatcher
{
    private static readonly IReadOnlyDictionary<string, Func<string[], Task<int>>> Commands =
        new Dictionary<string, Func<string[], Task<int>>>(StringComparer.Ordinal)
        {
            ["adr-readiness"] = arguments => Task.FromResult(AdrReadinessCommand.Run(arguments)),
            ["owner-decisions"] = arguments => Task.FromResult(OwnerDecisionCommand.Run(arguments)),
            ["development-attest"] = arguments => Task.FromResult(DevelopmentEvidenceCommand.Run(arguments)),
            ["json-format"] = arguments => Task.FromResult(JsonFormatCommand.Run(arguments)),
            ["test"] = arguments => Task.FromResult(ToolingTests.Run(arguments)),
        };

    public static async Task<int> RunAsync(string[] arguments)
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
        if (arguments.Length == 0 || !Commands.TryGetValue(arguments[0], out var command))
        {
            Console.Error.WriteLine($"Usage: terrascale-orchestrator-tooling <{string.Join('|', Commands.Keys)}> [options]");
            return 2;
        }

        try
        {
            return await command(arguments[1..]);
        }
        catch (ToolValidationException exception)
        {
            foreach (var error in exception.Errors)
            {
                Console.Error.WriteLine(error);
            }

            return 1;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }
}

internal static class JsonFormatCommand
{
    public static int Run(string[] arguments)
    {
        if (arguments.Length != 1) throw new ToolValidationException(["json-format requires exactly one file"]);
        var path = Path.GetFullPath(arguments[0], ToolingSupport.Root);
        var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))
            ?? throw new InvalidDataException("empty JSON document");
        Console.Write(ToolingSupport.Serialize(node));
        return 0;
    }
}
