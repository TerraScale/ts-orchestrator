using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using System.Text.Json;
using System.Text.Json.Serialization;

try
{
    var options = OrchestratorOptions.Parse(args, Environment.GetEnvironmentVariable);
    using var shutdown = new CancellationTokenSource();

    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        shutdown.Cancel();
    };

    if (options.Command is OrchestratorCommand.Lab)
    {
        return await DevelopmentLab.ExecuteAsync(options, shutdown.Token);
    }
    if (options.Command is OrchestratorCommand.Catalog)
    {
        var serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
        };
        Console.WriteLine(JsonSerializer.Serialize(AdmittedRoleCatalog.All, serializerOptions));
        return 0;
    }

    await using var runtime = await NatsRuntime.StartAsync(options, shutdown.Token);
    Console.WriteLine($"{BuildVersion.Current.DisplayName} ready in {options.Cell} via {options.NatsUrl}");

    if (options.Command is OrchestratorCommand.Run)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, shutdown.Token);
    }

    return 0;
}
catch (OperationCanceledException)
{
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}
