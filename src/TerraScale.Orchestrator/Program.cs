using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Messaging;

try
{
    var options = OrchestratorOptions.Parse(args, Environment.GetEnvironmentVariable);
    using var shutdown = new CancellationTokenSource();

    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        shutdown.Cancel();
    };

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
