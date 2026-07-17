using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.Observability;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

try
{
    if (args.FirstOrDefault() is "runtime")
    {
        return HostRuntimeCli.Execute(args.Skip(1).ToArray());
    }
    using var shutdown = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        shutdown.Cancel();
    };
    if (args.FirstOrDefault() is "operator")
    {
        return await OperatorCli.ExecuteAsync(
            args.Skip(1).ToArray(),
            Environment.GetEnvironmentVariable,
            shutdown.Token);
    }
    var runtimeConfiguration = OrchestratorRuntimeConfiguration.Load(
        Environment.GetEnvironmentVariable("TS_ORCH_CONFIG"));
    var options = OrchestratorOptions.Parse(
        args,
        key => runtimeConfiguration?.GetEnvironmentValue(key) ?? Environment.GetEnvironmentVariable(key));
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

    using var commandIdentity = options.CommandIdentity?.Open();
    using var telemetry = OrchestratorTelemetry.Start(options, Environment.GetEnvironmentVariable);
    using var startupActivity = telemetry.StartRuntime();
    var startupTimestamp = Stopwatch.GetTimestamp();
    NatsRuntime? runtime = null;
    GlobalNatsRuntime? globalRuntime = null;
    try
    {
        runtime = await NatsRuntime.StartAsync(options, shutdown.Token);
        if (options.GlobalNats is not null)
            globalRuntime = await GlobalNatsRuntime.StartAsync(
                options.GlobalNats,
                options.Instance,
                shutdown.Token);
    }
    catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception exception)
    {
        if (globalRuntime is not null) await globalRuntime.DisposeAsync();
        if (runtime is not null) await runtime.DisposeAsync();
        telemetry.RecordFailure(Stopwatch.GetElapsedTime(startupTimestamp), exception);
        startupActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
        throw;
    }
    await using var ownedRuntime = runtime;
    await using var ownedGlobalRuntime = globalRuntime;
    ForgejoWebhookServer? webhookServer = null;
    ForgejoSourcePoller? sourcePoller = null;
    try
    {
        webhookServer = options.Command == OrchestratorCommand.Run && options.ForgejoWebhook is not null
            ? ForgejoWebhookServer.Start(options.ForgejoWebhook, ownedGlobalRuntime!.ForgejoWebhooks)
            : null;
        sourcePoller = options.Command == OrchestratorCommand.Run && options.ForgejoSource is not null
            ? ForgejoSourcePoller.Start(
                options.ForgejoSource,
                ownedGlobalRuntime!.ForgejoSources,
                ownedGlobalRuntime.NativeGitOpsSources,
                () => ownedGlobalRuntime.AuthoritySnapshot)
            : null;
    }
    catch (Exception exception)
    {
        if (sourcePoller is not null) await sourcePoller.DisposeAsync();
        if (webhookServer is not null) await webhookServer.DisposeAsync();
        telemetry.RecordFailure(Stopwatch.GetElapsedTime(startupTimestamp), exception);
        startupActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
        throw;
    }
    await using var webhooks = webhookServer;
    await using var sources = sourcePoller;
    telemetry.RecordReady(Stopwatch.GetElapsedTime(startupTimestamp));
    startupActivity?.SetStatus(ActivityStatusCode.Ok);
    Console.WriteLine(options.GlobalNats is null
        ? $"{BuildVersion.Current.DisplayName} ready in {options.Cell} via {options.NatsUrl}"
        : $"{BuildVersion.Current.DisplayName} ready in {options.Cell} with regional and global authority");

    if (options.Command is OrchestratorCommand.Run)
    {
        var completions = new[]
        {
            ownedRuntime.Completion,
            ownedGlobalRuntime?.Completion,
            webhooks?.Completion,
            sources?.Completion,
        }.Where(static task => task is not null).Cast<Task>();
        var completion = Task.WhenAny(completions).Unwrap();
        await completion.WaitAsync(shutdown.Token);
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
