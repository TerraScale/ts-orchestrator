using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.Observability;
using TerraScale.Orchestrator.Security;
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
    string? LocalEnvironment(string key) =>
        runtimeConfiguration?.GetEnvironmentValue(key) ?? Environment.GetEnvironmentVariable(key);
    if (args.FirstOrDefault() is "infisical")
    {
        return await InfisicalCli.ExecuteAsync(
            args.Skip(1).ToArray(),
            LocalEnvironment,
            shutdown.Token);
    }
    var infisicalConfiguration = InfisicalConfiguration.RequiresRuntimeSecretEnvironment(args.FirstOrDefault())
        ? InfisicalConfiguration.Resolve(LocalEnvironment)
        : null;
    using var infisicalEnvironment = infisicalConfiguration is null
        ? null
        : await InfisicalSecretEnvironment.LoadAsync(infisicalConfiguration, shutdown.Token);
    string? ResolvedEnvironment(string key) =>
        LocalEnvironment(key) ?? infisicalEnvironment?.GetValue(key);
    if (args.FirstOrDefault() is "runner")
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("CI runners require Linux isolation.");
        return await CiRunnerProcess.ExecuteAsync(ResolvedEnvironment, shutdown.Token);
    }
    var options = OrchestratorOptions.Parse(
        args,
        ResolvedEnvironment);
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
    if (options.Command is OrchestratorCommand.ProvisionJournal)
    {
        await NatsOperationJournalProvisioner.ProvisionAsync(options, shutdown.Token);
        Console.WriteLine(
            $"Provisioned regional control topology, exact durable startup and CellSpec consumers for " +
            $"{options.Cell}/{options.Instance}, and immutable R3 operation journal stores via {options.NatsUrl}");
        return 0;
    }
    if (options.Command is OrchestratorCommand.JournalWriter)
    {
        await using var writer = await NatsJournalWriterRuntime.StartAsync(options, shutdown.Token);
        Console.WriteLine($"{BuildVersion.Current.DisplayName} isolated journal writer ready in {options.Cell} via {options.NatsUrl}");
        await writer.Completion.WaitAsync(shutdown.Token);
        return 0;
    }

    using var commandIdentity = options.CommandIdentity?.Open();
    using var ciRunnerNatsIdentity = options.CiRunnerNatsIdentity?.Open();
    using var telemetry = OrchestratorTelemetry.Start(options, ResolvedEnvironment);
    using var startupActivity = telemetry.StartRuntime();
    var startupTimestamp = Stopwatch.GetTimestamp();
    NatsRuntime? runtime = null;
    GlobalNatsRuntime? globalRuntime = null;
    NativeGitOpsRuntime? nativeGitOpsRuntime = null;
    try
    {
        runtime = await NatsRuntime.StartAsync(options, shutdown.Token);
        var observedRuntime = runtime;
        telemetry.ObserveMembership(() => observedRuntime.MembershipHealth);
        if (options.GlobalNats is not null)
        {
            var verifier = commandIdentity?.Verifier;
            NativeGitOpsRuntime.ValidateConfiguration(
                globalNatsConfigured: true,
                nativeGitOpsPublicationConfigured: commandIdentity?.Signer is not null,
                trustedVerifierConfigured: verifier is not null);
            globalRuntime = await GlobalNatsRuntime.StartAsync(
                options.GlobalNats,
                options.Instance,
                options.Cell,
                ciRunnerNatsIdentity,
                shutdown.Token,
                options.ForgejoSource,
                options.ForgejoCiSourceGraph,
                options.Command == OrchestratorCommand.Run ? options.OciCiRunnerPool : null,
                commandIdentity?.Signer,
                commandIdentity?.Signer,
                commandIdentity?.Verifier,
                commandIdentity?.Verifier,
                commandIdentity?.Signer,
                verifier is not null);
            if (options.Command is OrchestratorCommand.Run && NativeGitOpsRuntime.IsEnabled(
                    globalNatsConfigured: true,
                    trustedVerifierConfigured: verifier is not null))
                nativeGitOpsRuntime = NativeGitOpsRuntime.Start(
                    runtime, globalRuntime, verifier ?? throw new InvalidOperationException("Native GitOps verifier is unavailable."));
        }
    }
    catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception exception)
    {
        if (nativeGitOpsRuntime is not null) await nativeGitOpsRuntime.DisposeAsync();
        if (globalRuntime is not null) await globalRuntime.DisposeAsync();
        if (runtime is not null) await runtime.DisposeAsync();
        telemetry.RecordFailure(Stopwatch.GetElapsedTime(startupTimestamp), exception);
        startupActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
        throw;
    }
    await using var ownedRuntime = runtime;
    await using var ownedGlobalRuntime = globalRuntime;
    await using var ownedNativeGitOpsRuntime = nativeGitOpsRuntime;
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
                () => ownedGlobalRuntime.AuthoritySnapshot,
                ownedGlobalRuntime.NativeGitOpsHandoffs)
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
            ownedNativeGitOpsRuntime?.Completion,
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
