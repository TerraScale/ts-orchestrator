using NATS.Client.Core;
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
    var startupPlan = OrchestratorRuntimeComposition.Plan(options);
    // Composition-level deployment mode for the direct-delivery provenance boundary: callers
    // must never select trust per request, so it is read from configuration once at startup.
    // Composition-level deployment mode for the direct-delivery provenance boundary: callers
    // must never select trust per request, so it is read from configuration once at startup.
    // An unrecognized non-empty value fails closed instead of silently degrading to development:
    // this setting selects a trust posture, so "prod" must never run as Development.
    var deliveryDeploymentModeRaw = (ResolvedEnvironment("TS_ORCH_DELIVERY_DEPLOYMENT_MODE") ?? string.Empty).Trim();
    var deliveryDeploymentMode = deliveryDeploymentModeRaw.Length == 0
        ? TerraScale.Orchestrator.Delivery.DirectDeliveryDeploymentMode.Development
        : deliveryDeploymentModeRaw.Equals("development", StringComparison.OrdinalIgnoreCase)
            ? TerraScale.Orchestrator.Delivery.DirectDeliveryDeploymentMode.Development
            : deliveryDeploymentModeRaw.Equals("production", StringComparison.OrdinalIgnoreCase)
                ? TerraScale.Orchestrator.Delivery.DirectDeliveryDeploymentMode.Production
                : throw new ArgumentException(
                    $"TS_ORCH_DELIVERY_DEPLOYMENT_MODE must be 'development' or 'production', not '{deliveryDeploymentModeRaw}'.");
    // The production admitted-target allow-list is configuration, never request input; parsing it
    // here means production composition fails closed at startup instead of at first request.
    TerraScale.Orchestrator.Delivery.DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null;
    var admittedDeliveryTargetEntries = ResolvedEnvironment("TS_ORCH_DELIVERY_ADMITTED_TARGETS");
    if (!string.IsNullOrWhiteSpace(admittedDeliveryTargetEntries))
        admittedDeliveryTargets = TerraScale.Orchestrator.Delivery.DirectDeliveryAdmittedTargets.Parse(
            admittedDeliveryTargetEntries.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
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
    GlobalCellDirectoryLifecycle? directoryLifecycle = null;
    GlobalNatsRuntime? globalRuntime = null;
    NativeGitOpsRuntime? nativeGitOpsRuntime = null;
    try
    {
        runtime = await NatsRuntime.StartAsync(
            options,
            shutdown.Token,
            commandIdentity?.Verifier,
            deliveryDeploymentMode,
            startupPlan.RegistersDirectDeliveryEndpoint,
            admittedDeliveryTargets);
        if (startupPlan.StartsDirectDelivery && runtime.DirectDelivery is null)
            throw new InvalidOperationException("The direct delivery mutation path was not composed with durable regional adapters.");
        var observedRuntime = runtime;
        telemetry.ObserveMembership(() => observedRuntime.MembershipHealth);
        if (options.GlobalDirectoryNats is not null)
        {
            try
            {
                directoryLifecycle = GlobalCellDirectoryLifecycle.Start(
                    options.GlobalDirectoryNats,
                    options.GlobalDirectoryServiceNats,
                    () => observedRuntime.MembershipSnapshot,
                    () => observedRuntime.AuthoritySnapshot,
                    publishEnabled: options.Command is OrchestratorCommand.Run,
                    shutdown.Token,
                    exception => Console.Error.WriteLine(
                        $"Global directory is unavailable ({exception.GetType().Name}); regional control remains active."));
                var observedDirectory = directoryLifecycle;
                telemetry.ObserveCellDirectory(() => observedDirectory.Snapshot);
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    $"Global directory is unavailable ({exception.GetType().Name}); regional control remains active.");
            }
        }
        if (options.GlobalNats is not null)
        {
            var verifier = commandIdentity?.Verifier;
            NativeGitOpsRuntime.ValidateConfiguration(
                globalNatsConfigured: true,
                nativeGitOpsPublicationConfigured: commandIdentity?.Signer is not null,
                trustedVerifierConfigured: verifier is not null);
            try
            {
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
                    verifier is not null,
                    ciConsumptionEnabled: startupPlan.StartsCiConsumption,
                    deliveryDeploymentMode: deliveryDeploymentMode,
                    admittedDeliveryTargets: admittedDeliveryTargets);
                if (startupPlan.StartsDirectDelivery && globalRuntime.DirectDelivery is null)
                    throw new InvalidOperationException("The global direct delivery mutation path was not composed with durable adapters.");
                if (globalRuntime is not null && options.Command is OrchestratorCommand.Run &&
                    NativeGitOpsRuntime.IsEnabled(
                        globalNatsConfigured: GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed(options.Cell),
                        trustedVerifierConfigured: verifier is not null))
                    nativeGitOpsRuntime = NativeGitOpsRuntime.Start(
                        runtime,
                        globalRuntime,
                        verifier ?? throw new InvalidOperationException("Native GitOps verifier is unavailable."));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    $"Global control is unavailable ({exception.GetType().Name}); regional control remains active.");
            }
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
        if (directoryLifecycle is not null) await directoryLifecycle.DisposeAsync();
        if (runtime is not null) await runtime.DisposeAsync();
        telemetry.RecordFailure(Stopwatch.GetElapsedTime(startupTimestamp), exception);
        startupActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
        throw;
    }
    await using var ownedRuntime = runtime;
    await using var ownedDirectoryLifecycle = directoryLifecycle;
    await using var ownedGlobalRuntime = globalRuntime;
    await using var ownedNativeGitOpsRuntime = nativeGitOpsRuntime;
    ForgejoWebhookServer? webhookServer = null;
    ForgejoSourcePoller? sourcePoller = null;
    try
    {
        webhookServer = options.Command == OrchestratorCommand.Run && options.ForgejoWebhook is not null &&
                        ownedGlobalRuntime is not null
            ? ForgejoWebhookServer.Start(options.ForgejoWebhook, ownedGlobalRuntime!.ForgejoWebhooks)
            : null;
        sourcePoller = options.Command == OrchestratorCommand.Run && options.ForgejoSource is not null &&
                       ownedGlobalRuntime is not null
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
    Console.WriteLine(ownedGlobalRuntime is null
        ? $"{BuildVersion.Current.DisplayName} ready in {options.Cell} via {options.NatsUrl}"
        : $"{BuildVersion.Current.DisplayName} ready in {options.Cell} with regional and global authority");

    if (options.Command is OrchestratorCommand.Run)
    {
        // Regional lifecycle is intentionally independent of every WAN/global
        // subsystem. Their own health surfaces report failures and recovery.
        await ownedRuntime.Completion.WaitAsync(shutdown.Token);
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
