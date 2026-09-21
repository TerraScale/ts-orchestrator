using NATS.Client.Core;
using TerraScale.Orchestrator;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.Observability;
using TerraScale.Orchestrator.Security;
using TerraScale.Orchestrator.Tooling;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

try
{
    if (ToolDispatcher.IsToolingCommand(args.FirstOrDefault()))
    {
        return await ToolDispatcher.RunAsync(args);
    }
    if (args.FirstOrDefault() is "runtime")
    {
        return HostRuntimeCli.Execute(args.Skip(1).ToArray());
    }
    using var shutdown = new CancellationTokenSource();
    using var shutdownSignals = ShutdownSignals.Wire(shutdown);
    if (args.FirstOrDefault() is "oci-bootstrap-secrets")
    {
        return await TerraScale.Orchestrator.Bootstrap.Secrets.OciBootstrapSecretsCli.ExecuteAsync(
            args.Skip(1).ToArray(), shutdown.Token);
    }
    if (args.FirstOrDefault() is "oci-founding-peers")
    {
        return await TerraScale.Orchestrator.Bootstrap.Founding.OciFoundingPeersCli.ExecuteAsync(
            args.Skip(1).ToArray(), shutdown.Token);
    }
    if (args.FirstOrDefault() is "oci-sign-founding")
    {
        return await TerraScale.Orchestrator.Bootstrap.Founding.OciFoundingGrantCli.ExecuteAsync(
            args.Skip(1).ToArray(), shutdown.Token);
    }
    if (args.FirstOrDefault() is "operator")
    {
        return await OperatorCli.ExecuteAsync(
            args.Skip(1).ToArray(),
            Environment.GetEnvironmentVariable,
            shutdown.Token);
    }
    if (args.FirstOrDefault() is "edge-routing-publish")
    {
        return await TerraScale.Orchestrator.ControlPlane.EdgeRouting.EdgeRoutingPublishCli.ExecuteAsync(
            args.Skip(1).ToArray(),
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
    if (!string.IsNullOrWhiteSpace(ResolvedEnvironment("TS_ORCH_HOST_ROLES")))
        throw new InvalidOperationException("Controller run/check cannot execute host roles; a dedicated restricted host runtime is required.");
    var options = OrchestratorOptions.Parse(
        args,
        ResolvedEnvironment);
    var startupPlan = OrchestratorRuntimeComposition.Plan(options);
    var autoProvision = ResolvedEnvironment("TS_ORCH_AUTO_PROVISION") is not { } autoProvisionValue ||
        autoProvisionValue is not ("0" or "false");
    var hostSessions = TerraScale.Orchestrator.ControlPlane.Delivery.RegionalHostSessionConfiguration.Load(
        ResolvedEnvironment("TS_ORCH_HOST_SESSION_POLICY_FILE"), options.Cell);
    // The TerraBase placement reconciler turns on with its bounded configuration file and
    // its member-host fleet file together: the runtime builds the OCI fleet where the
    // authority lease and the NATS stores live, and refuses to run with only one of the
    // two configured — fail closed at startup, never a reconciler running against nothing.
    TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseReconcilerConfiguration? terrabasePlacement =
        TerraScale.Orchestrator.ControlPlane.TerraBase.TerraBaseReconcilerConfiguration.Load(
            ResolvedEnvironment("TS_ORCH_TERRABASE_RECONCILER"));
    TerraScale.Orchestrator.Nodes.OciMemberHostFleetConfigurationFile? memberFleet =
        TerraScale.Orchestrator.Nodes.OciMemberHostFleetConfigurationFile.Load(
            ResolvedEnvironment("TS_ORCH_MEMBER_FLEET_FILE"));
    TerraScale.Orchestrator.Nodes.OciWorkloadFleetConfigurationFile? workloadFleet =
        TerraScale.Orchestrator.Nodes.OciWorkloadFleetConfigurationFile.Load(
            ResolvedEnvironment("TS_ORCH_WORKLOAD_FLEET_FILE"));
    if (memberFleet is not null || workloadFleet is not null || options.OciCiRunnerPool is not null)
    {
        var regionIntent = TerraScale.Orchestrator.Bootstrap.OciRegionIntent.Load(
            ResolvedEnvironment("TS_ORCH_REGION_INTENT_FILE"));
        regionIntent.RequireCell(options.Cell);
        if (memberFleet is not null)
        {
            regionIntent.RequireEndpoint(options.Cell, memberFleet.Endpoint);
            if (memberFleet.Templates.Keys.Any(region => region != options.Cell.ToUpperInvariant()))
                throw new InvalidDataException("A member fleet may provision only its own supported regional cell.");
        }
        if (workloadFleet is not null)
        {
            regionIntent.RequireEndpoint(options.Cell, workloadFleet.Endpoint);
            if (workloadFleet.Region != options.Cell.ToUpperInvariant())
                throw new InvalidDataException("A workload fleet may provision only its own supported regional cell.");
        }
        if (options.OciCiRunnerPool is { } runnerPool)
            regionIntent.RequireEndpoint(options.Cell, runnerPool.Endpoint);
    }
    // The production admitted-target allow-list is configuration, never request input; parsing it
    // here means production composition fails closed at startup instead of at first request.
    TerraScale.Orchestrator.Delivery.DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null;
    var admittedDeliveryTargetEntries = ResolvedEnvironment("TS_ORCH_DELIVERY_ADMITTED_TARGETS");
    if (!string.IsNullOrWhiteSpace(admittedDeliveryTargetEntries))
        admittedDeliveryTargets = TerraScale.Orchestrator.Delivery.DirectDeliveryAdmittedTargets.Parse(
            admittedDeliveryTargetEntries.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    var candidateHandoffV2Policies = options.Command is OrchestratorCommand.Run or OrchestratorCommand.Check
        ? CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Load(
            ResolvedEnvironment("TS_ORCH_CANDIDATE_HANDOFF_V2_POLICY_FILE"))
        : CandidateEvidenceHandoffV2AdmissionPolicyCatalog.Empty;
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
    // Distinct signing-key material per CI/delivery role (issue #7): the command identity stays
    // the base command/Native-GitOps identity, while repository-CI job dispatch, artifact
    // attestation/delivery evidence, and native runtime observation each get independently
    // configured — and therefore independently revocable — key material. A role without its own
    // configuration falls back to the shared command identity, which production composition
    // refuses for every role it actually composes (fail closed at startup, never at first use).
    using var ciRoleIdentities = TerraScale.Orchestrator.Delivery.DeliveryRoleIdentityRuntime.Open(
        TerraScale.Orchestrator.Delivery.DeliveryRoleIdentityConfiguration.Resolve(ResolvedEnvironment),
        commandIdentity,
        ProductionRoleComposition.ProductionCiRoles(options, startupPlan));
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
            startupPlan.RegistersDirectDeliveryEndpoint,
            admittedDeliveryTargets,
            ciRoleIdentities?.CiArtifactSignatures ?? commandIdentity?.Verifier,
            candidateHandoffV2Policies,
            autoProvision,
            terrabasePlacement,
            memberFleet,
            workloadFleet,
            hostSessions);
        if (startupPlan.StartsDirectDelivery && runtime.DirectDelivery is null)
            throw new InvalidOperationException("The direct delivery mutation path was not composed with durable regional adapters.");
        var observedRuntime = runtime;
        observedRuntime.AttachServiceTelemetry(telemetry);
        telemetry.ObserveOperatorStatus(() => observedRuntime.LatestOperatorStatus);
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
                globalRuntime = await GlobalControlStartup.StartWithRetryAsync(
                    token => GlobalNatsRuntime.StartAsync(
                        options.GlobalNats,
                        options.Instance,
                        options.Cell,
                        ciRunnerNatsIdentity,
                        token,
                        options.ForgejoSource,
                        options.ForgejoCiSourceGraph,
                        options.Command == OrchestratorCommand.Run ? options.OciCiRunnerPool : null,
                        ciRoleIdentities?.CiJob ?? commandIdentity?.Signer,
                        ciRoleIdentities?.CiArtifact ?? commandIdentity?.Signer,
                        ciRoleIdentities?.CiArtifactSignatures ?? commandIdentity?.Verifier,
                        ciRoleIdentities?.CiRuntimeSignatures ?? commandIdentity?.Verifier,
                        commandIdentity?.Signer,
                        verifier is not null,
                        ciConsumptionEnabled: startupPlan.StartsCiConsumption,
                        admittedDeliveryTargets: admittedDeliveryTargets,
                        candidateHandoffV2Policies: candidateHandoffV2Policies),
                    (attempt, exception) => Console.Error.WriteLine(
                        $"Global control start attempt {attempt} failed ({exception.GetType().Name}); retrying with backoff."),
                    shutdown.Token);
                if (globalRuntime is null)
                    Console.Error.WriteLine(
                        "Global control is unavailable after repeated start attempts; regional control remains active.");
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

            // Evaluated outside the availability swallow above: a started global runtime
            // that lacks durable direct-delivery adapters is a fatal composition bug, not a
            // degraded-control condition — the process must fail instead of continuing with
            // a broken mutation path (the outer handler disposes what started and rethrows).
            if (globalRuntime is not null)
                OrchestratorRuntimeComposition.EnsureGlobalDirectDeliveryComposed(
                    startupPlan.StartsDirectDelivery,
                    globalRuntimeStarted: true,
                    composedDirectDelivery: globalRuntime.DirectDelivery is not null);
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
        // subsystem. Their own health surfaces report failures and recovery — but a
        // FAULTED global or native-GitOps completion must not outlive the process:
        // it is observed here, logged, and fails the process through the same path a
        // regional fault takes, so systemd restarts a fresh candidate instead of
        // leaving a zombie controller holding a dead global control role.
        await RunCompletion.AwaitAsync(
            ownedRuntime.Completion,
            ownedGlobalRuntime?.Completion,
            ownedNativeGitOpsRuntime?.Completion,
            shutdown.Token);
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

/// <summary>
/// The CI/delivery roles this composition actually composes, whose production startup therefore
/// requires independently configured key material. Direct delivery always verifies durable
/// artifact evidence against the CiArtifact PUBLIC trust root — fail closed, but never demand
/// the PRIVATE signing key from a process that only verifies (a member host must not hold CI
/// attestation signing material). Global control additionally verifies native runtime
/// observations (CiRuntime), and the CI signer controller (an OCI runner pool in run mode)
/// additionally signs job dispatch (CiJob) and artifact attestations (CiArtifact signing).
/// </summary>
internal static class ProductionRoleComposition
{
    internal static IReadOnlyCollection<TerraScale.Orchestrator.Delivery.DeliverySigningRole> ProductionCiRoles(
        OrchestratorOptions options,
        TerraScale.Orchestrator.OrchestratorStartupPlan startupPlan)
    {
        if (options.Command is not (OrchestratorCommand.Run or OrchestratorCommand.Check))
            return [];
        var roles = new SortedSet<TerraScale.Orchestrator.Delivery.DeliverySigningRole>
        {
            // Production direct delivery fails closed without the artifact-evidence verifier in
            // both the regional and global adapter sets; that verifier is the CiArtifact trust root.
            TerraScale.Orchestrator.Delivery.DeliverySigningRole.CiArtifactTrust,
        };
        if (options.GlobalNats is not null || startupPlan.StartsCiConsumption)
            roles.Add(TerraScale.Orchestrator.Delivery.DeliverySigningRole.CiRuntime);
        if (options.Command == OrchestratorCommand.Run && options.OciCiRunnerPool is not null)
        {
            // Only this composition ever signs CI evidence: it must carry the role's private key,
            // and its absence fails closed here rather than at first attestation.
            roles.Add(TerraScale.Orchestrator.Delivery.DeliverySigningRole.CiJob);
            roles.Add(TerraScale.Orchestrator.Delivery.DeliverySigningRole.CiArtifact);
        }
        return roles.ToArray();
    }
}

/// <summary>
/// Graceful-shutdown triggers for the run process: SIGINT (<see cref="Console.CancelKeyPress"/>)
/// and SIGTERM — the signal systemd delivers on every unit stop and rollout replacement. Both
/// cancel the shared shutdown token instead of letting the default handler terminate the
/// process, so lease release, service drain, and the ordered disposal chain actually run in
/// production, not only for an interactive Ctrl+C.
/// </summary>
internal sealed class ShutdownSignals : IDisposable
{
    private readonly CancellationTokenSource shutdown;
    private readonly PosixSignalRegistration? sigterm;

    private ShutdownSignals(CancellationTokenSource shutdown)
    {
        this.shutdown = shutdown;
        Console.CancelKeyPress += OnCancelKeyPress;
        sigterm = OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()
            ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, OnPosixSignal)
            : null;
    }

    internal static ShutdownSignals Wire(CancellationTokenSource shutdown) => new(shutdown);

    internal void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs eventArgs)
    {
        // Cancel the default termination so the graceful disposal chain runs.
        eventArgs.Cancel = true;
        Trigger();
    }

    internal void OnPosixSignal(PosixSignalContext context)
    {
        context.Cancel = true;
        Trigger();
    }

    /// <summary>The shared graceful-shutdown trigger behind both signals.</summary>
    internal void Trigger() => shutdown.Cancel();

    public void Dispose()
    {
        Console.CancelKeyPress -= OnCancelKeyPress;
        sigterm?.Dispose();
    }
}

/// <summary>
/// Bounded, observable retry for the global control runtime's start: a boot-time global NATS
/// blip (cell restart, quorum re-election) must not permanently strip global-control duties
/// from an otherwise healthy controller. Attempts back off exponentially; after the bound the
/// composition degrades to regional control and the caller logs the degradation.
/// </summary>
internal static class GlobalControlStartup
{
    internal const int MaxStartAttempts = 5;

    internal static async Task<T?> StartWithRetryAsync<T>(
        Func<CancellationToken, Task<T>> start,
        Action<int, Exception> attemptFailed,
        CancellationToken cancellationToken,
        Func<int, TimeSpan>? backoff = null) where T : class
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(attemptFailed);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await start(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                if (attempt >= MaxStartAttempts)
                    return null;
                attemptFailed(attempt, exception);
                await Task.Delay((backoff ?? Backoff)(attempt), cancellationToken);
            }
        }
    }

    internal static TimeSpan Backoff(int attempt) =>
        TimeSpan.FromMilliseconds(Math.Min(500 * (1 << Math.Min(attempt - 1, 4)), 8_000));
}

/// <summary>
/// Awaits the run-mode lifecycles: the regional completion governs graceful shutdown, while
/// the unobserved WAN/global completions (global authority, native GitOps) are supervised —
/// their faults fail the process instead of zombieing behind healthy regional control.
/// </summary>
internal static class RunCompletion
{
    internal static async Task AwaitAsync(
        Task regionalCompletion,
        Task? globalCompletion,
        Task? nativeGitOpsCompletion,
        CancellationToken cancellationToken)
    {
        var regional = regionalCompletion.WaitAsync(cancellationToken);
        // Flat WhenAny over the regional wait and every fail-stop observer: awaiting the
        // winner propagates its outcome — a nested WhenAny would leave the observer's
        // fault unobserved and the fail-stop would never reach the process exit path.
        var lifecycles = new List<Task> { regional };
        if (globalCompletion is not null)
            lifecycles.Add(FailStopOnFaultedAsync("global authority", globalCompletion, cancellationToken));
        if (nativeGitOpsCompletion is not null)
            lifecycles.Add(FailStopOnFaultedAsync("native GitOps", nativeGitOpsCompletion, cancellationToken));
        if (lifecycles.Count == 1)
        {
            await regional;
            return;
        }
        await await Task.WhenAny(lifecycles);
    }

    /// <summary>
    /// Fail-stop supervision for a completion nothing else awaits: a fault (or an unexpected
    /// clean stop) is logged, then rethrown so the process exits non-zero and systemd restarts
    /// a fresh candidate. Cancellation is the graceful path and stays silent.
    /// </summary>
    internal static async Task FailStopOnFaultedAsync(
        string role,
        Task completion,
        CancellationToken cancellationToken,
        Action<string>? log = null)
    {
        log ??= static message => Console.Error.WriteLine(message);
        try
        {
            await completion.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            log(
                $"{role} runtime failed ({exception.GetType().Name}): {exception.Message}. " +
                "Stopping the process so a restart recovers the role.");
            throw;
        }
        log($"{role} runtime stopped without cancellation; stopping the process.");
        throw new InvalidOperationException($"The {role} runtime terminated without cancellation.");
    }
}
