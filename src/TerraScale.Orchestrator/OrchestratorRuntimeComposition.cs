using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator;

/// <summary>
/// Pure startup selection. The composition root turns this plan into runtime
/// adapters after option parsing, so role isolation can be checked without a
/// NATS connection.
/// </summary>
internal sealed record OrchestratorStartupPlan(
    bool StartsRegionalControl,
    bool StartsDirectory,
    bool StartsDirectoryService,
    bool StartsGlobalAuthority,
    bool StartsGlobalDelivery,
    bool AllowsGlobalMutation,
    bool StartsDirectDelivery,
    /// <summary>Only Run mode consumes CI events: Check must never touch delivery state.</summary>
    bool StartsCiConsumption,
    /// <summary>Only Run mode serves the direct-delivery mutation endpoint.</summary>
    bool RegistersDirectDeliveryEndpoint);

internal static class OrchestratorRuntimeComposition
{
    internal static OrchestratorStartupPlan Plan(OrchestratorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var isRunMode = options.Command == OrchestratorCommand.Run;
        return Describe(
            options.Cell,
            options.GlobalDirectoryNats is not null,
            options.GlobalDirectoryServiceNats is not null,
            options.GlobalNats is not null,
            options.ForgejoWebhook is not null || options.ForgejoSource is not null,
            // The pool is the executor: a runner-NATS identity alone can issue credentials but
            // cannot execute pipelines, so identity-without-pool must not satisfy hasCi.
            options.OciCiRunnerPool is not null,
            isRunMode &&
                options.GlobalNats is not null &&
                options.CommandIdentity?.TrustKeyFiles.Count > 0,
            options.Command is OrchestratorCommand.Run or OrchestratorCommand.Check,
            StartsCiConsumption: isRunMode,
            RegistersDirectDeliveryEndpoint: isRunMode);
    }

    internal static OrchestratorStartupPlan Describe(
        string cell,
        bool hasDirectory,
        bool hasDirectoryService,
        bool hasAuthority,
        bool hasForgejo,
        bool hasCi,
        bool hasNativeGitOps,
        bool hasDirectDelivery = true,
        bool StartsCiConsumption = true,
        bool RegistersDirectDeliveryEndpoint = true)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The startup composition cell is invalid.", nameof(cell));
        if (hasAuthority && cell != "gru")
            throw new ArgumentException("Global authority is GRU-only.", nameof(cell));
        if (hasDirectoryService && cell != "gru")
            throw new ArgumentException("The global directory service is GRU-only.", nameof(cell));
        if (hasDirectoryService && !hasDirectory)
            throw new ArgumentException("The global directory service requires the directory publisher/watch runtime.");
        if (!hasAuthority && (hasForgejo || hasCi || hasNativeGitOps))
            throw new ArgumentException(
                "Forgejo, CI, and native GitOps require the GRU global authority runtime.");
        // Fail closed before startup: a Forgejo-ingesting global runtime without an executor can
        // only journal-and-drop work, so it must never come up (ack-without-process guard). The
        // executor is the OCI CI runner POOL; a runner-NATS identity alone does not execute work.
        if (hasAuthority && hasForgejo && !hasCi)
            throw new ArgumentException(
                "Forgejo CI ingestion requires the OCI CI runner pool (TS_ORCH_CI_OCI_CONFIG) plus its command identity; " +
                "a CI runner NATS identity alone cannot execute pipelines.");

        var startsDelivery = hasAuthority && (hasForgejo || hasCi || hasNativeGitOps);
        return new(
            StartsRegionalControl: true,
            StartsDirectory: hasDirectory,
            StartsDirectoryService: hasDirectoryService,
            StartsGlobalAuthority: hasAuthority,
            StartsGlobalDelivery: startsDelivery,
            AllowsGlobalMutation: hasAuthority,
            StartsDirectDelivery: hasDirectDelivery,
            StartsCiConsumption: StartsCiConsumption,
            RegistersDirectDeliveryEndpoint: RegistersDirectDeliveryEndpoint);
    }

    /// <summary>
    /// Fail-closed composition invariant, evaluated AFTER the global runtime's
    /// availability swallow: when the global authority runtime actually started in a
    /// composition that serves direct delivery, its durable global adapters must have
    /// been composed — a missing adapter is a composition bug and must fail the process,
    /// never degrade to a warning. A runtime that never started (global control
    /// unavailable) legitimately degrades to regional control and must not be mistaken
    /// for a mis-composed one.
    /// </summary>
    internal static void EnsureGlobalDirectDeliveryComposed(
        bool startsDirectDelivery,
        bool globalRuntimeStarted,
        bool composedDirectDelivery)
    {
        if (startsDirectDelivery && globalRuntimeStarted && !composedDirectDelivery)
            throw new InvalidOperationException(
                "The global direct delivery mutation path was not composed with durable adapters.");
    }
}

