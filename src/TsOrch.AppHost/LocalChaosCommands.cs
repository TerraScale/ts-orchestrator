namespace TsOrch.AppHost;

internal sealed record class LocalChaosTargets(
    Uri WorkerUrl,
    Uri OciMockUrl,
    string StatefulNodeId,
    string WorkerNodeId,
    string FaultService,
    string RotatedSecret,
    string Region);

internal sealed record class LocalChaosCommand(string Name, string DisplayName, string Description, Func<LocalChaosTargets, ChaosRequestDocument> Request, bool BumpsSecret = false);

internal static class LocalChaosCommandExtensions
{
    private static readonly IReadOnlyList<LocalChaosCommand> Commands =
    [
        new("chaos-kill-worker-node", "Kill worker node", "Disconnects the worker node and marks it down to prove stateless failover.", static targets => new("kill_node", NodeId: targets.WorkerNodeId)),
        new("chaos-inject-5xx", "Inject 5xx spike", "Injects a 50% synthetic 5xx rate on the fault service for 2 minutes to prove canary rollback.", static targets => new("inject_5xx", Service: targets.FaultService, RatePct: 50, DurationSeconds: 120)),
        new("chaos-clear-5xx", "Clear 5xx spike", "Removes the synthetic 5xx rate.", static targets => new("inject_5xx", Service: targets.FaultService, RatePct: 0, DurationSeconds: 1)),
        new("chaos-cpu-load", "Inject CPU load", "Pins synthetic 95% CPU on the worker node for 5 minutes to prove replica and pool scale-up.", static targets => new("cpu_load", NodeId: targets.WorkerNodeId, CpuPct: 95, DurationSeconds: 300)),
        new("chaos-clear-cpu-load", "Drop CPU load", "Removes the synthetic CPU load to prove drain and pool scale-down.", static targets => new("cpu_load", NodeId: targets.WorkerNodeId, CpuPct: 0, DurationSeconds: 1)),
        new("chaos-fill-disk", "Fill data disk", "Reports 90% data volume usage on the stateful node to prove UpdateVolume and grow_volume.", static targets => new("fill_disk", NodeId: targets.StatefulNodeId, UsedPct: 90)),
        new("chaos-clear-disk", "Clear data disk", "Removes the synthetic data volume usage.", static targets => new("fill_disk", NodeId: targets.StatefulNodeId, UsedPct: 0)),
        new("chaos-bump-secret", "Rotate Vault secret", "Bumps the mock OCI Vault secret version and notifies every service that references it.", static targets => new("bump_secret", SecretName: targets.RotatedSecret), BumpsSecret: true),
        new("chaos-atlas-roundtrip", "Atlas round trip", "Publishes a local database placement through AtlasDO and reads it back.", static targets => new("atlas_roundtrip", Project: "aspire-local", Database: "maindb", Region: targets.Region)),
    ];

    extension(IResourceBuilder<ExecutableResource> worker)
    {
        public IResourceBuilder<ExecutableResource> WithLocalChaosCommands(LocalChaosTargets targets)
        {
            ArgumentNullException.ThrowIfNull(targets);
            var builder = worker;
            foreach (var command in Commands)
            {
                builder = builder.WithCommand(
                    command.Name,
                    command.DisplayName,
                    context => RunAsync(command, targets, context.CancellationToken),
                    new CommandOptions { Description = command.Description, IconName = "Flash" });
            }

            return builder;
        }
    }

    private static async Task<ExecuteCommandResult> RunAsync(LocalChaosCommand command, LocalChaosTargets targets, CancellationToken cancellationToken)
    {
        using var httpClient = LocalDevClient.CreateHttpClient();
        var client = new LocalDevClient(httpClient, TimeProvider.System);
        if (!command.BumpsSecret)
        {
            return await SendChaosAsync(client, command, targets, cancellationToken);
        }

        var bumped = await client.PostAsync(new Uri(targets.OciMockUrl, $"/_mock/secrets/{Uri.EscapeDataString(targets.RotatedSecret)}/bump"), "{}", null, cancellationToken);
        return bumped switch
        {
            string => await SendChaosAsync(client, command, targets, cancellationToken),
            LocalWorkerRequestRejected rejected => CommandResults.Failure(rejected.Message),
            LocalWorkerAccessDenied denied => CommandResults.Failure(denied.Message),
            LocalWorkerUnavailable unavailable => CommandResults.Failure(unavailable.Message),
        };
    }

    private static async Task<ExecuteCommandResult> SendChaosAsync(LocalDevClient client, LocalChaosCommand command, LocalChaosTargets targets, CancellationToken cancellationToken)
    {
        var login = await client.DevLoginAsync(targets.WorkerUrl, cancellationToken);
        return login switch
        {
            string cookie => await PostChaosAsync(client, command.Request(targets), targets.WorkerUrl, cookie, cancellationToken),
            LocalDevNotEnabled notLocal => CommandResults.Failure(notLocal.Message),
            LocalWorkerUnavailable unavailable => CommandResults.Failure(unavailable.Message),
        };
    }

    private static async Task<ExecuteCommandResult> PostChaosAsync(
        LocalDevClient client,
        ChaosRequestDocument request,
        Uri workerUrl,
        string cookie,
        CancellationToken cancellationToken)
    {
        var reply = await client.PostJsonAsync(new Uri(workerUrl, "/api/dev/chaos"), request, AppHostJsonContext.Default.ChaosRequestDocument, cookie, cancellationToken);
        return reply switch
        {
            string body => CommandResults.Success(body),
            LocalWorkerRequestRejected rejected => CommandResults.Failure(rejected.Message),
            LocalWorkerAccessDenied denied => CommandResults.Failure(denied.Message),
            LocalWorkerUnavailable unavailable => CommandResults.Failure(unavailable.Message),
        };
    }
}
