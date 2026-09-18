namespace TerraScale.Orchestrator.ControlPlane.EdgeRouting;

/// <summary>
/// The bounded operational entry <c>edge-routing-publish</c>: ONE publisher pass composed from
/// explicit arguments — account id, the REGIONS/PLACEMENT namespace titles, an API token file,
/// and an optional JSON edge placement snapshot document (the wire-shaped health document plus a
/// <c>databases</c> map). Production seam: this is a qualification/operational tool, not a
/// reconciler — the orchestrator reconciler owns continuous publication and constructs the
/// placement source from the placement evaluator plus live member observations per ADR 0050 §6.
/// Without <c>--snapshot</c> the source is empty, which the fail-closed snapshot validation
/// rejects: the command never publishes a document ts-proxy would null wholesale.
/// </summary>
internal static class EdgeRoutingPublishCli
{
    public static async Task<int> ExecuteAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken = default)
    {
        var (accountId, regionsTitle, placementTitle, tokenFilePath, snapshotPath) = arguments switch
        {
            ["--account", var account, "--regions-title", var regions, "--placement-title", var placement,
                "--token-file", var token, "--snapshot", var snapshot] =>
                (account, regions, placement, token, (string?)snapshot),
            ["--account", var account, "--regions-title", var regions, "--placement-title", var placement,
                "--token-file", var token] =>
                (account, regions, placement, token, null),
            _ => throw new ArgumentException(
                "edge-routing-publish requires --account <id> --regions-title <title> " +
                "--placement-title <title> --token-file <path> [--snapshot <path>]"),
        };

        var snapshot = snapshotPath is null
            ? new EdgePlacementSnapshot(new EdgeHealthDocument(0, [], []), null)
            : EdgePlacementJson.ReadSnapshot(await File.ReadAllTextAsync(snapshotPath, cancellationToken));
        var apiToken = (await File.ReadAllTextAsync(tokenFilePath, cancellationToken)).Trim();
        using var client = CloudflareKvClient.Create(apiToken, accountId);
        var result = await PublishOnceAsync(client, regionsTitle, placementTitle, snapshot, cancellationToken);
        Console.WriteLine(
            $"edge-routing publish: {result.PlacementWrites} placement write(s), " +
            $"{result.PlacementSkips} skipped, {result.DeletedKeys} deleted in {(long)result.Duration.TotalMilliseconds} ms");
        return 0;
    }

    /// <summary>
    /// The composition the command runs: one publisher pass from an explicit client, namespace
    /// titles, and snapshot. This is the seam the production reconciler replaces — it will
    /// construct the source from the placement evaluator plus member observations (ADR 0050 §6).
    /// </summary>
    internal static Task<EdgePublishResult> PublishOnceAsync(
        CloudflareKvClient client,
        string regionsNamespaceTitle,
        string placementNamespaceTitle,
        EdgePlacementSnapshot snapshot,
        CancellationToken cancellationToken = default) =>
        new EdgeRoutingPublisher(
                client,
                new StaticEdgePlacementSource(snapshot),
                regionsNamespaceTitle,
                placementNamespaceTitle)
            .PublishAsync(cancellationToken);
}
