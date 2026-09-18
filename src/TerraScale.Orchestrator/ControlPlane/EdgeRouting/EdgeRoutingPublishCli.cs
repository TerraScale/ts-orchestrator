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
        var (accountId, regionsTitle, placementTitle, tokenFilePath, snapshotFile) = arguments switch
        {
            ["--account", var account, "--regions-title", var regions, "--placement-title", var placement,
                "--token-file", var token, "--snapshot", var snapshotPath] =>
                (account, regions, placement, token, (string?)snapshotPath),
            ["--account", var account, "--regions-title", var regions, "--placement-title", var placement,
                "--token-file", var token] =>
                (account, regions, placement, token, null),
            _ => throw new ArgumentException(
                "edge-routing-publish requires --account <id> --regions-title <title> " +
                "--placement-title <title> --token-file <path> [--snapshot <path>]"),
        };

        var snapshot = snapshotFile is null
            ? new EdgePlacementSnapshot(new EdgeHealthDocument(0, [], []), null)
            : EdgePlacementJson.ReadSnapshot(await File.ReadAllTextAsync(snapshotFile, cancellationToken));
        var apiToken = await ReadApiTokenAsync(tokenFilePath, cancellationToken);
        using var client = CloudflareKvClient.Create(apiToken, accountId);
        var result = await PublishOnceAsync(client, regionsTitle, placementTitle, snapshot, cancellationToken);
        Console.WriteLine(
            $"edge-routing publish: {result.PlacementWrites} placement write(s), " +
            $"{result.PlacementSkips} skipped, {result.DeletedKeys} deleted in {(long)result.Duration.TotalMilliseconds} ms");
        return 0;
    }

    /// <summary>
    /// Reads the Cloudflare API token from an owner-private file, mirroring every sibling
    /// credential path (NatsCredentialFile, EcdsaCommandIdentity): a group- or other-readable
    /// token file is rejected before its contents are ever read.
    /// </summary>
    private static async Task<string> ReadApiTokenAsync(string path, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The Cloudflare API token file requires Linux file permissions.");
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException($"The Cloudflare API token file must be private to the current user: {path}.");
        return (await File.ReadAllTextAsync(path, cancellationToken)).Trim();
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
