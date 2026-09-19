using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Operations;

public static class OperatorCli
{
    private static readonly JsonSerializerOptions OutputOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<int> ExecuteAsync(
        IReadOnlyList<string> arguments,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        if (arguments.Count == 0 ||
            arguments[0] is not ("status" or "members" or "deploy" or "artifact-push" or "evidence-record" or
                "placement-apply"))
        {
            throw new ArgumentException(
                "operator requires 'status', 'members', 'deploy', 'artifact-push', 'evidence-record', or 'placement-apply'.");
        }
        var command = arguments[0];
        var values = ParseValues(arguments.Skip(1).ToArray());
        var cell = Value(values, "--cell", environment("TS_ORCH_CELL") ?? "local");
        var url = Value(values, "--nats-url", environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222");
        var nkeyFile = ValueOrNull(
            values,
            "--nkey-file",
            environment("TS_ORCH_NATS_NKEY_FILE"));
        nkeyFile = NatsCredentialFile.Resolve(nkeyFile, "operator --nkey-file");
        var tls = NatsTlsFiles.Resolve(
            ValueOrNull(values, "--tls-ca-file", environment("TS_ORCH_NATS_TLS_CA_FILE")),
            ValueOrNull(values, "--tls-cert-file", environment("TS_ORCH_NATS_TLS_CERT_FILE")),
            ValueOrNull(values, "--tls-key-file", environment("TS_ORCH_NATS_TLS_KEY_FILE")),
            "operator TLS");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "tls" ||
            nkeyFile is null || tls is null)
        {
            throw new ArgumentException(
                $"operator {command} requires a tls:// NATS URL, a private NKey seed, and complete mTLS credentials.");
        }
        _ = OrchestratorOptions.Parse(
            ["check"],
            key => key switch
            {
                "TS_ORCH_CELL" => cell,
                "TS_ORCH_NATS_URL" => url,
                "TS_ORCH_REPLICAS" => "1",
                "TS_ORCH_NATS_NKEY_FILE" => nkeyFile,
                "TS_ORCH_NATS_TLS_CA_FILE" => tls.CaFile,
                "TS_ORCH_NATS_TLS_CERT_FILE" => tls.CertificateFile,
                "TS_ORCH_NATS_TLS_KEY_FILE" => tls.KeyFile,
                _ => null
            });

        var clientOptions = new NatsOpts
        {
            Url = url,
            RetryOnInitialConnect = false,
            RequestTimeout = command is "deploy" ? TimeSpan.FromSeconds(30) : TimeSpan.FromSeconds(10)
        };
        if (nkeyFile is not null)
        {
            clientOptions = clientOptions with
            {
                AuthOpts = new NatsAuthOpts { NKeyFile = nkeyFile }
            };
        }
        if (tls is not null)
        {
            clientOptions = clientOptions with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = tls.CaFile,
                    CertFile = tls.CertificateFile,
                    KeyFile = tls.KeyFile
                }
            };
        }
        await using var client = new NatsClient(clientOptions);
        await client.ConnectAsync();
        var topology = new NatsTopology(cell, 1);
        if (command is "status" or "members")
        {
            var response = await client.RequestAsync<string, string>(
                command == "status" ? topology.StatusSubject : topology.MembersSubject,
                command,
                cancellationToken: cancellationToken);
            if (command == "status")
            {
                var status = JsonSerializer.Deserialize(
                    response.Data ?? throw new InvalidOperationException("The regional controller returned no status."),
                    RegionalControllerStatusJsonContext.Default.RegionalControllerStatus)
                    ?? throw new InvalidOperationException("The regional controller returned no status.");
                status.Validate(cell);
                Console.WriteLine(JsonSerializer.Serialize(status, OutputOptions));
            }
            else
            {
                var members = JsonSerializer.Deserialize(
                    response.Data ?? throw new InvalidOperationException("The regional controller returned no membership view."),
                    RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMembershipSnapshot)
                    ?? throw new InvalidOperationException("The regional controller returned no membership view.");
                members.Validate(cell);
                Console.WriteLine(JsonSerializer.Serialize(members, OutputOptions));
            }
            return 0;
        }
        if (command == "artifact-push")
        {
            await PushArtifactAsync(client, topology, values, cancellationToken);
            return 0;
        }
        if (command == "evidence-record")
        {
            await RecordEvidenceAsync(client, topology, values, cancellationToken);
            return 0;
        }
        if (command == "placement-apply")
        {
            await ApplyPlacementIntentAsync(client, topology, values, cancellationToken);
            return 0;
        }
        await DeployAsync(client, topology, cell, values, environment, cancellationToken);
        return 0;
    }

    /// <summary>
    /// Writes one database's member-lifecycle intent: the active Region set (a subset of
    /// <c>GRU</c>/<c>SFO</c>/<c>FRA</c>, no duplicates) and a revision that must strictly
    /// advance the stored one. The write is compare-and-set — a racing operator loses
    /// cleanly instead of overwriting.
    /// </summary>
    private static async Task ApplyPlacementIntentAsync(
        NatsClient client,
        NatsTopology topology,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        var intent = new TerraScale.Orchestrator.ControlPlane.TerraBase.PlacementIntentDocument(
            TerraScale.Orchestrator.ControlPlane.TerraBase.PlacementIntentDocument.CurrentSchemaVersion,
            Required(values, "--database", "placement-apply --database"),
            Required(values, "--regions", "placement-apply --regions")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            Required(values, "--partition", "placement-apply --partition"),
            long.Parse(Required(values, "--revision", "placement-apply --revision"), CultureInfo.InvariantCulture));
        intent.ValidateAdmission();
        var keyValue = client.CreateJetStreamContext().CreateKeyValueStoreContext();
        var delivery = await keyValue.GetStoreAsync(topology.Delivery.Bucket, cancellationToken);
        var disposition = await TerraScale.Orchestrator.ControlPlane.TerraBase.PlacementIntentStore.ApplyAsync(
            delivery, intent, cancellationToken);
        Console.WriteLine(disposition);
    }

    /// <summary>
    /// Publishes one artifact into the regional digest-addressed object store. The object name
    /// is the artifact's own SHA-256, so identical bytes are a natural no-op and a name can
    /// never change meaning (only a SHA-256 collision could, which the content check on every
    /// host install would still catch).
    /// </summary>
    private static async Task PushArtifactAsync(
        NatsClient client,
        NatsTopology topology,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        var file = Required(values, "--file", "artifact-push --file");
        await using var stream = File.OpenRead(file);
        var hex = await Sha256HexAsync(stream, cancellationToken);
        var objects = client.CreateJetStreamContext().CreateObjectStoreContext();
        var store = await objects.GetObjectStoreAsync(topology.Artifacts.Bucket, cancellationToken);
        stream.Position = 0;
        await store.PutAsync($"sha256-{hex}", stream, leaveOpen: true, cancellationToken);
        Console.WriteLine($"sha256:{hex}");
    }

    /// <summary>
    /// Records the durable signed artifact-evidence binding on a cell, so `operator deploy`
    /// passes production provenance on day one — before the global CI chain exists. The key
    /// file is the CI-artifact role's private key; the controller must carry its public half
    /// in the same trust set production provenance verifies against.
    /// </summary>
    private static async Task RecordEvidenceAsync(
        NatsClient client,
        NatsTopology topology,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        var keyFile = Required(values, "--key-file", "evidence-record --key-file");
        using var signer = EcdsaCommandSigner.LoadPrivatePem(keyFile);
        var evidence = new TerraScale.Orchestrator.Delivery.DirectDeliveryArtifactEvidence(
            Required(values, "--source-repository", "evidence-record --source-repository"),
            Required(values, "--source-commit", "evidence-record --source-commit"),
            Required(values, "--source-tree-digest", "evidence-record --source-tree-digest"),
            Required(values, "--digest", "evidence-record --digest"),
            Required(values, "--manifest-digest", "evidence-record --manifest-digest"),
            Value(values, "--kind", "service"));
        var keyValue = client.CreateJetStreamContext().CreateKeyValueStoreContext();
        var ledger = new TerraScale.Orchestrator.Delivery.NatsForgejoDeliveryLedger(
            await keyValue.GetStoreAsync(topology.Delivery.Bucket, cancellationToken));
        var disposition = await new TerraScale.Orchestrator.Delivery.DirectDeliveryArtifactEvidenceJournal(ledger)
            .RecordAsync(evidence, signer, cancellationToken);
        Console.WriteLine(disposition.ToString().ToLowerInvariant());
    }

    /// <summary>
    /// One-command deploy: builds the canonical handoff manifest, signs it with the operator's
    /// P-256 key, and submits it to the regional signed direct-delivery endpoint. The
    /// controller injects its own live authority into the mapped request, so the operator never
    /// races the lease; retries with the same operation id replay the durable record.
    /// </summary>
    private static async Task DeployAsync(
        NatsClient client,
        NatsTopology topology,
        string cell,
        IReadOnlyDictionary<string, string> values,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        var keyFile = Required(values, "--key-file", "deploy --key-file");
        using var signer = EcdsaCommandSigner.LoadPrivatePem(keyFile);
        var manifest = ComposeManifest(values, environment);
        var payload = Encoding.UTF8.GetBytes(DeployHandoffMapper.SerializeManifest(manifest));
        var issuedAt = DateTimeOffset.UtcNow;
        var headers = DirectDeliveryCommandWire.EncodeSignedHeaders(
            payload,
            manifest.OperationId!,
            generation: 1,
            epoch: 1,
            attempt: 1,
            cell,
            issuedAt,
            issuedAt.AddMinutes(5),
            signer.Sign);
        var requestHeaders = new NatsHeaders();
        foreach (var (name, value) in headers)
            requestHeaders.Add(name, value);
        var response = await client.RequestAsync<byte[], string>(
            topology.DirectDeliverySubject,
            payload,
            requestHeaders,
            cancellationToken: cancellationToken);
        Console.WriteLine(response.Data ?? string.Empty);
    }

    /// <summary>
    /// Builds the canonical handoff manifest from the closed deploy flag set. Pure, so the
    /// operator's exact encoding can be drift-tested against the controller's decoder.
    /// </summary>
    internal static DeployHandoffManifest ComposeManifest(
        IReadOnlyDictionary<string, string> values,
        Func<string, string?> environment)
    {
        var service = Required(values, "--service", "deploy --service");
        var digest = Required(values, "--digest", "deploy --digest");
        var manifestDigest = Required(values, "--manifest-digest", "deploy --manifest-digest");
        var regions = Required(values, "--regions", "deploy --regions")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var manifest = new DeployHandoffManifest(
            SchemaVersion: 1,
            OperationId: Value(
                values,
                "--operation-id",
                $"deploy-{service}-{TerraScale.Orchestrator.ControlPlane.Delivery.HostConvergenceRuntime.HexOf(digest)[..12]}"),
            Source: new DeployHandoffSource(
                Required(values, "--source-repository", "deploy --source-repository"),
                Required(values, "--source-commit", "deploy --source-commit"),
                Required(values, "--source-tree-digest", "deploy --source-tree-digest")),
            Artifact: new DeployHandoffArtifact(
                digest,
                manifestDigest,
                Value(values, "--kind", "service"),
                Value(values, "--architecture", "linux/arm64")),
            Rollback: ValueOrNull(values, "--rollback-digest", null) is { } rollbackDigest
                ? new DeployHandoffRollback(
                    rollbackDigest,
                    Required(values, "--rollback-manifest-digest", "deploy --rollback-manifest-digest"),
                    Value(values, "--kind", "service"),
                    Value(values, "--architecture", "linux/arm64"))
                : null,
            Target: new DeployHandoffTarget(
                service,
                Value(values, "--environment", environment("TS_ORCH_HOST_ENVIRONMENT") ?? "production"),
                regions),
            ConfigurationRevision: Value(
                values,
                "--configuration-revision",
                // Without an admitted configuration pipeline the manifest digest is the
                // closest honest identity for "the configuration this artifact ships with".
                manifestDigest),
            MigrationRevision: ValueOrNull(values, "--migration-revision", null),
            RequestedBy: Value(values, "--requested-by", Environment.UserName ?? "operator"),
            Reason: Required(values, "--reason", "deploy --reason"),
            Informational: null);
        return manifest;
    }

    internal static IReadOnlyDictionary<string, string> ParseValues(IReadOnlyList<string> arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Count; index += 2)
        {
            if (index + 1 >= arguments.Count ||
                arguments[index] is not ("--cell" or "--nats-url" or "--nkey-file" or
                    "--tls-ca-file" or "--tls-cert-file" or "--tls-key-file" or
                    "--key-file" or "--file" or "--service" or "--digest" or
                    "--manifest-digest" or "--kind" or "--architecture" or
                    "--environment" or "--regions" or "--operation-id" or
                    "--source-repository" or "--source-commit" or "--source-tree-digest" or
                    "--rollback-digest" or "--rollback-manifest-digest" or
                    "--configuration-revision" or "--migration-revision" or
                    "--requested-by" or "--reason" or "--database" or "--partition" or
                    "--revision") ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
            {
                throw new ArgumentException(
                    "operator commands accept the documented closed flag set only; " +
                    "every flag takes exactly one value.");
            }
        }
        return values;
    }

    private static string Required(IReadOnlyDictionary<string, string> values, string key, string name)
    {
        if (!values.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new ArgumentException($"{name} is required.");
        return value;
    }

    private static async Task<string> Sha256HexAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var hashed = SHA256.Create();
        var buffer = new byte[1024 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
            hashed.TransformBlock(buffer, 0, read, null, 0);
        hashed.TransformFinalBlock([], 0, 0);
        return Convert.ToHexStringLower(hashed.Hash ?? []);
    }

    private static string Value(IReadOnlyDictionary<string, string> values, string key, string fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;

    private static string? ValueOrNull(
        IReadOnlyDictionary<string, string> values,
        string key,
        string? fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : string.IsNullOrWhiteSpace(fallback) ? null : fallback;
}
