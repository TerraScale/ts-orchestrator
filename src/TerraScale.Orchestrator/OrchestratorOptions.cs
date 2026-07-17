namespace TerraScale.Orchestrator;

public enum OrchestratorCommand
{
    Run,
    Check,
    Lab,
    Catalog
}

public enum OrchestratorLabCommand
{
    Plan,
    Up,
    Status
}

public enum OrchestratorLabProfile
{
    DevContainers,
    DevContainersControl
}

public sealed record OrchestratorOptions(
    OrchestratorCommand Command,
    string Cell,
    string NatsUrl,
    int Replicas,
    OrchestratorLabCommand? LabCommand = null,
    string? WorkspaceRoot = null,
    string? DataDirectory = null,
    string? StateFile = null,
    string? EndpointsFile = null,
    string? EvidenceFile = null,
    string Instance = "local",
    OrchestratorLabProfile LabProfile = OrchestratorLabProfile.DevContainers,
    string? NatsNKeyFile = null,
    Messaging.NatsTlsFiles? NatsTls = null,
    Messaging.GlobalNatsConfiguration? GlobalNats = null,
    Delivery.ForgejoWebhookConfiguration? ForgejoWebhook = null,
    Delivery.ForgejoSourceConfiguration? ForgejoSource = null,
    Delivery.CommandIdentityConfiguration? CommandIdentity = null,
    Messaging.CiRunnerNatsIdentityConfiguration? CiRunnerNatsIdentity = null,
    ControlPlane.Providers.OciCiRunnerPoolConfiguration? OciCiRunnerPool = null)
{
    public static OrchestratorOptions Parse(
        IReadOnlyList<string> args,
        Func<string, string?> environment)
    {
        var command = (args.Count == 0 ? null : args[0]) switch
        {
            null or "run" => OrchestratorCommand.Run,
            "check" => OrchestratorCommand.Check,
            "lab" => OrchestratorCommand.Lab,
            "catalog" => OrchestratorCommand.Catalog,
            var value => throw new ArgumentException($"Unknown command '{value}'. Use 'run', 'check', 'catalog', or 'lab'.")
        };

        var cell = environment("TS_ORCH_CELL") ?? "local";
        var url = environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222";
        var replicasText = environment("TS_ORCH_REPLICAS") ?? "1";
        var instance = environment("TS_ORCH_INSTANCE") ?? "local";
        var natsNKeyFile = environment("TS_ORCH_NATS_NKEY_FILE");
        var natsTls = Messaging.NatsTlsFiles.Resolve(
            environment("TS_ORCH_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_NATS_TLS_KEY_FILE"),
            "TS_ORCH_NATS_TLS");

        if (!IsSubjectToken(cell))
        {
            throw new ArgumentException("TS_ORCH_CELL must contain only lowercase letters, digits, or hyphens.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not "nats" and not "tls")
        {
            throw new ArgumentException("TS_ORCH_NATS_URL must be an absolute nats:// or tls:// URL.");
        }

        if (!int.TryParse(replicasText, out var replicas) || replicas is < 1 or > 5 || replicas % 2 == 0)
        {
            throw new ArgumentException("TS_ORCH_REPLICAS must be 1, 3, or 5.");
        }

        if (!IsSubjectToken(instance))
        {
            throw new ArgumentException("TS_ORCH_INSTANCE must contain only lowercase letters, digits, or hyphens.");
        }
        natsNKeyFile = Messaging.NatsCredentialFile.Resolve(
            natsNKeyFile,
            "TS_ORCH_NATS_NKEY_FILE");
        var globalNats = command is OrchestratorCommand.Run or OrchestratorCommand.Check
            ? Messaging.GlobalNatsConfiguration.Resolve(
                environment("TS_ORCH_GLOBAL_NATS_URL"),
                environment("TS_ORCH_GLOBAL_NATS_NKEY_FILE"),
                environment("TS_ORCH_GLOBAL_NATS_TLS_CA_FILE"),
                environment("TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE"),
                environment("TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE"),
                replicas)
            : null;
        if (globalNats is not null &&
            (natsNKeyFile is null || natsTls is null ||
                Messaging.NatsCredentialFile.SameIdentity(globalNats.NKeyFile, natsNKeyFile) ||
                globalNats.Tls.SameIdentity(natsTls)))
            throw new ArgumentException("Global and regional control NATS require distinct complete identities.");

        if (command is not OrchestratorCommand.Lab)
        {
            if (args.Count > 1)
            {
                throw new ArgumentException($"The {args[0]} command does not accept arguments.");
            }
            var forgejoWebhook = command is OrchestratorCommand.Run or OrchestratorCommand.Check
                ? Delivery.ForgejoWebhookConfiguration.Resolve(
                    environment("TS_ORCH_FORGEJO_LISTEN_PREFIX"),
                    environment("TS_ORCH_FORGEJO_REPOSITORY"),
                    environment("TS_ORCH_FORGEJO_SECRET_FILE"))
                : null;
            var forgejoSource = command is OrchestratorCommand.Run or OrchestratorCommand.Check
                ? Delivery.ForgejoSourceConfiguration.Resolve(
                    environment("TS_ORCH_FORGEJO_API_URL"),
                    environment("TS_ORCH_FORGEJO_REPOSITORY"),
                    environment("TS_ORCH_FORGEJO_API_TOKEN_FILE"))
                : null;
            var commandIdentity = command is OrchestratorCommand.Run or OrchestratorCommand.Check
                ? Delivery.CommandIdentityConfiguration.Resolve(
                    environment("TS_ORCH_COMMAND_SIGNING_KEY_FILE"),
                    environment("TS_ORCH_COMMAND_TRUST_KEY_FILES"))
                : null;
            var ciRunnerNatsIdentity = command is OrchestratorCommand.Run or OrchestratorCommand.Check
                ? Messaging.CiRunnerNatsIdentityConfiguration.Resolve(
                    environment("TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE"),
                    environment("TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY"))
                : null;
            var ociCiRunnerPool = command is OrchestratorCommand.Run or OrchestratorCommand.Check
                ? ControlPlane.Providers.OciCiRunnerPoolConfiguration.Load(
                    environment("TS_ORCH_CI_OCI_CONFIG"))
                : null;
            if ((forgejoWebhook is not null || forgejoSource is not null) && globalNats is null)
                throw new ArgumentException("Forgejo ingestion requires configured global control authority.");
            if (ciRunnerNatsIdentity is not null && globalNats is null)
                throw new ArgumentException("CI runner NATS identity issuance requires configured global control authority.");
            if (ociCiRunnerPool is not null &&
                (globalNats is null || forgejoSource is null || commandIdentity?.SigningKeyFile is null))
                throw new ArgumentException(
                    "OCI CI requires global control authority, Forgejo source access, and a command signer.");
            return new(
                command,
                cell,
                uri.ToString(),
                replicas,
                Instance: instance,
                NatsNKeyFile: natsNKeyFile,
                NatsTls: natsTls,
                GlobalNats: globalNats,
                ForgejoWebhook: forgejoWebhook,
                ForgejoSource: forgejoSource,
                CommandIdentity: commandIdentity,
                CiRunnerNatsIdentity: ciRunnerNatsIdentity,
                OciCiRunnerPool: ociCiRunnerPool);
        }

        return ParseLab(args.Skip(1).ToArray(), environment, cell, uri.ToString(), replicas, instance);
    }

    private static OrchestratorOptions ParseLab(
        IReadOnlyList<string> args,
        Func<string, string?> environment,
        string cell,
        string natsUrl,
        int replicas,
        string instance)
    {
        var labCommand = (args.Count == 0 ? null : args[0]) switch
        {
            null or "plan" => OrchestratorLabCommand.Plan,
            "up" => OrchestratorLabCommand.Up,
            "status" => OrchestratorLabCommand.Status,
            var value => throw new ArgumentException($"Unknown lab command '{value}'. Use 'plan', 'up', or 'status'.")
        };

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = args.Count > 0 ? 1 : 0; index < args.Count; index++)
        {
            var argument = args[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Count)
            {
                throw new ArgumentException($"Invalid lab argument '{argument}'.");
            }

            if (!values.TryAdd(argument, args[++index]))
            {
                throw new ArgumentException($"Duplicate lab argument '{argument}'.");
            }
        }

        var workspaceRoot = Path.GetFullPath(GetValue(
            values,
            "--workspace",
            environment("TERRASCALE_WORKSPACE_ROOT") ?? Directory.GetCurrentDirectory()));
        var dataDirectory = Path.GetFullPath(GetValue(
            values,
            "--data-directory",
            environment("TS_ORCH_LAB_DATA") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "terrascale-orchestrator",
                "devhost")));
        var stateFile = Path.GetFullPath(GetValue(
            values,
            "--state-file",
            Path.Combine(dataDirectory, "state.json")));
        var endpointsFile = Path.GetFullPath(GetValue(
            values,
            "--endpoints-file",
            Path.Combine(dataDirectory, "endpoints.json")));
        values.TryGetValue("--evidence", out var evidenceFile);

        var labProfile = GetValue(values, "--profile", environment("TS_ORCH_LAB_PROFILE") ?? "dev-containers") switch
        {
            "dev-containers" => OrchestratorLabProfile.DevContainers,
            "dev-containers-control" => OrchestratorLabProfile.DevContainersControl,
            _ => throw new ArgumentException(
                "Lab profile must be 'dev-containers' or 'dev-containers-control'.")
        };

        var unknown = values.Keys.Except(
            ["--workspace", "--data-directory", "--state-file", "--endpoints-file", "--evidence", "--profile"],
            StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null)
        {
            throw new ArgumentException($"Unknown lab option '{unknown}'.");
        }

        return new(
            OrchestratorCommand.Lab,
            cell,
            natsUrl,
            replicas,
            labCommand,
            workspaceRoot,
            dataDirectory,
            stateFile,
            endpointsFile,
            evidenceFile is null ? null : Path.GetFullPath(evidenceFile),
            instance,
            labProfile);
    }

    private static string GetValue(
        IReadOnlyDictionary<string, string> values,
        string key,
        string fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;

    private static bool IsSubjectToken(string value) =>
        value.Length is > 0 and <= 32 &&
        value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
