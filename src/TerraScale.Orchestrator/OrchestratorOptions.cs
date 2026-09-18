namespace TerraScale.Orchestrator;

public enum OrchestratorCommand
{
    Run,
    Check,
    Catalog,
    ProvisionJournal,
    JournalWriter
}

public sealed record OrchestratorOptions(
    OrchestratorCommand Command,
    string Cell,
    string NatsUrl,
    int Replicas,
    string Instance = "local",
    string? NatsNKeyFile = null,
    Messaging.NatsTlsFiles? NatsTls = null,
    Messaging.GlobalNatsConfiguration? GlobalNats = null,
    Messaging.GlobalDirectoryNatsConfiguration? GlobalDirectoryNats = null,
    Messaging.GlobalDirectoryServiceNatsConfiguration? GlobalDirectoryServiceNats = null,
    Delivery.ForgejoWebhookConfiguration? ForgejoWebhook = null,
    Delivery.ForgejoSourceConfiguration? ForgejoSource = null,
    Delivery.ForgejoRepositoryCiSourceGraphConfiguration? ForgejoCiSourceGraph = null,
    Delivery.CommandIdentityConfiguration? CommandIdentity = null,
    Messaging.CiRunnerNatsIdentityConfiguration? CiRunnerNatsIdentity = null,
    ControlPlane.Providers.OciCiRunnerPoolConfiguration? OciCiRunnerPool = null,
    string? InfrastructureNatsNKeyFile = null,
    Messaging.NatsTlsFiles? InfrastructureNatsTls = null,
    Messaging.NatsAuthoritativeJournalConfiguration? AuthoritativeJournal = null)
{
    public static OrchestratorOptions Parse(
        IReadOnlyList<string> args,
        Func<string, string?> environment)
    {
        var command = (args.Count == 0 ? null : args[0]) switch
        {
            null or "run" => OrchestratorCommand.Run,
            "check" => OrchestratorCommand.Check,
            "catalog" => OrchestratorCommand.Catalog,
            "provision-journal" => OrchestratorCommand.ProvisionJournal,
            "journal-writer" => OrchestratorCommand.JournalWriter,
            var value => throw new ArgumentException($"Unknown command '{value}'. Use 'run', 'check', 'catalog', 'provision-journal', or 'journal-writer'.")
        };

        var cell = environment("TS_ORCH_CELL") ?? "local";
        var url = environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222";
        var replicasText = environment("TS_ORCH_REPLICAS");
        var instance = environment("TS_ORCH_INSTANCE") ?? "local";
        var globalUrl = environment("TS_ORCH_GLOBAL_NATS_URL");
        var globalDirectoryUrl = environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL");
        var globalDirectoryServiceUrl = environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL");
        var controllerNkey = environment("TS_ORCH_NATS_NKEY_FILE");
        var controllerTlsValues = new[]
        {
            environment("TS_ORCH_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_NATS_TLS_KEY_FILE")
        };
        var globalNkey = environment("TS_ORCH_GLOBAL_NATS_NKEY_FILE");
        var globalCredentials = environment("TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE");
        var globalTlsValues = new[]
        {
            environment("TS_ORCH_GLOBAL_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE")
        };
        var globalDirectoryNkey = environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE");
        var globalDirectoryCredentials = environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE");
        var globalDirectoryTlsValues = new[]
        {
            environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE")
        };
        var globalDirectoryServiceNkey = environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE");
        var globalDirectoryServiceCredentials = environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE");
        var globalDirectoryServiceTlsValues = new[]
        {
            environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE")
        };
        var infrastructureNkey = environment("TS_ORCH_INFRA_NATS_NKEY_FILE");
        var infrastructureTlsValues = new[]
        {
            environment("TS_ORCH_INFRA_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_INFRA_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_INFRA_NATS_TLS_KEY_FILE")
        };
        var journalValues = new[]
        {
            environment("TS_ORCH_JOURNAL_NATS_NKEY_FILE"),
            environment("TS_ORCH_JOURNAL_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE"),
            environment("TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE"),
            environment("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"),
            environment("TS_ORCH_JOURNAL_CONTROLLER_NKEYS")
        };
        RejectUnownedCredentials(
            command, controllerNkey, controllerTlsValues,
            globalUrl, globalNkey, globalCredentials, globalTlsValues,
            globalDirectoryUrl, globalDirectoryNkey, globalDirectoryCredentials, globalDirectoryTlsValues,
            globalDirectoryServiceUrl, globalDirectoryServiceNkey, globalDirectoryServiceCredentials, globalDirectoryServiceTlsValues,
            infrastructureNkey, infrastructureTlsValues, journalValues);
        var controllerCredentialsRequired = command is OrchestratorCommand.Run or OrchestratorCommand.Check;
        var natsNKeyFile = controllerCredentialsRequired
            ? Messaging.NatsCredentialFile.Resolve(controllerNkey, "TS_ORCH_NATS_NKEY_FILE")
            : null;
        var natsTls = controllerCredentialsRequired
            ? Messaging.NatsTlsFiles.Resolve(controllerTlsValues[0], controllerTlsValues[1], controllerTlsValues[2], "TS_ORCH_NATS_TLS")
            : null;

        if (!IsSubjectToken(cell))
        {
            throw new ArgumentException("TS_ORCH_CELL must contain only lowercase letters, digits, or hyphens.");
        }

        var uri = ParseRegionalNatsUrl(url, "TS_ORCH_NATS_URL");
        RejectNatsUrlUserInfo(globalUrl, "TS_ORCH_GLOBAL_NATS_URL");
        RejectNatsUrlUserInfo(globalDirectoryUrl, "TS_ORCH_GLOBAL_DIRECTORY_NATS_URL");
        RejectNatsUrlUserInfo(globalDirectoryServiceUrl, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL");

        if (string.IsNullOrWhiteSpace(replicasText))
        {
            // Only the read-only commands may default to a single-node cell. Every command
            // that provisions or converges the SHARED controller topology must state its
            // replica count explicitly: defaulting a restarted controller of a shared R3
            // cell to 1 would silently re-provision its streams and buckets as R1.
            if (command is OrchestratorCommand.Run or OrchestratorCommand.ProvisionJournal or
                OrchestratorCommand.JournalWriter)
            {
                throw new ArgumentException(
                    $"TS_ORCH_REPLICAS is required for the {CommandName(command)} command: it provisions or converges the shared cell topology, and an unset replica count could silently re-provision a shared R3 cell as R1. Set TS_ORCH_REPLICAS explicitly (1 for a single-node cell).");
            }
            replicasText = "1";
        }

        if (!int.TryParse(replicasText, out var replicas) || replicas is < 1 or > 5 || replicas % 2 == 0)
        {
            throw new ArgumentException("TS_ORCH_REPLICAS must be 1, 3, or 5.");
        }

        if (!IsSubjectToken(instance))
        {
            throw new ArgumentException("TS_ORCH_INSTANCE must contain only lowercase letters, digits, or hyphens.");
        }
        if (command == OrchestratorCommand.Run &&
            (uri.Scheme != "tls" || natsNKeyFile is null || natsTls is null))
        {
            throw new ArgumentException(
                "The run command requires a tls:// regional control NATS URL, a private NKey seed, and complete mTLS credentials.");
        }
        var infrastructureNatsNKeyFile = command == OrchestratorCommand.ProvisionJournal
            ? Messaging.NatsCredentialFile.Resolve(
                infrastructureNkey,
                "TS_ORCH_INFRA_NATS_NKEY_FILE")
            : null;
        var infrastructureNatsTls = command == OrchestratorCommand.ProvisionJournal
            ? Messaging.NatsTlsFiles.Resolve(
                infrastructureTlsValues[0],
                infrastructureTlsValues[1],
                infrastructureTlsValues[2],
                "TS_ORCH_INFRA_NATS_TLS")
            : null;
        if (command == OrchestratorCommand.ProvisionJournal &&
            (uri.Scheme != "tls" || infrastructureNatsNKeyFile is null || infrastructureNatsTls is null))
        {
            throw new ArgumentException(
                "The provision-journal command requires a tls:// regional control NATS URL and complete TS_ORCH_INFRA_NATS NKey and mTLS credentials.");
        }
        if (infrastructureNatsNKeyFile is not null && natsNKeyFile is not null &&
            Messaging.NatsCredentialFile.SameIdentity(infrastructureNatsNKeyFile, natsNKeyFile))
        {
            throw new ArgumentException("Infrastructure and controller NATS identities must be distinct.");
        }
        if (infrastructureNatsTls is not null && natsTls is not null &&
            infrastructureNatsTls.SameIdentity(natsTls))
        {
            throw new ArgumentException("Infrastructure and controller NATS mTLS identities must be distinct.");
        }
        var globalNats = command is OrchestratorCommand.Run or OrchestratorCommand.Check
            ? Messaging.GlobalNatsConfiguration.Resolve(
                globalUrl, globalNkey, globalCredentials,
                globalTlsValues[0], globalTlsValues[1], globalTlsValues[2],
                replicas,
                cell)
            : null;
        var globalDirectoryNats = command is OrchestratorCommand.Run or OrchestratorCommand.Check
            ? Messaging.GlobalDirectoryNatsConfiguration.Resolve(
                globalDirectoryUrl, globalDirectoryNkey, globalDirectoryCredentials,
                globalDirectoryTlsValues[0], globalDirectoryTlsValues[1], globalDirectoryTlsValues[2],
                replicas,
                cell,
                environment("TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS"))
            : null;
        var globalDirectoryServiceNats = command is OrchestratorCommand.Run or OrchestratorCommand.Check
            ? Messaging.GlobalDirectoryServiceNatsConfiguration.Resolve(
                globalDirectoryServiceUrl, globalDirectoryServiceNkey, globalDirectoryServiceCredentials,
                globalDirectoryServiceTlsValues[0], globalDirectoryServiceTlsValues[1], globalDirectoryServiceTlsValues[2],
                replicas,
                cell)
            : null;
        if (globalDirectoryServiceNats is not null && globalDirectoryNats is null)
            throw new ArgumentException(
                "The global directory service requires complete global directory publisher/watch credentials.");
        if ((globalNats is not null || globalDirectoryNats is not null) &&
            (natsNKeyFile is null || natsTls is null))
            throw new ArgumentException(
                "Global authority and directory roles require complete regional control credentials.");
        ValidateDistinctNatsIdentities(
            natsNKeyFile,
            natsTls,
            globalNats,
            globalDirectoryNats,
            globalDirectoryServiceNats);
        var authoritativeJournal = command == OrchestratorCommand.JournalWriter
            ? Messaging.NatsAuthoritativeJournalConfiguration.Resolve(
                journalValues[0], journalValues[1], journalValues[2], journalValues[3],
                journalValues[4], journalValues[5], journalValues[6])
            : null;
        if (command == OrchestratorCommand.JournalWriter &&
            (uri.Scheme != "tls" || replicas < 3 || authoritativeJournal is null))
            throw new ArgumentException("The journal-writer command requires R3/R5 tls:// control NATS and complete TS_ORCH_JOURNAL writer credentials.");
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
        var forgejoCiSourceGraph = command is OrchestratorCommand.Run or OrchestratorCommand.Check
            ? Delivery.ForgejoRepositoryCiSourceGraphConfiguration.Load(
                environment("TS_ORCH_FORGEJO_CI_SOURCE_GRAPH_FILE"),
                forgejoSource)
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
        _ = OrchestratorRuntimeComposition.Describe(
            cell,
            globalDirectoryNats is not null,
            globalDirectoryServiceNats is not null,
            globalNats is not null,
            forgejoWebhook is not null || forgejoSource is not null,
            // The pool is the executor; identity-without-pool must not pass the
            // Forgejo-requires-an-executor guard.
            ociCiRunnerPool is not null,
            command == OrchestratorCommand.Run &&
                globalNats is not null &&
                commandIdentity?.TrustKeyFiles.Count > 0);
        return new(
            command,
            cell,
            uri.ToString(),
            replicas,
            Instance: instance,
            NatsNKeyFile: natsNKeyFile,
            NatsTls: natsTls,
            GlobalNats: globalNats,
            GlobalDirectoryNats: globalDirectoryNats,
            GlobalDirectoryServiceNats: globalDirectoryServiceNats,
            ForgejoWebhook: forgejoWebhook,
            ForgejoSource: forgejoSource,
            ForgejoCiSourceGraph: forgejoCiSourceGraph,
            CommandIdentity: commandIdentity,
            CiRunnerNatsIdentity: ciRunnerNatsIdentity,
            OciCiRunnerPool: ociCiRunnerPool,
            InfrastructureNatsNKeyFile: infrastructureNatsNKeyFile,
            InfrastructureNatsTls: infrastructureNatsTls,
            AuthoritativeJournal: authoritativeJournal);
    }

    private static void RejectUnownedCredentials(
        OrchestratorCommand command,
        string? controllerNkey,
        IReadOnlyList<string?> controllerTls,
        string? globalUrl,
        string? globalNkey,
        string? globalCredentials,
        IReadOnlyList<string?> globalTls,
        string? globalDirectoryUrl,
        string? globalDirectoryNkey,
        string? globalDirectoryCredentials,
        IReadOnlyList<string?> globalDirectoryTls,
        string? globalDirectoryServiceUrl,
        string? globalDirectoryServiceNkey,
        string? globalDirectoryServiceCredentials,
        IReadOnlyList<string?> globalDirectoryServiceTls,
        string? infrastructureNkey,
        IReadOnlyList<string?> infrastructureTls,
        IReadOnlyList<string?> journal)
    {
        var hasController = !string.IsNullOrWhiteSpace(controllerNkey) ||
            controllerTls.Any(static value => !string.IsNullOrWhiteSpace(value)) ||
            !string.IsNullOrWhiteSpace(globalUrl) ||
            !string.IsNullOrWhiteSpace(globalNkey) ||
            !string.IsNullOrWhiteSpace(globalCredentials) ||
            globalTls.Any(static value => !string.IsNullOrWhiteSpace(value)) ||
            !string.IsNullOrWhiteSpace(globalDirectoryUrl) ||
            !string.IsNullOrWhiteSpace(globalDirectoryNkey) ||
            !string.IsNullOrWhiteSpace(globalDirectoryCredentials) ||
            globalDirectoryTls.Any(static value => !string.IsNullOrWhiteSpace(value)) ||
            !string.IsNullOrWhiteSpace(globalDirectoryServiceUrl) ||
            !string.IsNullOrWhiteSpace(globalDirectoryServiceNkey) ||
            !string.IsNullOrWhiteSpace(globalDirectoryServiceCredentials) ||
            globalDirectoryServiceTls.Any(static value => !string.IsNullOrWhiteSpace(value));
        var hasInfrastructure = !string.IsNullOrWhiteSpace(infrastructureNkey) || infrastructureTls.Any(static value => !string.IsNullOrWhiteSpace(value));
        var hasJournal = journal.Any(static value => !string.IsNullOrWhiteSpace(value));
        if (hasController && command is not (OrchestratorCommand.Run or OrchestratorCommand.Check))
            throw new ArgumentException($"The {CommandName(command)} role must not receive controller NATS credentials.");
        if (hasInfrastructure && command is not OrchestratorCommand.ProvisionJournal)
            throw new ArgumentException($"The {CommandName(command)} role must not receive infrastructure NATS credentials.");
        if (hasJournal && command is not OrchestratorCommand.JournalWriter)
            throw new ArgumentException($"The {CommandName(command)} role must not receive journal-writer credentials.");
    }

    private static string CommandName(OrchestratorCommand command) => command switch
    {
        OrchestratorCommand.ProvisionJournal => "provision-journal",
        OrchestratorCommand.JournalWriter => "journal-writer",
        _ => command.ToString().ToLowerInvariant()
    };

    internal static Uri ParseRegionalNatsUrl(string url, string optionName)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(optionName);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme is not "nats" and not "tls" ||
            string.IsNullOrEmpty(uri.Host))
        {
            throw new ArgumentException(
                $"{optionName} must be an absolute nats:// or tls:// URL.",
                optionName);
        }
        RejectNatsUrlUserInfo(uri, optionName);
        return uri;
    }

    internal static string SanitizeNatsUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return "[invalid NATS URL]";

        var builder = new UriBuilder(uri)
        {
            UserName = string.Empty,
            Password = string.Empty,
            Path = string.Empty,
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri.GetLeftPart(UriPartial.Authority);
    }

    private static void RejectNatsUrlUserInfo(string? url, string optionName)
    {
        if (url is not null && Uri.TryCreate(url, UriKind.Absolute, out var uri))
            RejectNatsUrlUserInfo(uri, optionName);
    }

    private static void RejectNatsUrlUserInfo(Uri uri, string optionName)
    {
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException(
                $"{optionName} must not include user information; provide NATS authentication through credential files.",
                optionName);
        }
    }

    private static void ValidateDistinctNatsIdentities(
        string? regionalNkey,
        Messaging.NatsTlsFiles? regionalTls,
        Messaging.GlobalNatsConfiguration? authority,
        Messaging.GlobalDirectoryNatsConfiguration? directory,
        Messaging.GlobalDirectoryServiceNatsConfiguration? service)
    {
        var identities = new List<(string Name, string PublicKey, Messaging.NatsTlsFiles Tls)>();
        if (regionalNkey is not null && regionalTls is not null)
            identities.Add(("regional control", Messaging.NatsCredentialFile.PublicKey(regionalNkey), regionalTls));
        if (authority is not null)
            identities.Add(("global authority", authority.Authentication.PublicKey, authority.Tls));
        if (directory is not null)
            identities.Add(("global directory", directory.Authentication.PublicKey, directory.Tls));
        if (service is not null)
            identities.Add(("global directory service", service.Authentication.PublicKey, service.Tls));

        for (var first = 0; first < identities.Count; first++)
            for (var second = first + 1; second < identities.Count; second++)
            {
                var left = identities[first];
                var right = identities[second];
                if (left.PublicKey == right.PublicKey ||
                    left.Tls.SameIdentity(right.Tls))
                    throw new ArgumentException(
                        $"{left.Name} and {right.Name} NATS identities must be distinct.");
            }
    }

    private static bool IsSubjectToken(string value) =>
        value.Length is > 0 and <= 32 &&
        value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
