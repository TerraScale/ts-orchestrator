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
    DevHost,
    RegionsSmol
}

public enum SmolVmLandlockMode
{
    Enforce,
    Off
}

public sealed record SmolVmLabOptions(
    string RunId,
    string PinFile,
    string InstallationRoot,
    string BaseArtifact,
    string BaseArtifactDigest,
    string SocketPath,
    string RuntimeDataRoot,
    byte CpuCount,
    uint MemoryMiB,
    ulong StorageGiB,
    ulong OverlayGiB,
    ushort FirstHostPort,
    IReadOnlyList<string> AllowedEgressCidrs,
    bool RequireInternalProvenance,
    SmolVmLandlockMode LandlockMode,
    bool AllowUnqualifiedHost);

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
    bool Watch = false,
    string Instance = "local",
    OrchestratorLabProfile LabProfile = OrchestratorLabProfile.DevHost,
    SmolVmLabOptions? SmolVm = null,
    string? NatsNKeyFile = null)
{
    public static OrchestratorOptions Parse(
        IReadOnlyList<string> args,
        Func<string, string?> environment)
    {
        var command = args.FirstOrDefault() switch
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

        if (command is not OrchestratorCommand.Lab)
        {
            if (args.Count > 1)
            {
                throw new ArgumentException($"The {args[0]} command does not accept arguments.");
            }
            return new(
                command,
                cell,
                uri.ToString(),
                replicas,
                Instance: instance,
                NatsNKeyFile: natsNKeyFile);
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
        var labCommand = args.FirstOrDefault() switch
        {
            null or "plan" => OrchestratorLabCommand.Plan,
            "up" => OrchestratorLabCommand.Up,
            "status" => OrchestratorLabCommand.Status,
            var value => throw new ArgumentException($"Unknown lab command '{value}'. Use 'plan', 'up', or 'status'.")
        };

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var watch = false;
        var requireInternalProvenance = false;
        var allowUnqualifiedSmolVmHost = false;
        for (var index = args.Count > 0 ? 1 : 0; index < args.Count; index++)
        {
            var argument = args[index];
            if (argument == "--watch")
            {
                watch = true;
                continue;
            }
            if (argument == "--require-internal-provenance")
            {
                requireInternalProvenance = true;
                continue;
            }
            if (argument == "--allow-unqualified-smolvm-host")
            {
                allowUnqualifiedSmolVmHost = true;
                continue;
            }

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

        var labProfile = GetValue(values, "--profile", environment("TS_ORCH_LAB_PROFILE") ?? "devhost") switch
        {
            "devhost" => OrchestratorLabProfile.DevHost,
            "regions-smol" => OrchestratorLabProfile.RegionsSmol,
            _ => throw new ArgumentException("Lab profile must be 'devhost' or 'regions-smol'.")
        };
        if (labProfile == OrchestratorLabProfile.RegionsSmol && !values.ContainsKey("--state-file"))
        {
            stateFile = Path.Combine(dataDirectory, "regions-smol-state.json");
        }

        var unknown = values.Keys.Except(
            [
                "--workspace", "--data-directory", "--state-file", "--endpoints-file", "--evidence", "--profile",
                "--run-id", "--smolvm-pin", "--smolvm-installation", "--base-artifact", "--base-digest",
                "--socket", "--smolvm-data-root", "--vm-cpus", "--vm-memory-mib", "--vm-storage-gib", "--vm-overlay-gib",
                "--first-host-port", "--allowed-cidrs", "--smolvm-landlock"
            ],
            StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null)
        {
            throw new ArgumentException($"Unknown lab option '{unknown}'.");
        }

        var smolVm = labProfile == OrchestratorLabProfile.RegionsSmol
            ? ParseSmolVm(
                values,
                environment,
                workspaceRoot,
                dataDirectory,
                requireInternalProvenance,
                allowUnqualifiedSmolVmHost)
            : null;
        if (labProfile == OrchestratorLabProfile.DevHost &&
            (requireInternalProvenance || allowUnqualifiedSmolVmHost ||
             values.Keys.Any(key => key.StartsWith("--smolvm", StringComparison.Ordinal) ||
                key is "--run-id" or "--base-artifact" or "--base-digest" or "--socket" or "--smolvm-data-root" or
                    "--vm-cpus" or "--vm-memory-mib" or "--vm-storage-gib" or "--vm-overlay-gib" or
                    "--first-host-port" or "--allowed-cidrs")))
        {
            throw new ArgumentException("SmolVM options require '--profile regions-smol'.");
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
            watch,
            instance,
            labProfile,
            smolVm);
    }

    private static SmolVmLabOptions ParseSmolVm(
        IReadOnlyDictionary<string, string> values,
        Func<string, string?> environment,
        string workspaceRoot,
        string dataDirectory,
        bool requireInternalProvenance,
        bool allowUnqualifiedHost)
    {
        var repository = Path.Combine(workspaceRoot, "TerraScale.Orchestrator");
        var runId = GetValue(values, "--run-id", environment("TS_ORCH_SMOLVM_RUN_ID") ?? "regions");
        if (!IsSubjectToken(runId) || runId.Length > 24)
        {
            throw new ArgumentException("SmolVM run ID must be a lowercase DNS token of at most 24 characters.");
        }
        var installation = RequiredValue(values, "--smolvm-installation", environment("TS_SMOLVM_HOME"));
        var baseArtifact = RequiredValue(values, "--base-artifact", environment("TS_ORCH_SMOLVM_BASE"));
        var baseDigest = RequiredValue(values, "--base-digest", environment("TS_ORCH_SMOLVM_BASE_SHA256"));
        _ = new Runtime.ArtifactDigest(baseDigest);
        var socket = RequiredValue(values, "--socket", environment("TS_ORCH_SMOLVM_SOCKET"));
        var runtimeDataRoot = RequiredValue(
            values,
            "--smolvm-data-root",
            environment("TS_ORCH_SMOLVM_DATA_ROOT"));
        var fullSocketPath = Path.GetFullPath(socket);
        var fullRuntimeDataRoot = Path.GetFullPath(runtimeDataRoot);
        if (fullSocketPath.Length > 100)
        {
            throw new ArgumentException("The SmolVM Unix socket path exceeds the portable Linux limit.");
        }
        if (fullRuntimeDataRoot.Length > 48)
        {
            throw new ArgumentException(
                "The SmolVM data root is too long for its internal Unix agent sockets (maximum 48 characters).");
        }
        var cidrs = RequiredValue(values, "--allowed-cidrs", environment("TS_ORCH_SMOLVM_ALLOWED_CIDRS"))
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (cidrs.Length == 0 || cidrs.Any(value => !IsCidr(value)))
        {
            throw new ArgumentException("SmolVM allowed CIDRs must be an explicit comma-separated IPv4/IPv6 CIDR list.");
        }
        var landlockMode = GetValue(
            values,
            "--smolvm-landlock",
            environment("TS_ORCH_SMOLVM_LANDLOCK") ?? "enforce") switch
        {
            "enforce" => SmolVmLandlockMode.Enforce,
            "off" => SmolVmLandlockMode.Off,
            _ => throw new ArgumentException("SmolVM Landlock mode must be 'enforce' or 'off'.")
        };
        if (landlockMode == SmolVmLandlockMode.Off && !allowUnqualifiedHost)
        {
            throw new ArgumentException(
                "Disabling SmolVM Landlock requires --allow-unqualified-smolvm-host and cannot qualify production parity.");
        }
        if (requireInternalProvenance && (landlockMode != SmolVmLandlockMode.Enforce || allowUnqualifiedHost))
        {
            throw new ArgumentException("Internally qualified SmolVM runs require Landlock enforcement.");
        }
        return new(
            runId,
            Path.GetFullPath(GetValue(values, "--smolvm-pin", Path.Combine(repository, "testlab/pins/smolvm-v1.5.0.json"))),
            Path.GetFullPath(installation),
            Path.GetFullPath(baseArtifact),
            baseDigest,
            fullSocketPath,
            fullRuntimeDataRoot,
            ParseNumber<byte>(values, "--vm-cpus", 2, value => value is >= 1 and <= 32),
            ParseNumber<uint>(values, "--vm-memory-mib", 2048, value => value is >= 512 and <= 131_072),
            ParseNumber<ulong>(values, "--vm-storage-gib", 20, value => value is >= 4 and <= 4_096),
            ParseNumber<ulong>(values, "--vm-overlay-gib", 4, value => value is >= 1 and <= 1_024),
            ParseNumber<ushort>(values, "--first-host-port", 24_000, value => value is >= 1024 and <= 65_355),
            cidrs,
            requireInternalProvenance,
            landlockMode,
            allowUnqualifiedHost);
    }

    private static T ParseNumber<T>(
        IReadOnlyDictionary<string, string> values,
        string key,
        T fallback,
        Func<T, bool> validate)
        where T : struct, IParsable<T>
    {
        var value = values.TryGetValue(key, out var text)
            ? T.Parse(text, System.Globalization.CultureInfo.InvariantCulture)
            : fallback;
        return validate(value) ? value : throw new ArgumentException($"Invalid value for {key}.");
    }

    private static string RequiredValue(
        IReadOnlyDictionary<string, string> values,
        string key,
        string? fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : !string.IsNullOrWhiteSpace(fallback)
                ? fallback
                : throw new ArgumentException($"The regions-smol profile requires {key}.");

    private static bool IsCidr(string value)
    {
        var parts = value.Split('/', 2);
        return parts.Length == 2 &&
            System.Net.IPAddress.TryParse(parts[0], out var address) &&
            int.TryParse(parts[1], out var prefix) &&
            prefix >= 0 && prefix <= (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
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
