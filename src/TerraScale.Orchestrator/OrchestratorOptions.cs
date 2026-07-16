namespace TerraScale.Orchestrator;

public enum OrchestratorCommand
{
    Run,
    Check,
    Lab
}

public enum OrchestratorLabCommand
{
    Plan,
    Up,
    Status
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
    bool Watch = false)
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
            var value => throw new ArgumentException($"Unknown command '{value}'. Use 'run', 'check', or 'lab'.")
        };

        var cell = environment("TS_ORCH_CELL") ?? "local";
        var url = environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222";
        var replicasText = environment("TS_ORCH_REPLICAS") ?? "1";

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

        if (command is not OrchestratorCommand.Lab)
        {
            return new(command, cell, uri.ToString(), replicas);
        }

        return ParseLab(args.Skip(1).ToArray(), environment, cell, uri.ToString(), replicas);
    }

    private static OrchestratorOptions ParseLab(
        IReadOnlyList<string> args,
        Func<string, string?> environment,
        string cell,
        string natsUrl,
        int replicas)
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
        for (var index = args.Count > 0 ? 1 : 0; index < args.Count; index++)
        {
            var argument = args[index];
            if (argument == "--watch")
            {
                watch = true;
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

        var unknown = values.Keys.Except(
            ["--workspace", "--data-directory", "--state-file", "--endpoints-file", "--evidence"],
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
            watch);
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
