namespace TerraScale.Orchestrator;

public enum OrchestratorCommand
{
    Run,
    Check
}

public sealed record OrchestratorOptions(
    OrchestratorCommand Command,
    string Cell,
    string NatsUrl,
    int Replicas)
{
    public static OrchestratorOptions Parse(
        IReadOnlyList<string> args,
        Func<string, string?> environment)
    {
        var command = args.FirstOrDefault() switch
        {
            null or "run" => OrchestratorCommand.Run,
            "check" => OrchestratorCommand.Check,
            var value => throw new ArgumentException($"Unknown command '{value}'. Use 'run' or 'check'.")
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

        return new(command, cell, uri.ToString(), replicas);
    }

    private static bool IsSubjectToken(string value) =>
        value.Length is > 0 and <= 32 &&
        value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
