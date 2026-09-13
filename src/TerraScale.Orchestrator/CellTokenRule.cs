namespace TerraScale.Orchestrator;

/// <summary>
/// Infrastructure-free grammar for a region or cell token used in subjects,
/// account names, and startup composition. NATS-specific modules may consume
/// this rule, but the rule itself has no messaging dependency.
/// </summary>
internal static class CellTokenRule
{
    internal static bool IsValid(string? cell) =>
        cell is { Length: >= 1 and <= 63 } &&
        cell[0] != '-' && cell[^1] != '-' &&
        cell.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}

