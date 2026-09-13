namespace TerraScale.Orchestrator;

public sealed record BuildVersion(string Contract, int Protocol)
{
    public static BuildVersion Current { get; } = new("phase0-draft", 1);

    public string DisplayName => $"TerraScale Orchestrator {Contract} (protocol v{Protocol})";
}

