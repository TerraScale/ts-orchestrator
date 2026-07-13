using TerraScale.Orchestrator.SchemaGenerator;

var outputRoot = args.Length switch
{
    0 => Directory.GetCurrentDirectory(),
    2 when args[0] == "--output-root" => args[1],
    _ => throw new ArgumentException("Usage: schema-generator [--output-root <repository-root>]")
};

foreach (var artifact in SchemaArtifacts.Generate())
{
    var path = Path.Combine(outputRoot, artifact.Key.Replace('/', Path.DirectorySeparatorChar));
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    File.WriteAllText(path, artifact.Value);
}
