namespace TerraScale.Orchestrator.Development;

internal sealed class DevelopmentArtifactBackup : IDisposable
{
    private readonly string root;
    private readonly IReadOnlyList<(string Source, string Backup)> directories;
    private readonly string? dashboardPointer;
    private readonly string dashboardPointerPath;

    private DevelopmentArtifactBackup(
        string root,
        IReadOnlyList<(string Source, string Backup)> directories,
        string dashboardPointerPath,
        string? dashboardPointer)
    {
        this.root = root;
        this.directories = directories;
        this.dashboardPointerPath = dashboardPointerPath;
        this.dashboardPointer = dashboardPointer;
    }

    public static DevelopmentArtifactBackup Capture(
        string dataDirectory,
        string reconciliationId,
        IReadOnlySet<DevelopmentResourceKind> kinds)
    {
        var root = Path.Combine(dataDirectory, "reconciliation-backups", reconciliationId);
        Directory.CreateDirectory(root);
        var sources = new List<string>();
        if (kinds.Contains(DevelopmentResourceKind.TerraBase))
        {
            sources.Add(DevelopmentArtifactBuilder.DotNetOutputDirectory(dataDirectory, "TerraBase.Server"));
        }
        if (kinds.Contains(DevelopmentResourceKind.Authentication))
        {
            sources.Add(DevelopmentArtifactBuilder.DotNetOutputDirectory(
                dataDirectory,
                "TerraScale.Authentication"));
        }
        if (kinds.Contains(DevelopmentResourceKind.Platform))
        {
            sources.Add(DevelopmentArtifactBuilder.DotNetOutputDirectory(dataDirectory, "TerraScale.Platform"));
        }

        var directories = sources.Distinct(StringComparer.Ordinal)
            .Select((source, index) => (Source: source, Backup: Path.Combine(root, index.ToString(
                System.Globalization.CultureInfo.InvariantCulture))))
            .ToArray();
        foreach (var (source, backup) in directories)
        {
            if (!Directory.Exists(source))
            {
                throw new InvalidOperationException($"Healthy development artifact '{source}' is missing.");
            }
            CopyDirectory(source, backup);
        }

        var pointer = Path.Combine(dataDirectory, "artifacts", "dashboard", "current");
        var pointerValue = kinds.Contains(DevelopmentResourceKind.Dashboard) && File.Exists(pointer)
            ? File.ReadAllText(pointer)
            : null;
        return new(root, directories, pointer, pointerValue);
    }

    public void Restore()
    {
        foreach (var (source, backup) in directories)
        {
            if (Directory.Exists(source))
            {
                Directory.Delete(source, recursive: true);
            }
            CopyDirectory(backup, source);
        }
        if (dashboardPointer is not null)
        {
            File.WriteAllText(dashboardPointerPath, dashboardPointer);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
        GC.SuppressFinalize(this);
    }

    private static void CopyDirectory(string source, string target)
    {
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(target, Path.GetRelativePath(source, directory)));
        }
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var destination = Path.Combine(target, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination, overwrite: true);
        }
    }
}
