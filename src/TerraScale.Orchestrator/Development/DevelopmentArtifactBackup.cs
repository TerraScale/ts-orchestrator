namespace TerraScale.Orchestrator.Development;

internal sealed class DevelopmentArtifactBackup : IDisposable
{
    private readonly string root;
    private readonly IReadOnlyList<(string Source, string Backup)> directories;
    private readonly IReadOnlyList<(string Path, string? Content)> stamps;
    private readonly string? dashboardPointer;
    private readonly string dashboardPointerPath;

    private DevelopmentArtifactBackup(
        string root,
        IReadOnlyList<(string Source, string Backup)> directories,
        IReadOnlyList<(string Path, string? Content)> stamps,
        string dashboardPointerPath,
        string? dashboardPointer)
    {
        this.root = root;
        this.directories = directories;
        this.stamps = stamps;
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
        // Build stamps must roll back with the artifacts they describe; otherwise a
        // restored last-healthy artifact would be stamped as the new source state.
        var stamps = kinds
            .Select(kind => DevelopmentArtifactBuilder.StampPath(dataDirectory, kind))
            .Distinct(StringComparer.Ordinal)
            .Select(path => (Path: path, Content: File.Exists(path) ? File.ReadAllText(path) : null))
            .ToArray();
        return new(root, directories, stamps, pointer, pointerValue);
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
        foreach (var (path, content) in stamps)
        {
            if (content is null)
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
                continue;
            }
            Directory.CreateDirectory(
                DevelopmentGuards.RequireDirectory(path, "Artifact stamp restore"));
            File.WriteAllText(path, content);
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
            Directory.CreateDirectory(
                DevelopmentGuards.RequireDirectory(destination, "Artifact backup destination"));
            File.Copy(file, destination, overwrite: true);
        }
    }
}
