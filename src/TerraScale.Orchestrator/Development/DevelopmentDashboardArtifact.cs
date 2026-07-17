using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentDashboardArtifact
{
    private const string CurrentFile = "current";

    public static string Snapshot(string dashboardDirectory, string dataDirectory)
    {
        var source = Path.Combine(dashboardDirectory, "dist", "standalone");
        RequireStandalone(source);
        var files = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var fingerprint = Fingerprint(source, files);
        var root = Path.Combine(dataDirectory, "artifacts", "dashboard");
        var target = Path.Combine(root, fingerprint);
        Directory.CreateDirectory(root);
        if (!Directory.Exists(target))
        {
            var staging = target + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                foreach (var sourceFile in files)
                {
                    var relative = Path.GetRelativePath(source, sourceFile);
                    var destination = Path.Combine(staging, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    File.Copy(sourceFile, destination);
                }
                Directory.Move(staging, target);
            }
            catch
            {
                if (Directory.Exists(staging))
                {
                    Directory.Delete(staging, recursive: true);
                }
                throw;
            }
        }
        var pointer = Path.Combine(root, CurrentFile);
        var temporaryPointer = pointer + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temporaryPointer, fingerprint, Encoding.UTF8);
        File.Move(temporaryPointer, pointer, overwrite: true);
        return target;
    }

    public static string Resolve(string dataDirectory)
    {
        var root = Path.Combine(dataDirectory, "artifacts", "dashboard");
        var pointer = Path.Combine(root, CurrentFile);
        if (!File.Exists(pointer))
        {
            throw new FileNotFoundException("The immutable dashboard artifact pointer is unavailable.", pointer);
        }
        var fingerprint = File.ReadAllText(pointer, Encoding.UTF8).Trim();
        var target = Path.GetFullPath(Path.Combine(root, fingerprint));
        var rooted = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        if (!target.StartsWith(rooted, StringComparison.Ordinal) || !Directory.Exists(target))
        {
            throw new InvalidOperationException("The immutable dashboard artifact pointer is invalid.");
        }
        RequireStandalone(target);
        return target;
    }

    private static string Fingerprint(string root, IEnumerable<string> files)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            aggregate.AppendData(Encoding.UTF8.GetBytes(relative));
            aggregate.AppendData([0]);
            using var stream = File.OpenRead(file);
            aggregate.AppendData(SHA256.HashData(stream));
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static void RequireStandalone(string directory)
    {
        if (!Directory.Exists(directory) || !File.Exists(Path.Combine(directory, "server.js")))
        {
            throw new InvalidOperationException("The dashboard standalone artifact is incomplete.");
        }
    }
}
