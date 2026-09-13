using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record CiRunnerMaterializedSource(
    string Root,
    string PlanDigest,
    string BundleSha256,
    int FileCount,
    long ExpandedBytes,
    string DescriptorSha256,
    string RecipeSha256);

/// <summary>
/// Expands one exact signed source bundle into a new private runner workspace. Only directories
/// and regular files are admitted; repository links and special files never reach BuildKit.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerSourceMaterializer(IDeliveryObjectStore bundles)
{
    internal const int MaximumEntries = 100_000;
    internal const long MaximumExpandedBytes = 2L * 1024 * 1024 * 1024;
    internal const long MaximumFileBytes = 512L * 1024 * 1024;
    private const int MaximumPathBytes = 4 * 1024;
    private const int MaximumTarPaddingBytes = 1024 * 1024;
    private const int CopyBufferBytes = 64 * 1024;
    private static readonly UnixFileMode DirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal async Task<CiRunnerMaterializedSource> MaterializeAsync(
        CiRunnerExecutionPlan plan,
        string destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("CI source workspaces require Linux file permissions.");
        ValidatePlan(plan);
        if (!Path.IsPathFullyQualified(destination))
            throw new ArgumentException("The CI source workspace path must be absolute.", nameof(destination));
        var root = Path.GetFullPath(destination);
        if (Directory.Exists(root) || File.Exists(root))
            throw new IOException("The CI source workspace must not already exist.");
        var parent = Directory.GetParent(root)
            ?? throw new ArgumentException("The CI source workspace has no parent directory.", nameof(destination));
        if (!parent.Exists || parent.LinkTarget is not null)
            throw new IOException("The CI source workspace parent must be an existing real directory.");

        var source = plan.Source;
        var content = await bundles.GetAsync(source.BundleObject, cancellationToken);
        if (content.Length != source.BundleBytes ||
            Convert.ToHexStringLower(SHA256.HashData(content)) != source.BundleSha256 ||
            content.Length < 3 || content[0] != 0x1f || content[1] != 0x8b || content[2] != 0x08)
            throw new InvalidDataException("The CI source bundle failed signed identity verification.");

        Directory.CreateDirectory(root, DirectoryMode);
        File.SetUnixFileMode(root, DirectoryMode);
        try
        {
            var expandedLimit = Math.Min(MaximumExpandedBytes, plan.Build.EphemeralDiskBytes / 2);
            var (fileCount, expandedBytes) = await ExtractAsync(
                content,
                root,
                expandedLimit,
                cancellationToken);
            var descriptor = RequiredFile(root, source.DescriptorPath);
            var recipe = RequiredFile(root, source.RecipePath);
            return new(
                root,
                plan.Digest,
                source.BundleSha256,
                fileCount,
                expandedBytes,
                await HashFileAsync(descriptor, cancellationToken),
                await HashFileAsync(recipe, cancellationToken));
        }
        catch
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch
            {
            }
            throw;
        }
    }

    private static async Task<(int FileCount, long ExpandedBytes)> ExtractAsync(
        byte[] content,
        string root,
        long expandedLimit,
        CancellationToken cancellationToken)
    {
        if (expandedLimit < 1)
            throw new InvalidDataException("The CI runner has no source-expansion disk budget.");
        var destinationPrefix = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? archiveRoot = null;
        var entries = 0;
        var files = 0;
        long expanded = 0;
        await using var compressed = new MemoryStream(content, writable: false);
        await using var gzip = new GZipStream(compressed, CompressionMode.Decompress, leaveOpen: false);
        await using var reader = new TarReader(gzip, leaveOpen: false);
        while (await reader.GetNextEntryAsync(copyData: false, cancellationToken) is { } entry)
        {
            if (++entries > MaximumEntries)
                throw new InvalidDataException("The CI source archive exceeded its entry bound.");
            var relative = RelativePath(entry, ref archiveRoot);
            if (relative is null)
            {
                if (!seen.Add(string.Empty))
                    throw new InvalidDataException("The CI source archive contains a duplicate root.");
                continue;
            }
            if (!seen.Add(relative))
                throw new InvalidDataException("The CI source archive contains a duplicate path.");
            var destination = Path.GetFullPath(Path.Combine(
                root,
                relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!destination.StartsWith(destinationPrefix, StringComparison.Ordinal))
                throw new InvalidDataException("The CI source archive escaped its workspace.");

            switch (entry.EntryType)
            {
                case TarEntryType.Directory:
                    if (entry.Length != 0 || File.Exists(destination))
                        throw new InvalidDataException("The CI source archive contains an invalid directory.");
                    EnsurePrivateDirectory(root, destination);
                    break;
                case TarEntryType.RegularFile:
                case TarEntryType.V7RegularFile:
                    if (entry.Length < 0 || entry.Length > MaximumFileBytes ||
                        expanded > expandedLimit - entry.Length || entry.DataStream is null)
                        throw new InvalidDataException("The CI source archive exceeded its file or expansion bound.");
                    var directory = Path.GetDirectoryName(destination)
                        ?? throw new InvalidDataException("The CI source archive file has no parent directory.");
                    EnsurePrivateDirectory(root, directory);
                    await CopyFileAsync(entry.DataStream, destination, entry.Length, cancellationToken);
                    var executable = (entry.Mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherExecute)) != 0;
                    File.SetUnixFileMode(
                        destination,
                        executable ? PrivateFileMode | UnixFileMode.UserExecute : PrivateFileMode);
                    expanded += entry.Length;
                    files++;
                    break;
                default:
                    throw new InvalidDataException("The CI source archive contains a link or special file.");
            }
        }
        await RequireOnlyBoundedZeroPaddingAsync(gzip, cancellationToken);
        if (archiveRoot is null || files == 0)
            throw new InvalidDataException("The CI source archive is empty.");
        return (files, expanded);
    }

    private static string? RelativePath(TarEntry entry, ref string? archiveRoot)
    {
        var name = entry.Name;
        if (name.Length == 0 || name[0] == '/' || name.Contains('\\') ||
            Encoding.UTF8.GetByteCount(name) > MaximumPathBytes)
            throw new InvalidDataException("The CI source archive contains an unsafe path.");
        if (name.EndsWith('/')) name = name[..^1];
        var segments = name.Split('/');
        if (segments.Any(static segment => segment.Length == 0 || segment is "." or ".." ||
                segment.Any(char.IsControl)))
            throw new InvalidDataException("The CI source archive contains an unsafe path.");
        archiveRoot ??= segments[0];
        if (segments[0] != archiveRoot)
            throw new InvalidDataException("The CI source archive has more than one root.");
        if (segments.Length == 1)
        {
            if (entry.EntryType != TarEntryType.Directory)
                throw new InvalidDataException("The CI source archive root is not a directory.");
            return null;
        }
        return string.Join('/', segments.AsSpan(1).ToArray());
    }

    private static async Task CopyFileAsync(
        Stream source,
        string destination,
        long length,
        CancellationToken cancellationToken)
    {
        await using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            CopyBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = new byte[CopyBufferBytes];
        var remaining = length;
        while (remaining > 0)
        {
            var read = await source.ReadAsync(
                buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                cancellationToken);
            if (read == 0)
                throw new InvalidDataException("A CI source archive file ended before its declared length.");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            remaining -= read;
        }
        await output.FlushAsync(cancellationToken);
    }

    private static void EnsurePrivateDirectory(string root, string destination)
    {
        Directory.CreateDirectory(destination, DirectoryMode);
        var current = new DirectoryInfo(destination);
        while (current.FullName != root)
        {
            if (current.LinkTarget is not null)
                throw new InvalidDataException("The CI source workspace contains a linked directory.");
            File.SetUnixFileMode(current.FullName, DirectoryMode);
            current = current.Parent
                ?? throw new InvalidDataException("The CI source workspace directory escaped its root.");
        }
    }

    private static async Task RequireOnlyBoundedZeroPaddingAsync(
        Stream source,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[CopyBufferBytes];
        var total = 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken);
            if (read == 0) return;
            total = checked(total + read);
            if (total > MaximumTarPaddingBytes || buffer.AsSpan(0, read).ContainsAnyExcept((byte)0))
                throw new InvalidDataException("The CI source archive contains ambiguous trailing data.");
        }
    }

    private static string RequiredFile(string root, string relative)
    {
        var path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is < 1 or > ForgejoSourceClient.MaximumFileBytes)
            throw new InvalidDataException("The CI source archive omitted a bounded required policy file.");
        return path;
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    private static void ValidatePlan(CiRunnerExecutionPlan plan)
    {
        var source = plan.Source;
        if (plan.SchemaVersion != 2 || plan.Digest != CiRunnerExecutionPlanner.Digest(plan) ||
            !ForgejoWebhookVerifier.IsRepository(source.Repository) ||
            !ObjectId(source.Commit) || !ObjectId(source.Tree) ||
            !Digest(source.BundleSha256) ||
            source.BundleObject != RepositoryCiSourceBundlePublisher.ObjectName(source.BundleSha256) ||
            source.BundleBytes is < 3 or > ForgejoSourceClient.MaximumArchiveBytes ||
            source.DescriptorPath != RepositoryCiImpactPlanner.DescriptorPath ||
            source.RecipePath != CiRunnerExecutionPlanner.RecipePath ||
            plan.Build.EphemeralDiskBytes <= 0)
            throw new InvalidDataException("The CI runner source plan is invalid.");
    }

    private static bool Digest(string value) => value.Length == 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool ObjectId(string value) => value.Length is 40 or 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

