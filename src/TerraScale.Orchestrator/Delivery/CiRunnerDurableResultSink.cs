using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record CiRunnerResultManifest(
    int SchemaVersion,
    string Job,
    string PlanDigest,
    bool Succeeded,
    int RequiredTestSkips,
    CiRunnerResultArtifact[]? Artifacts);

internal sealed record CiRunnerResultArtifact(
    string Artifact,
    string Architecture,
    string Path,
    string[]? Entrypoints);

internal sealed record CiRunnerStoredArtifactEvidence(
    string Artifact,
    RepositoryCiArchitecture Architecture,
    string Path,
    string Digest,
    int Files,
    long Bytes,
    string[] Entrypoints);

internal sealed record CiRunnerStoredWorkloadEvidence(
    int SchemaVersion,
    CiRunnerWorkloadEvidence Workload,
    string LogObject,
    string LogSha256,
    long LogBytes,
    string ArtifactObject,
    string ArtifactSha256,
    long ArtifactBytes,
    CiRunnerStoredArtifactEvidence[]? Artifacts,
    int RequiredTestSkips,
    int RetentionDays);

/// <summary>
/// Stores redacted logs, a deterministic validated output archive, and canonical evidence under
/// content identities. The execution journal remains the only winner pointer for crash takeover.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerDurableResultSink(IDeliveryObjectStore objects) : ICiRunnerWorkloadResultSink
{
    internal const string ResultManifestPath = "terrascale-ci-result-v2.json";
    internal const int RetentionDays = 30;
    private const int MaximumEvidenceBytes = 64 * 1024;
    private const int MaximumManifestBytes = 16 * 1024;
    private readonly IDeliveryObjectStore objects = objects ?? throw new ArgumentNullException(nameof(objects));

    public async Task<CiRunnerDurableWorkloadResult> PersistAsync(
        CiRunnerWorkloadEvidence evidence,
        ReadOnlyMemory<byte> redactedLog,
        string? exportDirectory,
        CiRunnerExecutionPlan? plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ValidateEvidence(evidence, redactedLog, exportDirectory, plan);

        var logObject = string.Empty;
        if (evidence.LogSha256.Length != 0)
        {
            logObject = $"ci-result-log-{evidence.LogSha256}";
            await PutVerifiedAsync(logObject, redactedLog, cancellationToken);
        }

        var requiredTestSkips = 0;
        var artifactObject = string.Empty;
        var artifactSha256 = string.Empty;
        long artifactBytes = 0;
        CiRunnerStoredArtifactEvidence[] artifacts = [];
        if (evidence.Succeeded)
        {
            string? archivePath = null;
            ArchiveEvidence archive;
            try
            {
                var root = exportDirectory is { } configuredExportDirectory
                    ? Path.GetFullPath(configuredExportDirectory)
                    : throw new InvalidDataException("A successful CI result requires an export directory.");
                EnsureAdmittedRoot(root);
                var executionPlan = plan ??
                    throw new InvalidDataException("A successful CI result requires an execution plan.");
                var manifest = await ReadManifestAsync(root, evidence, cancellationToken);
                requiredTestSkips = manifest.RequiredTestSkips;
                manifest = manifest with { Artifacts = ValidateArtifacts(executionPlan, manifest.Artifacts) };
                archivePath = Path.Combine(root, ".terrascale-ci-artifact.tar.gz");
                archive = await CreateArchiveAsync(root, archivePath, evidence, manifest, cancellationToken);
                artifacts = archive.Artifacts;
            }
            catch (InvalidDataException)
            {
                Delete(archivePath);
                var rejected = evidence with
                {
                    BuildDisposition = CiRunnerBuildKitExecutionDisposition.Unspecified,
                    ExitCode = -1,
                    MetadataSha256 = string.Empty,
                    OutputSha256 = string.Empty,
                    OutputFiles = 0,
                    OutputBytes = 0,
                    Succeeded = false,
                    FailureKind = RepositoryCiJobFailureKind.WorkloadFailed,
                    FailureCode = CiRunnerWorkloadFailureCode.OutputRejected,
                };
                ValidateEvidence(rejected, redactedLog, null, plan);
                return await PersistEvidenceAsync(
                    rejected,
                    logObject,
                    string.Empty,
                    string.Empty,
                    0,
                    [],
                    0,
                    cancellationToken);
            }

            try
            {
                var archiveFile = archivePath ??
                    throw new InvalidDataException("The CI result archive path was not created.");
                artifactObject = $"ci-result-artifact-{evidence.OutputSha256}";
                await using (var archiveContent = new FileStream(
                    archiveFile,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    64 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                    await objects.PutAsync(artifactObject, archiveContent, cancellationToken);
                using var readback = new HashingWriteStream(Stream.Null, archive.Bytes);
                await objects.CopyToAsync(artifactObject, readback, cancellationToken);
                var observed = readback.Complete();
                if (observed.Bytes != archive.Bytes || observed.Sha256 != archive.Sha256)
                    throw new InvalidDataException("The durable CI artifact archive failed readback verification.");
                artifactSha256 = archive.Sha256;
                artifactBytes = archive.Bytes;
            }
            finally
            {
                Delete(archivePath);
            }
        }

        return await PersistEvidenceAsync(
            evidence,
            logObject,
            artifactObject,
            artifactSha256,
            artifactBytes,
            artifacts,
            requiredTestSkips,
            cancellationToken);
    }

    private async Task<CiRunnerDurableWorkloadResult> PersistEvidenceAsync(
        CiRunnerWorkloadEvidence evidence,
        string logObject,
        string artifactObject,
        string artifactSha256,
        long artifactBytes,
        CiRunnerStoredArtifactEvidence[] artifacts,
        int requiredTestSkips,
        CancellationToken cancellationToken)
    {
        var document = new CiRunnerStoredWorkloadEvidence(
            2,
            evidence,
            logObject,
            evidence.LogSha256,
            evidence.LogBytes,
            artifactObject,
            artifactSha256,
            artifactBytes,
            artifacts,
            requiredTestSkips,
            RetentionDays);
        var evidenceContent = JsonSerializer.SerializeToUtf8Bytes(
            document,
            CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
        if (evidenceContent.Length is < 1 or > MaximumEvidenceBytes)
            throw new InvalidDataException("The canonical CI workload evidence exceeded its bound.");
        var digest = Hash(evidenceContent);
        await PutVerifiedAsync($"ci-result-evidence-{digest}", evidenceContent, cancellationToken);
        return new(digest, requiredTestSkips, evidence.FailureKind);
    }

    private static void Delete(string? path)
    {
        if (path is null) return;
        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }

    private static async Task<CiRunnerResultManifest> ReadManifestAsync(
        string root,
        CiRunnerWorkloadEvidence evidence,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(root, ResultManifestPath);
        if (!Path.GetFullPath(path).Equals(Path.Combine(root, ResultManifestPath), StringComparison.Ordinal) ||
            Path.GetRelativePath(root, path) != ResultManifestPath)
            throw new InvalidDataException("The CI result manifest path escaped its admitted output root.");
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            CiRunnerBuildKitExecutor.FileKind(path) != CiRunnerOutputFileKind.Regular ||
            info.Length is < 2 or > MaximumManifestBytes)
            throw new InvalidDataException("The CI result manifest is missing, linked, or oversized.");
        var content = await File.ReadAllBytesAsync(path, cancellationToken);
        try
        {
            if (HasDuplicateProperties(content)) throw new JsonException();
            var value = JsonSerializer.Deserialize(
                content,
                CiRunnerDurableResultJsonContext.Default.CiRunnerResultManifest)
                ?? throw new JsonException();
            if (value.SchemaVersion != 2 || value.Job != evidence.Job ||
                value.PlanDigest != evidence.PlanDigest || !value.Succeeded ||
                value.RequiredTestSkips is < 0 or > 1_000_000 || !ValidArtifacts(value.Artifacts))
                throw new JsonException();
            return value;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The CI result manifest is invalid.", exception);
        }
    }

    private static async Task<ArchiveEvidence> CreateArchiveAsync(
        string root,
        string archivePath,
        CiRunnerWorkloadEvidence evidence,
        CiRunnerResultManifest manifest,
        CancellationToken cancellationToken)
    {
        var directory = new DirectoryInfo(root);
        if (!directory.Exists || directory.LinkTarget is not null ||
            !IsWithin(root, archivePath) || File.Exists(archivePath) ||
            Directory.Exists(archivePath) || HasLinkedParent(archivePath))
            throw new InvalidDataException("The CI artifact export or archive path is invalid.");
        var entries = Enumerate(root)
            .OrderBy(static value => value.Relative, StringComparer.Ordinal)
            .ToArray();
        if (entries.Length is < 1 or > CiRunnerBuildKitExecutor.MaximumOutputFiles)
            throw new InvalidDataException("The CI artifact export exceeded its entry bound.");

        var maximumArchiveBytes = checked(evidence.OutputBytes +
            CiRunnerBuildKitExecutor.ArtifactArchiveOverheadBytes);
        await using var file = new FileStream(
            archivePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        File.SetUnixFileMode(archivePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        using var output = new HashingWriteStream(file, maximumArchiveBytes);
        using var canonical = new ZStringWriter();
        var artifacts = (manifest.Artifacts ?? []).Select(static value => new ArtifactTracker(value)).ToArray();
        var files = 0;
        long bytes = 0;
        await using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        await using (var writer = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: true))
        {
            foreach (var (entry, relative) in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
                if (artifacts.Length != 0 && normalized != ResultManifestPath &&
                    !artifacts.Any(artifact => artifact.Covers(normalized, entry is DirectoryInfo)))
                    throw new InvalidDataException("The CI artifact export contains an undeclared path.");
                if (entry is DirectoryInfo)
                {
                    canonical.Write("d:");
                    canonical.Write(normalized);
                    canonical.Write('\n');
                    foreach (var artifact in artifacts) artifact.Directory(normalized);
                    await writer.WriteEntryAsync(TarEntry(
                        TarEntryType.Directory,
                        normalized + '/',
                        executable: true), cancellationToken);
                    continue;
                }
                if (entry is not FileInfo source)
                    throw new InvalidDataException("The CI artifact export contains an invalid entry.");
                var length = source.Length;
                var executable = (File.GetUnixFileMode(source.FullName) & (UnixFileMode.UserExecute |
                    UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
                await using var input = new FileStream(
                    source.FullName,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    64 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var header = new byte[20];
                var headerBytes = await input.ReadAtLeastAsync(
                    header,
                    header.Length,
                    throwOnEndOfStream: false,
                    cancellationToken);
                input.Position = 0;
                using var hashed = new HashingReadStream(input);
                var tar = TarEntry(TarEntryType.RegularFile, normalized, executable);
                tar.DataStream = hashed;
                await writer.WriteEntryAsync(tar, cancellationToken);
                var content = hashed.Complete();
                source.Refresh();
                if (content.Bytes != length || source.Length != length ||
                    CiRunnerBuildKitExecutor.FileKind(source.FullName) != CiRunnerOutputFileKind.Regular)
                    throw new InvalidDataException("A CI artifact file changed during durable capture.");
                canonical.Write("f:");
                canonical.Write(normalized);
                canonical.Write(':');
                canonical.Write(length.ToString(CultureInfo.InvariantCulture));
                canonical.Write(':');
                canonical.Write(executable ? '1' : '0');
                canonical.Write(':');
                canonical.Write(content.Sha256);
                canonical.Write('\n');
                foreach (var artifact in artifacts)
                    artifact.File(normalized, length, executable, content.Sha256, header.AsSpan(0, headerBytes));
                bytes += length;
                files++;
            }
        }
        await output.FlushAsync(cancellationToken);
        var archive = output.Complete();
        var outputDigest = Hash(Encoding.UTF8.GetBytes(canonical.ToString()));
        if (files != evidence.OutputFiles || bytes != evidence.OutputBytes ||
            outputDigest != evidence.OutputSha256)
            throw new InvalidDataException("The CI artifact export changed after BuildKit validation.");
        return new(archive.Sha256, archive.Bytes, artifacts.Select(static value => value.Complete()).ToArray());
    }

    private static bool ValidArtifacts(CiRunnerResultArtifact[]? artifacts)
    {
        artifacts ??= [];
        if (artifacts.Length > 2 || artifacts.Any(static value => value is null ||
                !ArtifactId(value.Artifact) || !Architecture(value.Architecture) || !RelativePath(value.Path) ||
                !ValidEntrypoints(value)) ||
            artifacts.Select(static value => value.Architecture).Distinct().Count() != artifacts.Length ||
            artifacts.Select(static value => value.Path).Distinct(StringComparer.Ordinal).Count() != artifacts.Length)
            return false;
        return !artifacts.Any(left => artifacts.Any(right => left != right &&
            right.Path.StartsWith(left.Path + '/', StringComparison.Ordinal)));
    }

    private static CiRunnerResultArtifact[] ValidateArtifacts(
        CiRunnerExecutionPlan plan,
        CiRunnerResultArtifact[]? artifacts)
    {
        var values = artifacts ?? [];
        IReadOnlyList<RepositoryCiArchitecture> expected =
            plan.Build.Output == CiRunnerExecutionOutputKind.CandidateArtifacts
                ? plan.Build.Architectures
                : [];
        if (values.Length != expected.Count ||
            values.Where((value, index) => value.Architecture != expected[index].ToString()).Any())
            throw new InvalidDataException("The CI result manifest does not match the signed artifact plan.");
        return values;
    }

    private static bool ArtifactId(string? value) => value is { Length: >= 1 and <= 256 } &&
        value[0] != '/' && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool RelativePath(string? value) => value is { Length: >= 1 and <= 1024 } &&
        value[0] != '/' && !value.EndsWith('/') && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool Architecture(string? value) => value is
        nameof(RepositoryCiArchitecture.Any) or nameof(RepositoryCiArchitecture.LinuxX64) or
        nameof(RepositoryCiArchitecture.LinuxArm64);

    private static bool ValidEntrypoints(CiRunnerResultArtifact artifact) =>
        Enum.TryParse<RepositoryCiArchitecture>(artifact.Architecture, out var architecture) &&
        RepositoryCiArtifactAttestation.TryEntrypointsDigest(
            architecture,
            artifact.Entrypoints,
            out _);

    private sealed class ArtifactTracker(CiRunnerResultArtifact artifact)
    {
        private readonly ZStringWriter canonical = new();
        private readonly RepositoryCiArchitecture architecture =
            Enum.Parse<RepositoryCiArchitecture>(artifact.Architecture);
        private readonly string[] declaredEntrypoints = artifact.Entrypoints ?? [];
        private readonly HashSet<string> missingEntrypoints = new(
            artifact.Entrypoints ?? [],
            StringComparer.Ordinal);
        private bool rootFound;
        private int files;
        private int executables;
        private long bytes;

        internal bool Covers(string path, bool directory) =>
            path == artifact.Path || path.StartsWith(artifact.Path + '/', StringComparison.Ordinal) ||
            directory && artifact.Path.StartsWith(path + '/', StringComparison.Ordinal);

        internal void Directory(string path)
        {
            if (path == artifact.Path)
            {
                rootFound = true;
                return;
            }
            if (Relative(path) is { } relative)
            {
                canonical.Write("d:");
                canonical.Write(relative);
                canonical.Write('\n');
            }
        }

        internal void File(
            string path,
            long bytes,
            bool executable,
            string digest,
            ReadOnlySpan<byte> header)
        {
            if (Relative(path) is not { } relative) return;
            if (missingEntrypoints.Contains(relative) && !executable)
                throw new InvalidDataException("A declared CI artifact entrypoint is not executable.");
            if (executable)
            {
                RequireElfArchitecture(header, architecture);
                executables++;
            }
            _ = missingEntrypoints.Remove(relative);
            canonical.Write("f:");
            canonical.Write(relative);
            canonical.Write(':');
            canonical.Write(bytes.ToString(CultureInfo.InvariantCulture));
            canonical.Write(':');
            canonical.Write(executable ? '1' : '0');
            canonical.Write(':');
            canonical.Write(digest);
            canonical.Write('\n');
            files++;
            this.bytes += bytes;
        }

        internal CiRunnerStoredArtifactEvidence Complete()
        {
            if (!rootFound || files == 0 || missingEntrypoints.Count != 0 ||
                architecture != RepositoryCiArchitecture.Any && executables == 0)
                throw new InvalidDataException("A declared CI artifact root is missing or empty.");
            var digest = Hash(Encoding.UTF8.GetBytes(canonical.ToString()));
            canonical.Dispose();
            return new(
                artifact.Artifact,
                architecture,
                artifact.Path,
                digest,
                files,
                bytes,
                declaredEntrypoints.ToArray());
        }

        private string? Relative(string path) => path.StartsWith(artifact.Path + '/', StringComparison.Ordinal)
            ? path[(artifact.Path.Length + 1)..]
            : null;

        private static void RequireElfArchitecture(
            ReadOnlySpan<byte> header,
            RepositoryCiArchitecture architecture)
        {
            if (architecture == RepositoryCiArchitecture.Any) return;
            var machine = architecture switch
            {
                RepositoryCiArchitecture.LinuxX64 => 62,
                RepositoryCiArchitecture.LinuxArm64 => 183,
                _ => 0,
            };
            if (header.Length < 20 || !header[..4].SequenceEqual("\x7fELF"u8) ||
                header[4] != 2 || header[5] != 1 || header[6] != 1 ||
                header[18] != (byte)machine || header[19] != 0)
                throw new InvalidDataException("A CI artifact executable has the wrong ELF architecture.");
        }
    }

    private sealed record ArchiveEvidence(
        string Sha256,
        long Bytes,
        CiRunnerStoredArtifactEvidence[] Artifacts);

    private static PaxTarEntry TarEntry(TarEntryType type, string name, bool executable) => new(type, name)
    {
        Gid = 0,
        GroupName = string.Empty,
        Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite |
            (executable ? UnixFileMode.UserExecute : 0),
        ModificationTime = DateTimeOffset.UnixEpoch,
        Uid = 0,
        UserName = string.Empty,
    };

    private static IReadOnlyList<(FileSystemInfo Entry, string Relative)> Enumerate(string root)
    {
        var values = new List<(FileSystemInfo, string)>();
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new(root));
        while (pending.TryPop(out var directory))
        {
            foreach (var entry in directory.EnumerateFileSystemInfos())
            {
                if (values.Count == CiRunnerBuildKitExecutor.MaximumOutputFiles)
                    throw new InvalidDataException("The CI artifact export exceeded its entry bound.");
                var kind = CiRunnerBuildKitExecutor.FileKind(entry.FullName);
                if (kind == CiRunnerOutputFileKind.Directory && entry is DirectoryInfo child)
                    pending.Push(child);
                else if (kind != CiRunnerOutputFileKind.Regular || entry is not FileInfo)
                    throw new InvalidDataException("The CI artifact export contains a link or special file.");
                var relative = Path.GetRelativePath(root, entry.FullName);
                if (relative.Length is < 1 or > 4 * 1024 || relative.Split(Path.DirectorySeparatorChar)
                    .Any(static segment => segment is "" or "." or ".." || segment.Any(char.IsControl)))
                    throw new InvalidDataException("The CI artifact export contains an unsafe path.");
                values.Add((entry, relative));
            }
        }
        return values;
    }

    private static void EnsureAdmittedRoot(string root)
    {
        if (!Path.IsPathFullyQualified(root) || root.Any(char.IsControl) ||
            root == Path.GetPathRoot(root) || !Directory.Exists(root) ||
            new DirectoryInfo(root).LinkTarget is not null || HasLinkedParent(root))
            throw new InvalidDataException("The CI result export root is not an admitted private directory.");
    }

    private static bool HasLinkedParent(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.LinkTarget is not null) return true;
            current = current.Parent;
        }
        return false;
    }

    private static bool IsWithin(string root, string path)
    {
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedPath = Path.GetFullPath(path);
        return normalizedPath.StartsWith(normalizedRoot, StringComparison.Ordinal);
    }

    private async Task PutVerifiedAsync(
        string name,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        await objects.PutAsync(name, content, cancellationToken);
        var observed = await objects.GetAsync(name, cancellationToken);
        if (!observed.AsSpan().SequenceEqual(content.Span))
            throw new InvalidDataException("A durable CI result object failed readback verification.");
    }

    private static void ValidateEvidence(
        CiRunnerWorkloadEvidence value,
        ReadOnlyMemory<byte> log,
        string? exportDirectory,
        CiRunnerExecutionPlan? plan)
    {
        var succeeded = value.Succeeded;
        var failure = !succeeded;
        if (value.SchemaVersion != 1 || !Identity(value.Runner) || !Digest(value.PipelineDigest) ||
            !Identity(value.Job) || !Digest(value.JobDigest) || !Digest(value.ExecutionIdentityDigest) ||
            !Digest(value.PayloadDigest) || !Digest(value.SignatureDigest) || value.StreamSequence == 0 ||
            value.AcceptanceRevision == 0 || value.Attempt is < 1 or > 3 || value.LeaseSequence <= 0 ||
            !Digest(value.SourceBundleSha256) || value.LogBytes is < 0 or > 64L * 1024 * 1024 ||
            value.LogBytes != log.Length ||
            value.LogSha256.Length != 0 && (!Digest(value.LogSha256) ||
                Hash(log.Span) != value.LogSha256 || !CiRunnerLogRedactor.IsSafe(log.Span)) ||
            value.LogSha256.Length == 0 && !log.IsEmpty ||
            plan is not null && (plan.Digest != value.PlanDigest || plan.Job != value.Job ||
                plan.Attempt != value.Attempt) ||
            succeeded && (!Digest(value.PlanDigest) || !Digest(value.DescriptorSha256) ||
                !Digest(value.RecipeSha256) || value.BuildDisposition != CiRunnerBuildKitExecutionDisposition.Succeeded ||
                value.ExitCode != 0 || !Digest(value.LogSha256) || !Digest(value.MetadataSha256) ||
                !Digest(value.OutputSha256) || value.OutputFiles is < 1 or > CiRunnerBuildKitExecutor.MaximumOutputFiles ||
                value.OutputBytes < 1 || value.FailureKind != RepositoryCiJobFailureKind.Unspecified ||
                value.FailureCode != CiRunnerWorkloadFailureCode.Unspecified ||
                exportDirectory is null || !Path.IsPathFullyQualified(exportDirectory) || plan is null) ||
            failure && (value.FailureKind == RepositoryCiJobFailureKind.Unspecified ||
                !Enum.IsDefined(value.FailureKind) || value.FailureCode == CiRunnerWorkloadFailureCode.Unspecified ||
                !Enum.IsDefined(value.FailureCode) || value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Succeeded ||
                value.MetadataSha256.Length != 0 || value.OutputSha256.Length != 0 || value.OutputFiles != 0 ||
                value.OutputBytes != 0 || exportDirectory is not null || !ValidFailure(value)))
            throw new InvalidDataException("The CI workload evidence is internally inconsistent.");
    }

    private static bool ValidFailure(CiRunnerWorkloadEvidence value) => value.FailureCode switch
    {
        CiRunnerWorkloadFailureCode.PolicyRejected or CiRunnerWorkloadFailureCode.SourceRejected =>
            value.FailureKind == RepositoryCiJobFailureKind.PolicyDenied &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Unspecified && value.ExitCode == -1 &&
            value.LogSha256.Length == 0 && value.LogBytes == 0,
        CiRunnerWorkloadFailureCode.OutputRejected =>
            value.FailureKind == RepositoryCiJobFailureKind.WorkloadFailed &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Unspecified && value.ExitCode == -1 &&
            (value.LogSha256.Length == 0 && value.LogBytes == 0 || Digest(value.LogSha256)),
        CiRunnerWorkloadFailureCode.ProcessFailed =>
            value.FailureKind == RepositoryCiJobFailureKind.WorkloadFailed &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.ProcessFailed && value.ExitCode > 0 &&
            Digest(value.LogSha256),
        CiRunnerWorkloadFailureCode.TimedOut =>
            value.FailureKind == RepositoryCiJobFailureKind.WorkloadFailed &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.TimedOut && value.ExitCode == -1 &&
            Digest(value.LogSha256),
        CiRunnerWorkloadFailureCode.LogLimitExceeded =>
            value.FailureKind == RepositoryCiJobFailureKind.WorkloadFailed &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.LogLimitExceeded && value.ExitCode == -1 &&
            Digest(value.LogSha256),
        _ => false,
    };

    private static bool HasDuplicateProperties(byte[] payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        var fields = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) fields.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) fields.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                if (!fields.TryPeek(out var current) || reader.GetString() is not { } propertyName ||
                    !current.Add(propertyName))
                    return true;
            }
        }
        return fields.Count != 0;
    }

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static bool Digest(string? value) => RepositoryCiJobExecutionDocument.IsDigest(value);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private sealed class HashingReadStream(Stream inner) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long bytes;
        private bool completed;

        internal (string Sha256, long Bytes) Complete()
        {
            if (completed) throw new InvalidOperationException("The stream digest was already completed.");
            completed = true;
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), bytes);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            Capture(buffer.AsSpan(offset, read));
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = inner.Read(buffer);
            Capture(buffer[..read]);
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken);
            Capture(buffer.Span[..read]);
            return read;
        }

        private void Capture(ReadOnlySpan<byte> value)
        {
            hash.AppendData(value);
            bytes += value.Length;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) hash.Dispose();
            base.Dispose(disposing);
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class HashingWriteStream(Stream inner, long maximumBytes) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long bytes;
        private bool completed;

        internal (string Sha256, long Bytes) Complete()
        {
            if (completed) throw new InvalidOperationException("The stream digest was already completed.");
            completed = true;
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), bytes);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Capture(buffer);
            inner.Write(buffer);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Capture(buffer.Span);
            await inner.WriteAsync(buffer, cancellationToken);
        }

        private void Capture(ReadOnlySpan<byte> value)
        {
            if (value.Length > maximumBytes - bytes)
                throw new InvalidDataException("The CI artifact archive exceeded its disk budget.");
            hash.AppendData(value);
            bytes += value.Length;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) hash.Dispose();
            base.Dispose(disposing);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => bytes;
        public override long Position { get => bytes; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(CiRunnerResultManifest))]
[JsonSerializable(typeof(CiRunnerStoredWorkloadEvidence))]
internal sealed partial class CiRunnerDurableResultJsonContext : JsonSerializerContext;
