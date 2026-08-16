using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

internal sealed class RepositoryCiOciRegistryPublisherConfiguration
{
    internal RepositoryCiOciRegistryPublisherConfiguration(
        Uri registry,
        string namespacePrefix,
        string authFilePath,
        string? stagingRoot = null,
        TimeSpan? processTimeout = null,
        int maximumProcessOutputBytes = 64 * 1024,
        long maximumArchiveBytes = 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024)
    {
        Registry = registry ?? throw new ArgumentNullException(nameof(registry));
        NamespacePrefix = namespacePrefix ?? throw new ArgumentNullException(nameof(namespacePrefix));
        AuthFilePath = authFilePath ?? throw new ArgumentNullException(nameof(authFilePath));
        StagingRoot = stagingRoot;
        ProcessTimeout = processTimeout ?? TimeSpan.FromMinutes(5);
        MaximumProcessOutputBytes = maximumProcessOutputBytes;
        MaximumArchiveBytes = maximumArchiveBytes;
    }

    internal RepositoryCiOciRegistryPublisherConfiguration(
        string registry,
        string namespacePrefix,
        string authFilePath,
        string? stagingRoot = null,
        TimeSpan? processTimeout = null,
        int maximumProcessOutputBytes = 64 * 1024,
        long maximumArchiveBytes = 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024)
        : this(
            Uri.TryCreate(registry, UriKind.Absolute, out var parsed)
                ? parsed
                : throw new ArgumentException("The OCI registry URI is invalid.", nameof(registry)),
            namespacePrefix,
            authFilePath,
            stagingRoot,
            processTimeout,
            maximumProcessOutputBytes,
            maximumArchiveBytes)
    {
    }

    internal Uri Registry { get; }
    internal string NamespacePrefix { get; }
    internal string AuthFilePath { get; }
    internal string? StagingRoot { get; }
    internal TimeSpan ProcessTimeout { get; }
    internal int MaximumProcessOutputBytes { get; }
    internal long MaximumArchiveBytes { get; }
}

internal enum RepositoryCiOciRegistryPublicationDisposition
{
    Unspecified,
    Published,
    Duplicate,
    StaleAuthority,
    IdentityConflict,
}

internal sealed record RepositoryCiOciRegistryPublicationReceipt(
    RepositoryCiOciRegistryPublicationDisposition Disposition,
    string RegistryRepository = "",
    string Tag = "",
    string PublishedDigest = "");

internal enum RepositoryCiOciRegistryProcessOperation
{
    Inspect,
    Copy,
}

internal sealed record RepositoryCiOciRegistryProcessInvocation(
    RepositoryCiOciRegistryProcessOperation Operation,
    string Executable,
    IReadOnlyList<string> Arguments,
    TimeSpan Timeout,
    int MaximumOutputBytes);

internal enum RepositoryCiOciRegistryProcessDisposition
{
    Exited,
    TimedOut,
    OutputLimitExceeded,
}

internal sealed record RepositoryCiOciRegistryProcessResult(
    RepositoryCiOciRegistryProcessDisposition Disposition,
    int ExitCode,
    string StandardOutput,
    string StandardError);

internal interface IRepositoryCiOciRegistryProcess
{
    Task<RepositoryCiOciRegistryProcessResult> RunAsync(
        RepositoryCiOciRegistryProcessInvocation invocation,
        CancellationToken cancellationToken = default);
}

/// <summary>Runs the fixed skopeo executable without a shell and with bounded redacted output.</summary>
internal sealed class ProcessRepositoryCiOciRegistryProcess : IRepositoryCiOciRegistryProcess
{
    public async Task<RepositoryCiOciRegistryProcessResult> RunAsync(
        RepositoryCiOciRegistryProcessInvocation invocation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        if (invocation.Executable != RepositoryCiOciRegistryPublisher.ExecutablePath ||
            invocation.Arguments is null || invocation.Arguments.Count > 32 ||
            invocation.Timeout <= TimeSpan.Zero || invocation.MaximumOutputBytes is < 1 or > 1024 * 1024)
            throw new InvalidDataException("The OCI registry process invocation is invalid.");

        using var timeout = new CancellationTokenSource(invocation.Timeout);
        using var overflow = new CancellationTokenSource();
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token,
            overflow.Token);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(invocation.Executable)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in invocation.Arguments)
            process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment.Clear();

        process.Start();
        var standardOutput = CaptureAsync(
            process.StandardOutput,
            invocation.MaximumOutputBytes,
            stopping.Token,
            overflow);
        var standardError = CaptureAsync(
            process.StandardError,
            invocation.MaximumOutputBytes,
            stopping.Token,
            overflow);
        try
        {
            await ProcessLifecycle.WaitForExitAsync(process, stopping.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            await DrainAfterKillAsync(standardOutput, standardError);
            throw;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            TryKill(process);
            await DrainAfterKillAsync(standardOutput, standardError);
            return new(
                RepositoryCiOciRegistryProcessDisposition.TimedOut,
                -1,
                await CaptureAfterStopAsync(standardOutput),
                await CaptureAfterStopAsync(standardError));
        }
        catch (OperationCanceledException) when (overflow.IsCancellationRequested)
        {
            TryKill(process);
            await DrainAfterKillAsync(standardOutput, standardError);
            return new(
                RepositoryCiOciRegistryProcessDisposition.OutputLimitExceeded,
                -1,
                string.Empty,
                string.Empty);
        }

        var output = await standardOutput;
        var error = await standardError;
        return new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            process.ExitCode,
            output,
            error);
    }

    private static async Task<string> CaptureAsync(
        StreamReader reader,
        int maximumBytes,
        CancellationToken cancellationToken,
        CancellationTokenSource overflow)
    {
        var builder = new StringBuilder();
        var buffer = new char[4 * 1024];
        while (await reader.ReadAsync(buffer, cancellationToken) is var read && read > 0)
        {
            var value = new string(buffer, 0, read);
            if (Encoding.UTF8.GetByteCount(value) > maximumBytes - Encoding.UTF8.GetByteCount(builder.ToString()))
            {
                overflow.Cancel();
                throw new OperationCanceledException(overflow.Token);
            }
            builder.Append(value);
        }
        return Redact(builder.ToString());
    }

    private static async Task<string> CaptureAfterStopAsync(Task<string> capture)
    {
        try
        {
            return await capture;
        }
        catch (OperationCanceledException)
        {
            return string.Empty;
        }
        catch (InvalidDataException)
        {
            return string.Empty;
        }
    }

    private static string Redact(string value)
    {
        if (value.Length == 0) return value;
        var lines = value.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var lower = lines[index].ToLowerInvariant();
            if (lower.Contains("password", StringComparison.Ordinal) ||
                lower.Contains("token", StringComparison.Ordinal) ||
                lower.Contains("secret", StringComparison.Ordinal) ||
                lower.Contains("authorization", StringComparison.Ordinal))
                lines[index] = "[redacted]";
        }
        return string.Join('\n', lines);
    }

    private static async Task DrainAfterKillAsync(Task<string> output, Task<string> error)
    {
        try
        {
            await Task.WhenAll(output, error);
        }
        catch (OperationCanceledException)
        {
        }
        catch (InvalidDataException)
        {
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
    }
}

/// <summary>
/// Publishes a verified OCI archive through the fixed skopeo boundary. The registry is never
/// called until the archive has been staged, structurally validated, and authority rechecked.
/// </summary>
internal sealed class RepositoryCiOciRegistryPublisher : IRepositoryCiOciRegistryPublisher
{
    internal const string ExecutablePath = "/usr/bin/skopeo";
    private const long MaximumIndexBytes = 16L * 1024 * 1024;
    private const long MaximumBlobBytes = 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024;
    private const int MaximumEntries = 10_000;
    private const string LayoutVersion = "1.0.0";
    private readonly RepositoryCiOciRegistryPublisherConfiguration configuration;
    private readonly IRepositoryCiOciRegistryProcess process;

    internal RepositoryCiOciRegistryPublisher(
        RepositoryCiOciRegistryPublisherConfiguration configuration,
        IRepositoryCiOciRegistryProcess? process = null)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.process = process ?? new ProcessRepositoryCiOciRegistryProcess();
    }

    internal RepositoryCiOciRegistryPublisher(
        Uri registry,
        string namespacePrefix,
        string authFilePath,
        IRepositoryCiOciRegistryProcess? process = null,
        string? stagingRoot = null)
        : this(
            new RepositoryCiOciRegistryPublisherConfiguration(
                registry,
                namespacePrefix,
                authFilePath,
                stagingRoot),
            process)
    {
    }

    public async Task<RepositoryCiOciRegistryPublicationReceipt> PublishAsync(
        string artifactRepository,
        string candidateDigest,
        string archiveSha256,
        long archiveBytes,
        Func<Stream, CancellationToken, Task> copyArchive,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidateConfiguration();
        ValidateInputs(artifactRepository, candidateDigest, archiveSha256, archiveBytes);
        ArgumentNullException.ThrowIfNull(copyArchive);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (!authorityStillValid()) return new(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
        ValidateAuthFile(configuration.AuthFilePath);

        var repository = Repository(artifactRepository);
        var tag = candidateDigest;
        var destination = Destination(repository, tag);
        var staging = CreateStagingDirectory();
        try
        {
            var outerPath = Path.Combine(staging, "candidate.tar.gz");
            var imagePath = Path.Combine(staging, "image.tar");
            await StageAsync(outerPath, archiveBytes, archiveSha256, copyArchive, cancellationToken);
            ExtractImageArchive(outerPath, imagePath, configuration.MaximumArchiveBytes);
            var image = ValidateOciArchive(imagePath, configuration.MaximumArchiveBytes);
            var localDigest = image.Digest;

            var existing = await InspectAsync(destination, cancellationToken);
            if (existing is not null)
            {
                if (!StringComparer.Ordinal.Equals(existing, localDigest))
                    return new(
                        RepositoryCiOciRegistryPublicationDisposition.IdentityConflict,
                        repository,
                        tag,
                        existing);
                return authorityStillValid()
                    ? new(
                        RepositoryCiOciRegistryPublicationDisposition.Duplicate,
                        repository,
                        tag,
                        existing)
                    : new(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
            }

            if (!authorityStillValid())
                return new(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
            var copied = await RunAsync(
                RepositoryCiOciRegistryProcessOperation.Copy,
                [
                    "copy",
                    "--all",
                    "--preserve-digests",
                    "--authfile",
                    configuration.AuthFilePath,
                    $"oci-archive:{imagePath}:{image.SourceTag}",
                    destination,
                ],
                cancellationToken);
            RequireSuccess(copied, "OCI image upload");

            if (!authorityStillValid())
                return new(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
            var readback = await InspectAsync(destination, cancellationToken);
            if (readback is null || !StringComparer.Ordinal.Equals(readback, localDigest))
                return new(
                    RepositoryCiOciRegistryPublicationDisposition.IdentityConflict,
                    repository,
                    tag,
                    readback ?? string.Empty);
            if (!authorityStillValid())
                return new(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
            return new(
                RepositoryCiOciRegistryPublicationDisposition.Published,
                repository,
                tag,
                localDigest);
        }
        finally
        {
            DeleteStagingDirectory(staging);
        }
    }

    private async Task<string?> InspectAsync(string destination, CancellationToken cancellationToken)
    {
        var result = await RunAsync(
            RepositoryCiOciRegistryProcessOperation.Inspect,
            ["inspect", "--authfile", configuration.AuthFilePath, "--format", "{{.Digest}}", destination],
            cancellationToken);
        if (result.ExitCode == 0)
        {
            var value = result.StandardOutput.Trim();
            if (!DigestReference(value))
                throw new InvalidDataException("The OCI registry returned an invalid image digest.");
            return value;
        }
        if (IsAbsent(result)) return null;
        throw new IOException("The OCI registry inspection failed.");
    }

    private async Task<RepositoryCiOciRegistryProcessResult> RunAsync(
        RepositoryCiOciRegistryProcessOperation operation,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var invocation = new RepositoryCiOciRegistryProcessInvocation(
            operation,
            ExecutablePath,
            Array.AsReadOnly(arguments.ToArray()),
            configuration.ProcessTimeout,
            configuration.MaximumProcessOutputBytes);
        var result = await process.RunAsync(invocation, cancellationToken) ??
            throw new InvalidDataException("The OCI registry process returned no result.");
        if (result.StandardOutput is null || result.StandardError is null ||
            Encoding.UTF8.GetByteCount(result.StandardOutput) > configuration.MaximumProcessOutputBytes ||
            Encoding.UTF8.GetByteCount(result.StandardError) > configuration.MaximumProcessOutputBytes)
            throw new InvalidDataException("The OCI registry process output exceeded its bound.");
        if (result.Disposition != RepositoryCiOciRegistryProcessDisposition.Exited)
            throw result.Disposition == RepositoryCiOciRegistryProcessDisposition.TimedOut
                ? new TimeoutException("The OCI registry process timed out.")
                : new InvalidDataException("The OCI registry process output exceeded its bound.");
        if (result.ExitCode < 0)
            throw new InvalidDataException("The OCI registry process returned an invalid exit code.");
        return result;
    }

    private static void RequireSuccess(
        RepositoryCiOciRegistryProcessResult result,
        string operation)
    {
        if (result.ExitCode != 0)
            throw new IOException($"{operation} failed at the OCI registry boundary.");
    }

    private static bool IsAbsent(RepositoryCiOciRegistryProcessResult result)
    {
        var value = $"{result.StandardOutput}\n{result.StandardError}".ToLowerInvariant();
        return value.Contains("not found", StringComparison.Ordinal) ||
            value.Contains("manifest unknown", StringComparison.Ordinal) ||
            value.Contains("name unknown", StringComparison.Ordinal) ||
            value.Contains("does not exist", StringComparison.Ordinal) ||
            value.Contains("404", StringComparison.Ordinal) ||
            value.Contains("no such", StringComparison.Ordinal);
    }

    private string Repository(string artifactRepository)
    {
        var value = $"{configuration.NamespacePrefix.TrimEnd('/')}/{artifactRepository}".ToLowerInvariant();
        if (!ReferencePath(value))
            throw new InvalidDataException("The OCI repository reference is invalid.");
        return value;
    }

    private string Destination(string repository, string tag)
    {
        var authority = configuration.Registry.GetComponents(
            UriComponents.HostAndPort,
            UriFormat.UriEscaped);
        if (authority.Length == 0 || !ReferenceComponent(authority, allowColon: true))
            throw new InvalidDataException("The OCI registry authority is invalid.");
        return $"docker://{authority}/{repository}:{tag}";
    }

    private void ValidateConfiguration()
    {
        var registry = configuration.Registry;
        if (!registry.IsAbsoluteUri || registry.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(registry.UserInfo) || !string.IsNullOrEmpty(registry.Query) ||
            !string.IsNullOrEmpty(registry.Fragment) || registry.AbsolutePath is not ("" or "/") ||
            registry.Port is 0 or < -1 || !ReferenceComponent(registry.Host, allowColon: true))
            throw new InvalidDataException("The OCI registry URI is invalid or unsafe.");
        if (!ReferencePath(configuration.NamespacePrefix.TrimEnd('/')))
            throw new InvalidDataException("The OCI registry namespace is invalid or unsafe.");
        if (!SafeAbsolutePath(configuration.AuthFilePath, allowTrailingSeparator: false))
            throw new InvalidDataException("The OCI registry auth-file path is invalid.");
        if (configuration.ProcessTimeout <= TimeSpan.Zero || configuration.ProcessTimeout > TimeSpan.FromMinutes(10) ||
            configuration.MaximumProcessOutputBytes is < 256 or > 1024 * 1024 ||
            configuration.MaximumArchiveBytes is < 1 or > 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024)
            throw new InvalidDataException("The OCI registry publisher bounds are invalid.");
        if (configuration.StagingRoot is { } root && !SafeAbsolutePath(root, allowTrailingSeparator: true))
            throw new InvalidDataException("The OCI registry staging root is invalid.");
    }

    private static bool SafeAbsolutePath(string value, bool allowTrailingSeparator) =>
        Path.IsPathFullyQualified(value) && !value.Contains('\0') && !value.Contains('\\') &&
        (allowTrailingSeparator || !value.EndsWith(Path.DirectorySeparatorChar)) &&
        value.Replace(Path.DirectorySeparatorChar, '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .All(static segment => segment is not ("." or ".."));

    private static void ValidateInputs(
        string artifactRepository,
        string candidateDigest,
        string archiveSha256,
        long archiveBytes)
    {
        if (!ForgejoWebhookVerifier.IsRepository(artifactRepository))
            throw new ArgumentException("The OCI artifact repository identity is invalid.", nameof(artifactRepository));
        if (!RepositoryCiJobExecutionDocument.IsDigest(candidateDigest) ||
            !RepositoryCiJobExecutionDocument.IsDigest(archiveSha256))
            throw new ArgumentException("The OCI candidate or archive digest is invalid.");
        if (archiveBytes is < 1 or > 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(archiveBytes));
    }

    private static void ValidateAuthFile(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > 64 * 1024)
            throw new InvalidDataException("The OCI registry auth file is outside its size bound.");
        if (OperatingSystem.IsLinux())
        {
            var forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((File.GetUnixFileMode(path) & forbidden) != 0)
                throw new InvalidDataException("The OCI registry auth file must be owner-private.");
        }
    }

    private async Task StageAsync(
        string path,
        long expectedBytes,
        string expectedSha256,
        Func<Stream, CancellationToken, Task> copyArchive,
        CancellationToken cancellationToken)
    {
        await using var output = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await using var verified = new HashingWriteStream(output, expectedBytes);
        await copyArchive(verified, cancellationToken);
        var actual = verified.Complete();
        if (actual.Bytes != expectedBytes || actual.Sha256 != expectedSha256)
            throw new InvalidDataException("The OCI candidate archive differs from its durable evidence.");
    }

    private static void ExtractImageArchive(string outerPath, string imagePath, long maximumBytes)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var entries = 0;
        var expanded = 0L;
        var imageFound = false;
        var resultManifestFound = false;
        using var input = new FileStream(outerPath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024);
        using var gzip = new GZipStream(input, CompressionMode.Decompress, leaveOpen: false);
        using var reader = new TarReader(gzip, leaveOpen: false);
        using var image = new FileStream(
            imagePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.SequentialScan);
        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            if (++entries > MaximumEntries) throw new InvalidDataException("The OCI outer archive has too many entries.");
            var name = EntryName(entry);
            if (!seen.Add(name)) throw new InvalidDataException("The OCI outer archive contains duplicate paths.");
            switch (entry.EntryType)
            {
                case TarEntryType.Directory:
                    if (entry.Length != 0) throw new InvalidDataException("The OCI outer archive contains an invalid directory.");
                    break;
                case TarEntryType.RegularFile:
                case TarEntryType.V7RegularFile:
                    if (entry.DataStream is null || entry.Length < 1 ||
                        entry.Length > 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024 ||
                        expanded > maximumBytes - entry.Length)
                        throw new InvalidDataException("The OCI outer archive exceeds its expansion bound.");
                    if (name.EndsWith(".tar", StringComparison.Ordinal))
                    {
                        if (imageFound)
                            throw new InvalidDataException("The OCI outer archive must contain one nested image tar.");
                        entry.DataStream.CopyTo(image);
                        imageFound = true;
                    }
                    else if (name == "terrascale-ci-result-v2.json" && entry.Length <= MaximumIndexBytes)
                    {
                        entry.DataStream.CopyTo(Stream.Null);
                        resultManifestFound = true;
                    }
                    else
                    {
                        throw new InvalidDataException("The OCI outer archive contains an unexpected file.");
                    }
                    expanded += entry.Length;
                    break;
                default:
                    throw new InvalidDataException("The OCI outer archive contains a link or special file.");
            }
        }
        if (!imageFound || !resultManifestFound)
            throw new InvalidDataException("The OCI outer archive must contain one image tar and one CI result manifest.");
        image.Flush(flushToDisk: true);
    }

    private static OciImageSelection ValidateOciArchive(string imagePath, long maximumBytes)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var entries = 0;
        var expanded = 0L;
        byte[]? layout = null;
        byte[]? index = null;
        var blobs = new Dictionary<string, OciBlobObservation>(StringComparer.Ordinal);
        using var input = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024);
        using var reader = new TarReader(input, leaveOpen: false);
        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            if (++entries > MaximumEntries) throw new InvalidDataException("The OCI image archive has too many entries.");
            var name = EntryName(entry);
            if (!seen.Add(name)) throw new InvalidDataException("The OCI image archive contains duplicate paths.");
            switch (entry.EntryType)
            {
                case TarEntryType.Directory:
                    if (entry.Length != 0) throw new InvalidDataException("The OCI image archive contains an invalid directory.");
                    if (name is not ("blobs" or "blobs/sha256"))
                        throw new InvalidDataException("The OCI image archive contains an unexpected directory.");
                    break;
                case TarEntryType.RegularFile:
                case TarEntryType.V7RegularFile:
                    if (entry.Length is < 0 or > MaximumBlobBytes ||
                        expanded > maximumBytes - entry.Length || entry.DataStream is null)
                        throw new InvalidDataException("The OCI image archive exceeds its expansion bound.");
                    if (name is "oci-layout" or "index.json")
                    {
                        if (entry.Length > MaximumIndexBytes)
                            throw new InvalidDataException("The OCI OCI metadata is oversized.");
                        var content = ReadEntryBytes(entry, MaximumIndexBytes);
                        if (name == "oci-layout") layout = content;
                        else index = content;
                    }
                    else
                    {
                        var digest = BlobDigest(name);
                        if (digest is null)
                            throw new InvalidDataException("The OCI image archive contains an unexpected file.");
                        var observed = ObserveBlob(entry, digest);
                        if (!blobs.TryAdd(digest, observed))
                            throw new InvalidDataException("The OCI image archive contains duplicate blobs.");
                    }
                    expanded += entry.Length;
                    break;
                default:
                    throw new InvalidDataException("The OCI image archive contains a link or special file.");
            }
        }
        if (layout is null || index is null) throw new InvalidDataException("The OCI image archive metadata is incomplete.");
        ValidateLayout(layout);
        return ValidateIndex(imagePath, index, blobs);
    }

    private static void ValidateLayout(byte[] value)
    {
        using var document = ParseJson(value, 8);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The OCI layout is not an object.");
        var version = string.Empty;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!seen.Add(property.Name) || property.Name != "imageLayoutVersion" ||
                property.Value.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("The OCI layout is invalid.");
            version = property.Value.GetString() ?? string.Empty;
        }
        if (version != LayoutVersion) throw new InvalidDataException("The OCI layout version is unsupported.");
    }

    private static OciImageSelection ValidateIndex(
        string imagePath,
        byte[] value,
        IReadOnlyDictionary<string, OciBlobObservation> blobs)
    {
        using var document = ParseJson(value, 32);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The OCI index is not an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        JsonElement manifests = default;
        var schemaVersion = 0;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new InvalidDataException("The OCI index contains duplicate fields.");
            if (property.Name == "schemaVersion" && property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt32(out schemaVersion))
                continue;
            if (property.Name == "manifests" && property.Value.ValueKind == JsonValueKind.Array)
            {
                manifests = property.Value;
                continue;
            }
            if (property.Name == "mediaType" && property.Value.ValueKind == JsonValueKind.String &&
                IsIndexMediaType(property.Value.GetString() ?? string.Empty))
                continue;
            if (property.Name == "annotations" && property.Value.ValueKind == JsonValueKind.Object)
                continue;
            throw new InvalidDataException("The OCI index contains an unsupported field.");
        }
        if (schemaVersion != 2 || manifests.ValueKind != JsonValueKind.Array ||
            manifests.GetArrayLength() is < 1 or > 128)
            throw new InvalidDataException("The OCI index is missing its tagged image descriptor.");
        var declared = new Dictionary<string, OciDescriptor>(StringComparer.Ordinal);
        var tags = new HashSet<string>(StringComparer.Ordinal);
        foreach (var descriptor in manifests.EnumerateArray())
        {
            var descriptorValue = ReadDescriptor(descriptor, requirePlatform: false);
            if (!IsIndexMediaType(descriptorValue.MediaType) ||
                descriptorValue.RefName is not { } tag || !ReferenceTag(tag) || !tags.Add(tag))
                throw new InvalidDataException("The OCI root index descriptor is not a unique tagged image index.");
            if (declared.Count == 0)
                declared.Add(descriptorValue.Digest, descriptorValue);
            else
            {
                var identity = declared.Values.Single();
                if (identity.Digest != descriptorValue.Digest || identity.Size != descriptorValue.Size ||
                    identity.MediaType != descriptorValue.MediaType)
                    throw new InvalidDataException("The OCI archive tags do not identify one immutable image index.");
            }
        }
        var selected = declared.Values.Single();
        var platformDescriptors = ParseNestedIndex(ReadBlob(imagePath, selected.Digest, blobs));
        if (platformDescriptors.Count != 2 || platformDescriptors.Any(static descriptor =>
                !IsManifestMediaType(descriptor.MediaType) || descriptor.Os is null || descriptor.Architecture is null) ||
            !platformDescriptors.Any(static descriptor => descriptor.Os == "linux" && descriptor.Architecture == "amd64") ||
            !platformDescriptors.Any(static descriptor => descriptor.Os == "linux" && descriptor.Architecture == "arm64"))
            throw new InvalidDataException("The selected OCI image index must contain linux/amd64 and linux/arm64 manifests only.");
        var reachable = new HashSet<string>(StringComparer.Ordinal);
        var declaredByDigest = new Dictionary<string, OciDescriptor>(StringComparer.Ordinal);
        foreach (var descriptor in declared.Values)
            TraverseDescriptor(
                imagePath,
                blobs,
                descriptor,
                reachable,
                declaredByDigest,
                new HashSet<string>(StringComparer.Ordinal),
                depth: 0);
        if (!blobs.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(reachable))
            throw new InvalidDataException("The OCI image archive contains an orphan or unreachable blob.");
        return new($"sha256:{selected.Digest}", tags.Order(StringComparer.Ordinal).First());
    }

    private static void TraverseDescriptor(
        string imagePath,
        IReadOnlyDictionary<string, OciBlobObservation> blobs,
        OciDescriptor descriptor,
        HashSet<string> reachable,
        Dictionary<string, OciDescriptor> declaredByDigest,
        HashSet<string> visiting,
        int depth)
    {
        if (depth > 16) throw new InvalidDataException("The OCI descriptor graph is too deep.");
        if (!declaredByDigest.TryGetValue(descriptor.Digest, out var previous))
            declaredByDigest.Add(descriptor.Digest, descriptor);
        else if (previous.Size != descriptor.Size || previous.MediaType != descriptor.MediaType)
            throw new InvalidDataException("The OCI descriptor identity changed across references.");
        if (!blobs.TryGetValue(descriptor.Digest, out var observed) || observed.Bytes != descriptor.Size)
            throw new InvalidDataException("The OCI descriptor blob is missing or has the wrong size.");
        if (visiting.Contains(descriptor.Digest))
            throw new InvalidDataException("The OCI descriptor graph contains a cycle.");
        if (!reachable.Add(descriptor.Digest))
            return;
        visiting.Add(descriptor.Digest);
        try
        {
            if (IsIndexMediaType(descriptor.MediaType))
            {
                var index = ParseNestedIndex(ReadBlob(imagePath, descriptor.Digest, blobs));
                foreach (var child in index)
                    TraverseDescriptor(
                        imagePath,
                        blobs,
                        child,
                        reachable,
                        declaredByDigest,
                        visiting,
                        depth + 1);
            }
            else if (IsManifestMediaType(descriptor.MediaType))
            {
                var manifest = ParseManifest(ReadBlob(imagePath, descriptor.Digest, blobs));
                TraverseDescriptor(
                    imagePath,
                    blobs,
                    manifest.Config,
                    reachable,
                    declaredByDigest,
                    visiting,
                    depth + 1);
                foreach (var layer in manifest.Layers)
                    TraverseDescriptor(
                        imagePath,
                        blobs,
                        layer,
                        reachable,
                        declaredByDigest,
                        visiting,
                        depth + 1);
            }
            else if (IsConfigMediaType(descriptor.MediaType) || IsLayerMediaType(descriptor.MediaType))
            {
                // Config and layer descriptors are verified by their canonical blob path,
                // declared length, and content digest. They are graph leaves.
            }
            else
            {
                throw new InvalidDataException("The OCI root graph contains an unsupported descriptor.");
            }
        }
        finally
        {
            visiting.Remove(descriptor.Digest);
        }
    }

    private static IReadOnlyList<OciDescriptor> ParseNestedIndex(byte[] value)
    {
        using var document = ParseJson(value, 32);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The nested OCI index is not an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        JsonElement manifests = default;
        var schemaVersion = 0;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new InvalidDataException("The nested OCI index contains duplicate fields.");
            if (property.Name == "schemaVersion" && property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt32(out schemaVersion))
                continue;
            if (property.Name == "manifests" && property.Value.ValueKind == JsonValueKind.Array)
            {
                manifests = property.Value;
                continue;
            }
            if (property.Name == "mediaType" && property.Value.ValueKind == JsonValueKind.String &&
                IsIndexMediaType(property.Value.GetString() ?? string.Empty))
                continue;
            if (property.Name == "annotations" && property.Value.ValueKind == JsonValueKind.Object)
                continue;
            throw new InvalidDataException("The nested OCI index contains an unsupported field.");
        }
        if (schemaVersion != 2 || manifests.ValueKind != JsonValueKind.Array ||
            manifests.GetArrayLength() is < 1 or > 128)
            throw new InvalidDataException("The nested OCI index is invalid.");
        var values = new List<OciDescriptor>(manifests.GetArrayLength());
        foreach (var manifest in manifests.EnumerateArray())
        {
            var descriptor = ReadDescriptor(manifest, requirePlatform: true);
            if (!IsIndexMediaType(descriptor.MediaType) && !IsManifestMediaType(descriptor.MediaType))
                throw new InvalidDataException("The nested OCI descriptor media type is invalid.");
            values.Add(descriptor);
        }
        return values;
    }

    private static OciManifest ParseManifest(byte[] value)
    {
        using var document = ParseJson(value, 32);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The OCI image manifest is not an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        JsonElement config = default;
        JsonElement layers = default;
        var schemaVersion = 0;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new InvalidDataException("The OCI image manifest contains duplicate fields.");
            if (property.Name == "schemaVersion" && property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt32(out schemaVersion))
                continue;
            if (property.Name == "config" && property.Value.ValueKind == JsonValueKind.Object)
            {
                config = property.Value;
                continue;
            }
            if (property.Name == "layers" && property.Value.ValueKind == JsonValueKind.Array)
            {
                layers = property.Value;
                continue;
            }
            if (property.Name is "mediaType" or "annotations")
                continue;
            throw new InvalidDataException("The OCI image manifest contains an unsupported field.");
        }
        if (schemaVersion != 2 || config.ValueKind != JsonValueKind.Object ||
            layers.ValueKind != JsonValueKind.Array || layers.GetArrayLength() > 10_000)
            throw new InvalidDataException("The OCI image manifest is invalid.");
        var configDescriptor = ReadDescriptor(config, requirePlatform: false);
        if (!IsConfigMediaType(configDescriptor.MediaType))
            throw new InvalidDataException("The OCI config media type is invalid.");
        var layerDescriptors = new List<OciDescriptor>(layers.GetArrayLength());
        foreach (var layer in layers.EnumerateArray())
        {
            var descriptor = ReadDescriptor(layer, requirePlatform: false);
            if (!IsLayerMediaType(descriptor.MediaType))
                throw new InvalidDataException("The OCI layer media type is invalid.");
            layerDescriptors.Add(descriptor);
        }
        return new(configDescriptor, layerDescriptors);
    }

    private static OciDescriptor ReadDescriptor(JsonElement value, bool requirePlatform)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The OCI descriptor is not an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var digest = string.Empty;
        var mediaType = string.Empty;
        long size = -1;
        JsonElement platform = default;
        string? refName = null;
        foreach (var property in value.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new InvalidDataException("The OCI descriptor contains duplicate fields.");
            if (property.Name == "digest" && property.Value.ValueKind == JsonValueKind.String)
                digest = property.Value.GetString() ?? string.Empty;
            else if (property.Name == "mediaType" && property.Value.ValueKind == JsonValueKind.String)
                mediaType = property.Value.GetString() ?? string.Empty;
            else if (property.Name == "size" && property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt64(out var declaredSize))
                size = declaredSize;
            else if (property.Name == "platform" && property.Value.ValueKind == JsonValueKind.Object)
                platform = property.Value;
            else if (property.Name == "annotations" && property.Value.ValueKind == JsonValueKind.Object)
            {
                var annotationNames = new HashSet<string>(StringComparer.Ordinal);
                foreach (var annotation in property.Value.EnumerateObject())
                {
                    if (!annotationNames.Add(annotation.Name) || annotation.Value.ValueKind != JsonValueKind.String)
                        throw new InvalidDataException("The OCI descriptor annotations are invalid.");
                    if (annotation.Name == "org.opencontainers.image.ref.name")
                        refName = annotation.Value.GetString();
                }
            }
            else if (property.Name is not ("urls" or "artifactType" or "data"))
                throw new InvalidDataException("The OCI descriptor contains an unsupported field.");
        }
        if (!DigestReference(digest) || size < 0 || size > MaximumBlobBytes ||
            !IsSafeMediaType(mediaType) || requirePlatform && platform.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The OCI descriptor identity is invalid.");
        string? os = null;
        string? architecture = null;
        if (platform.ValueKind == JsonValueKind.Object)
        {
            var platformSeen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in platform.EnumerateObject())
            {
                if (!platformSeen.Add(property.Name))
                    throw new InvalidDataException("The OCI platform contains duplicate fields.");
                if (property.Name == "os" && property.Value.ValueKind == JsonValueKind.String)
                    os = property.Value.GetString();
                else if (property.Name == "architecture" && property.Value.ValueKind == JsonValueKind.String)
                    architecture = property.Value.GetString();
                else if (property.Name is not ("os.version" or "os.features" or "variant"))
                    throw new InvalidDataException("The OCI platform contains an unsupported field.");
            }
        }
        if (requirePlatform && (os is null || architecture is null))
            throw new InvalidDataException("The OCI root descriptor lacks a platform.");
        return new(digest[7..], size, mediaType, os, architecture, refName);
    }

    private static byte[] ReadBlob(
        string imagePath,
        string digest,
        IReadOnlyDictionary<string, OciBlobObservation> blobs)
    {
        if (!blobs.TryGetValue(digest, out var expected) || expected.Bytes > MaximumIndexBytes)
            throw new InvalidDataException("The OCI descriptor blob is missing or oversized.");
        using var input = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024);
        using var reader = new TarReader(input, leaveOpen: false);
        var path = $"blobs/sha256/{digest}";
        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            if (EntryName(entry) != path || entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                continue;
            if (entry.DataStream is null || entry.Length != expected.Bytes)
                throw new InvalidDataException("The OCI descriptor blob length changed.");
            return ReadEntryBytes(entry, MaximumIndexBytes);
        }
        throw new InvalidDataException("The OCI descriptor blob is missing.");
    }

    private static byte[] ReadEntryBytes(TarEntry entry, long maximumBytes)
    {
        if (entry.DataStream is null || entry.Length is < 0 or > int.MaxValue ||
            entry.Length > maximumBytes)
            throw new InvalidDataException("The OCI archive entry is oversized.");
        using var content = new MemoryStream(checked((int)entry.Length));
        entry.DataStream.CopyTo(content);
        if (content.Length != entry.Length)
            throw new InvalidDataException("The OCI archive entry was truncated.");
        return content.ToArray();
    }

    private static OciBlobObservation ObserveBlob(TarEntry entry, string digest)
    {
        if (entry.DataStream is null || entry.Length < 0)
            throw new InvalidDataException("The OCI blob entry is invalid.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long bytes = 0;
        while (entry.DataStream.Read(buffer, 0, buffer.Length) is var read && read > 0)
        {
            bytes = checked(bytes + read);
            hash.AppendData(buffer, 0, read);
        }
        if (bytes != entry.Length)
            throw new InvalidDataException("The OCI blob entry was truncated.");
        var observed = Convert.ToHexStringLower(hash.GetHashAndReset());
        if (observed != digest)
            throw new InvalidDataException("The OCI blob path does not match its content digest.");
        return new(bytes);
    }

    private static string? BlobDigest(string name)
    {
        const string prefix = "blobs/sha256/";
        if (!name.StartsWith(prefix, StringComparison.Ordinal))
            return null;
        var digest = name[prefix.Length..];
        return digest.Length == 64 && digest.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f')
            ? digest
            : null;
    }

    private static bool IsSafeMediaType(string value) =>
        value is { Length: >= 1 and <= 256 } &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '/' or '+' or '-' or '_');

    private static bool IsIndexMediaType(string value) => value is
        "application/vnd.oci.image.index.v1+json" or
        "application/vnd.docker.distribution.manifest.list.v2+json";

    private static bool IsManifestMediaType(string value) => value is
        "application/vnd.oci.image.manifest.v1+json" or
        "application/vnd.docker.distribution.manifest.v2+json";

    private static bool IsConfigMediaType(string value) => value is
        "application/vnd.oci.image.config.v1+json" or
        "application/vnd.docker.container.image.v1+json";

    private static bool IsLayerMediaType(string value) => value is
        "application/vnd.oci.image.layer.v1.tar" or
        "application/vnd.oci.image.layer.v1.tar+gzip" or
        "application/vnd.oci.image.layer.v1.tar+zstd" or
        "application/vnd.docker.image.rootfs.diff.tar" or
        "application/vnd.docker.image.rootfs.diff.tar.gzip";

    private static bool ReferenceTag(string value) => value is { Length: >= 1 and <= 128 } &&
        (value[0] is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_') &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '_' or '.' or '-');

    private static JsonDocument ParseJson(byte[] value, int maximumDepth)
    {
        try
        {
            return JsonDocument.Parse(value, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = maximumDepth,
            });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The OCI metadata is invalid JSON.", exception);
        }
    }

    private sealed record OciBlobObservation(long Bytes);

    private sealed record OciDescriptor(
        string Digest,
        long Size,
        string MediaType,
        string? Os,
        string? Architecture,
        string? RefName);

    private sealed record OciImageSelection(string Digest, string SourceTag);

    private sealed record OciManifest(
        OciDescriptor Config,
        IReadOnlyList<OciDescriptor> Layers);

    private static string EntryName(TarEntry entry)
    {
        if (entry.Name is not { Length: > 0 and <= 1024 } name || name.Contains('\\') || name.StartsWith('/'))
            throw new InvalidDataException("The OCI archive contains an unsafe path.");
        var normalized = name.TrimEnd('/');
        if (normalized.Length == 0 || normalized.Split('/').Any(static segment => segment is "" or "." or ".."))
            throw new InvalidDataException("The OCI archive contains a traversal path.");
        return normalized;
    }

    private static bool ReferencePath(string value) =>
        value is { Length: >= 1 and <= 512 } &&
        value.Split('/').All(static segment => ReferenceComponent(segment, allowColon: false));

    private static bool ReferenceComponent(string value, bool allowColon) =>
        value is { Length: >= 1 and <= 256 } &&
        value[0] != '.' && value[^1] != '.' &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-' ||
            allowColon && character == ':');

    private static bool DigestReference(string value) =>
        value is { Length: 71 } && value.StartsWith("sha256:", StringComparison.Ordinal) &&
        RepositoryCiJobExecutionDocument.IsDigest(value[7..]);

    private string CreateStagingDirectory()
    {
        var root = configuration.StagingRoot ?? Path.GetTempPath();
        Directory.CreateDirectory(root);
        var rootInfo = new DirectoryInfo(root);
        if (rootInfo.LinkTarget is not null)
            throw new InvalidDataException("The OCI staging root cannot be linked.");
        var path = Path.Combine(rootInfo.FullName, $"terrascale-oci-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static void DeleteStagingDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch
        {
        }
    }

    private sealed class HashingWriteStream(Stream destination, long maximumBytes) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool completed;

        internal long Bytes { get; private set; }

        internal (string Sha256, long Bytes) Complete()
        {
            if (completed) throw new InvalidOperationException("The OCI archive digest was already completed.");
            completed = true;
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), Bytes);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Capture(buffer);
            destination.Write(buffer);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Capture(buffer.Span);
            return destination.WriteAsync(buffer, cancellationToken);
        }

        private void Capture(ReadOnlySpan<byte> value)
        {
            if (value.Length > maximumBytes - Bytes)
                throw new InvalidDataException("The OCI archive exceeded its declared length.");
            hash.AppendData(value);
            Bytes += value.Length;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) hash.Dispose();
            base.Dispose(disposing);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Bytes;
        public override long Position { get => Bytes; set => throw new NotSupportedException(); }
        public override void Flush() => destination.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

internal interface IRepositoryCiOciRegistryPublisher
{
    Task<RepositoryCiOciRegistryPublicationReceipt> PublishAsync(
        string artifactRepository,
        string candidateDigest,
        string archiveSha256,
        long archiveBytes,
        Func<Stream, CancellationToken, Task> copyArchive,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default);
}
