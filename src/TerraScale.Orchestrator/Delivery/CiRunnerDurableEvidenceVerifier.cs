using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

internal interface IRepositoryCiJobResultEvidenceVerifier
{
    Task<bool> VerifyAsync(
        RepositoryCiJobExecutionSnapshot execution,
        CancellationToken cancellationToken);
}

/// <summary>Verifies the canonical runner evidence object before controller state trusts it.</summary>
internal sealed class CiRunnerDurableEvidenceVerifier(IDeliveryObjectStore objects)
    : IRepositoryCiJobResultEvidenceVerifier
{
    private const int MaximumEvidenceBytes = 64 * 1024;
    private const int MaximumOutputFiles = 10_000;
    private const long MaximumOutputBytes = 2L * 1024 * 1024 * 1024;
    private const long ArtifactArchiveOverheadBytes = 64L * 1024 * 1024;
    private readonly IDeliveryObjectStore objects = objects ?? throw new ArgumentNullException(nameof(objects));

    public async Task<bool> VerifyAsync(
        RepositoryCiJobExecutionSnapshot execution,
        CancellationToken cancellationToken) =>
        await ReadVerifiedAsync(execution, cancellationToken) is not null;

    internal async Task<CiRunnerStoredWorkloadEvidence?> ReadVerifiedAsync(
        RepositoryCiJobExecutionSnapshot execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        if (execution.Phase is not (RepositoryCiJobExecutionPhase.Succeeded or
                RepositoryCiJobExecutionPhase.Failed) || !Digest(execution.EvidenceDigest))
            return null;
        var content = await objects.GetAsync(
            $"ci-result-evidence-{execution.EvidenceDigest}",
            cancellationToken);
        if (content.Length is < 1 or > MaximumEvidenceBytes ||
            Hash(content) != execution.EvidenceDigest || HasDuplicateProperties(content))
            return null;

        CiRunnerStoredWorkloadEvidence? stored;
        try
        {
            stored = JsonSerializer.Deserialize(
                content,
                CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);
        }
        catch (JsonException)
        {
            return null;
        }
        return stored is not null && Matches(execution, stored) &&
            await VerifyObjectsAsync(stored, cancellationToken)
                ? stored
                : null;
    }

    private async Task<bool> VerifyObjectsAsync(
        CiRunnerStoredWorkloadEvidence stored,
        CancellationToken cancellationToken)
    {
        if (stored.LogBytes > 0)
        {
            var log = await objects.GetAsync(stored.LogObject, cancellationToken);
            if (log.LongLength != stored.LogBytes || Hash(log) != stored.LogSha256 ||
                !CiRunnerLogRedactor.IsSafe(log))
                return false;
        }

        if (stored.ArtifactBytes == 0) return true;
        using var observed = new BoundedHashingStream(stored.ArtifactBytes);
        try
        {
            await objects.CopyToAsync(stored.ArtifactObject, observed, cancellationToken);
        }
        catch (InvalidDataException)
        {
            return false;
        }
        var artifact = observed.Complete();
        return artifact.Bytes == stored.ArtifactBytes && artifact.Sha256 == stored.ArtifactSha256;
    }

    private static bool Matches(
        RepositoryCiJobExecutionSnapshot execution,
        CiRunnerStoredWorkloadEvidence stored)
    {
        var expected = execution.Document;
        var workload = stored.Workload;
        if (stored.SchemaVersion != 2 || stored.RetentionDays != CiRunnerDurableResultSink.RetentionDays ||
            stored.LogObject is null || stored.LogSha256 is null || stored.ArtifactObject is null ||
            stored.ArtifactSha256 is null || workload is null || workload.SchemaVersion != 1 ||
            workload.Runner != expected.Runner ||
            workload.PipelineDigest != expected.PipelineDigest || workload.Job != expected.Job ||
            workload.JobDigest != expected.JobDigest ||
            workload.ExecutionIdentityDigest != expected.ExecutionIdentityDigest ||
            workload.PayloadDigest != expected.PayloadDigest ||
            workload.SignatureDigest != expected.SignatureDigest ||
            workload.StreamSequence != expected.StreamSequence ||
            workload.AcceptanceRevision != expected.AcceptanceRevision || workload.Attempt != expected.Attempt ||
            workload.LeaseSequence != expected.LeaseSequence ||
            workload.Succeeded != (execution.Phase == RepositoryCiJobExecutionPhase.Succeeded) ||
            workload.FailureKind != execution.FailureKind ||
            stored.RequiredTestSkips != execution.RequiredTestSkips || !ValidWorkload(workload))
            return false;

        var logMatches = workload.LogSha256.Length == 0
            ? stored.LogObject.Length == 0 && stored.LogSha256.Length == 0 && stored.LogBytes == 0
            : stored.LogObject == $"ci-result-log-{workload.LogSha256}" &&
                stored.LogSha256 == workload.LogSha256 && stored.LogBytes == workload.LogBytes;
        var artifactMatches = workload.Succeeded
            ? stored.ArtifactObject == $"ci-result-artifact-{workload.OutputSha256}" &&
                Digest(stored.ArtifactSha256) && stored.ArtifactBytes > 0 &&
                stored.ArtifactBytes <= workload.OutputBytes + ArtifactArchiveOverheadBytes &&
                ValidArtifacts(stored.Artifacts ?? [], workload)
            : stored.ArtifactObject.Length == 0 && stored.ArtifactSha256.Length == 0 &&
                stored.ArtifactBytes == 0 && stored.RequiredTestSkips == 0 &&
                (stored.Artifacts?.Length ?? 0) == 0;
        return logMatches && artifactMatches;
    }

    private static bool ValidArtifacts(
        CiRunnerStoredArtifactEvidence[] artifacts,
        CiRunnerWorkloadEvidence workload)
    {
        if (artifacts.Length > 2 || artifacts.Any(static value => value is null) ||
            !artifacts.SequenceEqual(artifacts.OrderBy(static value => value.Architecture)))
            return false;
        if (artifacts.Select(static value => value.Architecture).Distinct().Count() != artifacts.Length ||
            artifacts.Select(static value => value.Path).Distinct(StringComparer.Ordinal).Count() != artifacts.Length ||
            artifacts.Any(left => artifacts.Any(right => left != right &&
                right.Path.StartsWith(left.Path + '/', StringComparison.Ordinal))))
            return false;
        long bytes = 0;
        var files = 0;
        foreach (var artifact in artifacts)
        {
            if (!ArtifactId(artifact.Artifact) || artifact.Architecture is not (
                    RepositoryCiArchitecture.Any or RepositoryCiArchitecture.LinuxX64 or
                    RepositoryCiArchitecture.LinuxArm64) || !RelativePath(artifact.Path) ||
                !Digest(artifact.Digest) || artifact.Files is < 1 or > MaximumOutputFiles ||
                artifact.Bytes is < 1 or > MaximumOutputBytes ||
                !RepositoryCiArtifactAttestation.TryEntrypointsDigest(
                    artifact.Architecture,
                    artifact.Entrypoints,
                    out _) ||
                bytes > workload.OutputBytes - artifact.Bytes ||
                files > workload.OutputFiles - artifact.Files)
                return false;
            bytes += artifact.Bytes;
            files += artifact.Files;
        }
        return bytes <= workload.OutputBytes && files <= workload.OutputFiles;
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

    private static bool ValidWorkload(CiRunnerWorkloadEvidence value)
    {
        if (value.LogSha256 is null || value.MetadataSha256 is null || value.OutputSha256 is null ||
            value.PlanDigest is null || value.SourceBundleSha256 is null || value.DescriptorSha256 is null ||
            value.RecipeSha256 is null)
            return false;
        if (!Identity(value.Runner) || !Digest(value.PipelineDigest) || !Identity(value.Job) ||
            !Digest(value.JobDigest) || !Digest(value.ExecutionIdentityDigest) || !Digest(value.PayloadDigest) ||
            !Digest(value.SignatureDigest) || value.StreamSequence == 0 || value.AcceptanceRevision == 0 ||
            value.Attempt is < 1 or > 3 || value.LeaseSequence <= 0 || !Digest(value.SourceBundleSha256) ||
            value.LogBytes is < 0 or > 64L * 1024 * 1024 ||
            value.LogSha256.Length != 0 && !Digest(value.LogSha256))
            return false;
        if (value.Succeeded)
            return Digest(value.PlanDigest) && Digest(value.DescriptorSha256) && Digest(value.RecipeSha256) &&
                value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Succeeded && value.ExitCode == 0 &&
                Digest(value.LogSha256) && Digest(value.MetadataSha256) && Digest(value.OutputSha256) &&
                value.OutputFiles is >= 1 and <= MaximumOutputFiles &&
                value.OutputBytes is > 0 and <= MaximumOutputBytes &&
                value.FailureKind == RepositoryCiJobFailureKind.Unspecified &&
                value.FailureCode == CiRunnerWorkloadFailureCode.Unspecified;
        return value.FailureKind != RepositoryCiJobFailureKind.Unspecified &&
            Enum.IsDefined(value.FailureKind) && value.FailureCode != CiRunnerWorkloadFailureCode.Unspecified &&
            Enum.IsDefined(value.FailureCode) &&
            value.BuildDisposition != CiRunnerBuildKitExecutionDisposition.Succeeded &&
            value.MetadataSha256.Length == 0 && value.OutputSha256.Length == 0 && value.OutputFiles == 0 &&
            value.OutputBytes == 0 && ValidFailure(value);
    }

    private static bool ValidFailure(CiRunnerWorkloadEvidence value) => value.FailureCode switch
    {
        CiRunnerWorkloadFailureCode.PolicyRejected or CiRunnerWorkloadFailureCode.SourceRejected =>
            value.FailureKind == RepositoryCiJobFailureKind.PolicyDenied &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Unspecified && value.ExitCode == -1 &&
            value.LogSha256.Length == 0 && value.LogBytes == 0,
        CiRunnerWorkloadFailureCode.OutputRejected =>
            value.FailureKind == RepositoryCiJobFailureKind.WorkloadFailed &&
            value.BuildDisposition == CiRunnerBuildKitExecutionDisposition.Unspecified && value.ExitCode == -1,
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
        try
        {
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.StartObject) fields.Push(new(StringComparer.Ordinal));
                else if (reader.TokenType == JsonTokenType.EndObject) fields.Pop();
                else if (reader.TokenType == JsonTokenType.PropertyName &&
                    !fields.Peek().Add(reader.GetString()!))
                    return true;
            }
        }
        catch (JsonException)
        {
            return true;
        }
        return fields.Count != 0;
    }

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static bool Digest(string? value) => RepositoryCiJobExecutionDocument.IsDigest(value);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private sealed class BoundedHashingStream(long maximumBytes) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long bytes;
        private bool completed;

        internal (string Sha256, long Bytes) Complete()
        {
            if (completed) throw new InvalidOperationException("The object digest was already completed.");
            completed = true;
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), bytes);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Capture(buffer);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Capture(buffer.Span);
            return ValueTask.CompletedTask;
        }

        private void Capture(ReadOnlySpan<byte> value)
        {
            if (value.Length > maximumBytes - bytes)
                throw new InvalidDataException("The durable CI result object exceeded its bound.");
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
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
