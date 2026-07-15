using System.Collections.ObjectModel;

namespace TerraScale.ReproduciblePublish;

public static class PublishPathPolicy
{
    public static PublishFailureCode ValidateRoots(string sourceRoot, string firstOutputRoot, string repeatOutputRoot)
    {
        string source;
        string first;
        string repeat;
        try
        {
            source = Normalize(sourceRoot);
            first = Normalize(firstOutputRoot);
            repeat = Normalize(repeatOutputRoot);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return PublishFailureCode.InvalidArgument;
        }

        if (StringComparer.Ordinal.Equals(first, repeat)) return PublishFailureCode.RootAlias;
        if (Contains(source, first) || Contains(first, source) || Contains(source, repeat) || Contains(repeat, source))
            return PublishFailureCode.SourceOutputOverlap;
        return PublishFailureCode.None;
    }

    public static bool IsConfined(string root, string candidate)
    {
        var canonicalRoot = Normalize(root);
        var canonicalCandidate = Normalize(candidate);
        return StringComparer.Ordinal.Equals(canonicalRoot, canonicalCandidate) || Contains(canonicalRoot, canonicalCandidate);
    }

    public static string Normalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static bool Contains(string parent, string child)
    {
        if (!child.StartsWith(parent, StringComparison.Ordinal) || child.Length <= parent.Length) return false;
        return child[parent.Length] == Path.DirectorySeparatorChar;
    }
}

public static class ElfVerifier
{
    public static ElfFailureCode Verify(ReadOnlySpan<byte> header, PublishTarget target)
    {
        if (!Enum.IsDefined(target)) return ElfFailureCode.MachineMismatch;
        if (header.Length < 20) return ElfFailureCode.Truncated;
        if (header[0] != 0x7f || header[1] != (byte)'E' || header[2] != (byte)'L' || header[3] != (byte)'F') return ElfFailureCode.MagicMismatch;
        if (header[4] != 2) return ElfFailureCode.ClassMismatch;
        if (header[5] != 1) return ElfFailureCode.EndiannessMismatch;
        var type = (ushort)(header[16] | (header[17] << 8));
        if (type is not 2 and not 3) return ElfFailureCode.TypeMismatch;
        var machine = (ushort)(header[18] | (header[19] << 8));
        return machine == PublishTargetCatalog.ElfMachine(target) ? ElfFailureCode.None : ElfFailureCode.MachineMismatch;
    }
}

public static class CopiedInputVerifier
{
    public static PublishFailureCode Compare(string firstSha256, string repeatSha256, InputTreeDigest expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (!IsDigest(firstSha256) || !IsDigest(repeatSha256)) return PublishFailureCode.InvalidTreeDigest;
        if (!StringComparer.Ordinal.Equals(firstSha256, repeatSha256)) return PublishFailureCode.InputCopyMismatch;
        return StringComparer.Ordinal.Equals(firstSha256, expected.Sha256) ? PublishFailureCode.None : PublishFailureCode.InputDigestMismatch;
    }

    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal static class PublishObservationVerifier
{
    private const string ExecutableName = "terrascale-orchestrator";

    internal static ReproduciblePublishResult Evaluate(
        ReproduciblePublishRequest request,
        IEnumerable<PublishRunObservation> firstRuns,
        IEnumerable<PublishRunObservation> repeatRuns)
    {
        ArgumentNullException.ThrowIfNull(request);
        PublishRunObservation[] first;
        PublishRunObservation[] repeat;
        try
        {
            first = BoundedMaterializer.Take(firstRuns, (ulong)request.Targets.Count + 1, nameof(firstRuns)).ToArray();
            repeat = BoundedMaterializer.Take(repeatRuns, (ulong)request.Targets.Count + 1, nameof(repeatRuns)).ToArray();
        }
        catch (ArgumentException) { return new ReproduciblePublishResult(request.TreeDigest, PublishFailureCode.IoFailure, Array.Empty<PublishArtifactResult>(), 0, 0); }
        var rootFailure = PublishPathPolicy.ValidateRoots(request.SourceRoot, request.FirstOutputRoot, request.RepeatOutputRoot);
        if (rootFailure != PublishFailureCode.None) return Failure(request, rootFailure, first, repeat);
        if (!first.Select(r => r.Target).SequenceEqual(request.Targets) || !repeat.Select(r => r.Target).SequenceEqual(request.Targets))
            return Failure(request, PublishFailureCode.UnexpectedRid, first, repeat);

        var artifacts = new List<PublishArtifactResult>();
        foreach (var target in request.Targets)
        {
            var firstRun = first.Single(r => r.Target == target);
            var repeatRun = repeat.Single(r => r.Target == target);
            if (!ExpectedOutputRoot(request.FirstOutputRoot, firstRun.OutputRoot, target) || !ExpectedOutputRoot(request.RepeatOutputRoot, repeatRun.OutputRoot, target))
                return Failure(request, PublishFailureCode.PathOutsideRoot, first, repeat);
            var processFailure = ProcessFailure(firstRun.Process);
            if (processFailure != PublishFailureCode.None) return Failure(request, processFailure, first, repeat);
            processFailure = ProcessFailure(repeatRun.Process);
            if (processFailure != PublishFailureCode.None) return Failure(request, processFailure, first, repeat);

            var firstArtifact = ValidateOutput(firstRun, target, out var firstFailure);
            if (firstFailure != PublishFailureCode.None) return Failure(request, firstFailure, first, repeat);
            var repeatArtifact = ValidateOutput(repeatRun, target, out var repeatFailure);
            if (repeatFailure != PublishFailureCode.None) return Failure(request, repeatFailure, first, repeat);
            if (!StringComparer.Ordinal.Equals(firstArtifact!.Sha256, repeatArtifact!.Sha256) || firstArtifact.ByteLength != repeatArtifact.ByteLength)
                return Failure(request, PublishFailureCode.RepeatDigestMismatch, first, repeat);
            artifacts.Add(new PublishArtifactResult(target, PublishTargetCatalog.Rid(target), firstArtifact.ByteLength, firstArtifact.Sha256!, repeatArtifact.Sha256!));
        }

        if (StringComparer.Ordinal.Equals(artifacts[0].Sha256, artifacts[1].Sha256))
            return Failure(request, PublishFailureCode.ArchitectureDigestCollision, first, repeat);
        var counts = DiagnosticCounts(first, repeat);
        return new ReproduciblePublishResult(request.TreeDigest, PublishFailureCode.None, new ReadOnlyCollection<PublishArtifactResult>(artifacts), counts.Stdout, counts.Stderr);
    }

    private static OutputItemObservation? ValidateOutput(PublishRunObservation run, PublishTarget target, out PublishFailureCode failure)
    {
        foreach (var item in run.Items)
        {
            if (!PublishPathPolicy.IsConfined(run.OutputRoot, item.CanonicalPath)) { failure = PublishFailureCode.PathOutsideRoot; return null; }
            if (item.Kind == OutputItemKind.SymbolicLink) { failure = PublishFailureCode.SymbolicLink; return null; }
            if (item.Kind is not OutputItemKind.RegularFile and not OutputItemKind.Directory) { failure = PublishFailureCode.NonRegularOutput; return null; }
        }

        var files = run.Items.Where(i => i.Kind == OutputItemKind.RegularFile).ToArray();
        var exactExecutablePath = PublishPathPolicy.Normalize(Path.Combine(run.OutputRoot, ExecutableName));
        var executable = files.Where(i => StringComparer.Ordinal.Equals(PublishPathPolicy.Normalize(i.CanonicalPath), exactExecutablePath)).ToArray();
        if (executable.Length == 0) { failure = PublishFailureCode.MissingExecutable; return null; }
        if (files.Length != 1 || executable.Length != 1) { failure = PublishFailureCode.ExtraOutput; return null; }
        var executeBits = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
        if ((executable[0].UnixFileMode & executeBits) == 0) { failure = PublishFailureCode.NotExecutable; return null; }
        if (!IsDigest(executable[0].Sha256)) { failure = PublishFailureCode.InvalidArgument; return null; }
        failure = ElfFailure(ElfVerifier.Verify(executable[0].ElfHeader.ToArray(), target));
        return failure == PublishFailureCode.None ? executable[0] : null;
    }

    private static PublishFailureCode ProcessFailure(ProcessObservation process)
    {
        if (process.Cancelled) return PublishFailureCode.Cancelled;
        if (process.TimedOut) return PublishFailureCode.ProcessTimeout;
        if (process.DiagnosticReadFailed) return PublishFailureCode.IoFailure;
        if (!process.Started || process.ExitCode != 0) return PublishFailureCode.ProcessNonZeroExit;
        if (process.DiagnosticLimitExceeded) return PublishFailureCode.DiagnosticLimitExceeded;
        return PublishFailureCode.None;
    }

    private static PublishFailureCode ElfFailure(ElfFailureCode failure) => failure switch
    {
        ElfFailureCode.None => PublishFailureCode.None,
        ElfFailureCode.Truncated => PublishFailureCode.ElfTruncated,
        ElfFailureCode.MagicMismatch => PublishFailureCode.ElfMagicMismatch,
        ElfFailureCode.ClassMismatch => PublishFailureCode.ElfClassMismatch,
        ElfFailureCode.EndiannessMismatch => PublishFailureCode.ElfEndiannessMismatch,
        ElfFailureCode.MachineMismatch => PublishFailureCode.ElfMachineMismatch,
        ElfFailureCode.TypeMismatch => PublishFailureCode.ElfTypeMismatch,
        _ => PublishFailureCode.InvalidArgument,
    };

    private static ReproduciblePublishResult Failure(ReproduciblePublishRequest request, PublishFailureCode failure, IReadOnlyList<PublishRunObservation> first, IReadOnlyList<PublishRunObservation> repeat)
    {
        var counts = DiagnosticCounts(first, repeat);
        return new ReproduciblePublishResult(request.TreeDigest, failure, Array.Empty<PublishArtifactResult>(), counts.Stdout, counts.Stderr);
    }

    private static (ulong Stdout, ulong Stderr) DiagnosticCounts(IReadOnlyList<PublishRunObservation> first, IReadOnlyList<PublishRunObservation> repeat)
    {
        ulong stdout = 0;
        ulong stderr = 0;
        foreach (var run in first.Concat(repeat))
        {
            stdout = SaturatingAdd(stdout, run.Process.StandardOutputCharacters);
            stderr = SaturatingAdd(stderr, run.Process.StandardErrorCharacters);
        }
        return (stdout, stderr);
    }

    private static ulong SaturatingAdd(ulong left, ulong right) => ulong.MaxValue - left < right ? ulong.MaxValue : left + right;
    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool ExpectedOutputRoot(string parent, string observed, PublishTarget target) => StringComparer.Ordinal.Equals(PublishPathPolicy.Normalize(Path.Combine(parent, "publish", PublishTargetCatalog.Rid(target))), PublishPathPolicy.Normalize(observed));
}
