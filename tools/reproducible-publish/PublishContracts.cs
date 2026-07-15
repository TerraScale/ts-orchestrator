using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace TerraScale.ReproduciblePublish;

public enum PublishTarget { LinuxX64 = 1, LinuxArm64 = 2 }
public enum PublishConfiguration { Release = 1 }
public enum OutputItemKind { RegularFile = 1, Directory = 2, SymbolicLink = 3, Other = 4 }
public enum PublishFailureCode
{
    None = 0,
    InvalidArgument = 1,
    InvalidTreeDigest = 2,
    UnexpectedRid = 3,
    PathOutsideRoot = 4,
    RootAlias = 5,
    SourceOutputOverlap = 6,
    OutputRootNotEmpty = 7,
    SymbolicLink = 8,
    NonRegularOutput = 9,
    MissingExecutable = 10,
    ExtraOutput = 11,
    ElfTruncated = 12,
    ElfMagicMismatch = 13,
    ElfClassMismatch = 14,
    ElfEndiannessMismatch = 15,
    ElfMachineMismatch = 16,
    ProcessTimeout = 17,
    ProcessNonZeroExit = 18,
    DiagnosticLimitExceeded = 19,
    RepeatDigestMismatch = 20,
    ArchitectureDigestCollision = 21,
    IoFailure = 22,
    Cancelled = 23,
    ElfTypeMismatch = 24,
    NotExecutable = 25,
    OutputItemLimitExceeded = 26,
    InputCopyMismatch = 27,
    InputDigestMismatch = 28,
}

public enum ElfFailureCode { None = 0, Truncated = 1, MagicMismatch = 2, ClassMismatch = 3, EndiannessMismatch = 4, MachineMismatch = 5, TypeMismatch = 6 }

public sealed record InputTreeDigest
{
    public InputTreeDigest(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        if (sha256.Length != 64 || sha256.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("Tree digest must be canonical SHA-256.", nameof(sha256));
        Sha256 = sha256;
    }
    public string Sha256 { get; }
}

public sealed record PositiveSeconds
{
    public PositiveSeconds(uint value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public uint Value { get; }
}

public sealed record DiagnosticCharacterLimit
{
    public DiagnosticCharacterLimit(uint value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public uint Value { get; }
}

public sealed record OutputItemLimit
{
    public OutputItemLimit(uint value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public uint Value { get; }
}

public sealed record ReproduciblePublishRequest
{
    public ReproduciblePublishRequest(
        string sourceRoot,
        string firstOutputRoot,
        string repeatOutputRoot,
        InputTreeDigest treeDigest,
        PublishConfiguration configuration,
        IEnumerable<PublishTarget> targets,
        PositiveSeconds timeout,
        DiagnosticCharacterLimit diagnosticLimit,
        OutputItemLimit outputItemLimit,
        long sourceDateEpoch)
    {
        SourceRoot = RequiredPath(sourceRoot, nameof(sourceRoot));
        FirstOutputRoot = RequiredPath(firstOutputRoot, nameof(firstOutputRoot));
        RepeatOutputRoot = RequiredPath(repeatOutputRoot, nameof(repeatOutputRoot));
        TreeDigest = treeDigest ?? throw new ArgumentNullException(nameof(treeDigest));
        Configuration = Enum.IsDefined(configuration) ? configuration : throw new ArgumentOutOfRangeException(nameof(configuration));
        Targets = BoundedMaterializer.Take(targets, 2, nameof(targets));
        if (!Targets.SequenceEqual([PublishTarget.LinuxX64, PublishTarget.LinuxArm64]))
            throw new ArgumentException("Expected targets are exactly linux-x64 then linux-arm64.", nameof(targets));
        Timeout = timeout ?? throw new ArgumentNullException(nameof(timeout));
        DiagnosticLimit = diagnosticLimit ?? throw new ArgumentNullException(nameof(diagnosticLimit));
        OutputItemLimit = outputItemLimit ?? throw new ArgumentNullException(nameof(outputItemLimit));
        SourceDateEpoch = sourceDateEpoch >= 0 ? sourceDateEpoch : throw new ArgumentOutOfRangeException(nameof(sourceDateEpoch));
    }

    public string SourceRoot { get; }
    public string FirstOutputRoot { get; }
    public string RepeatOutputRoot { get; }
    public InputTreeDigest TreeDigest { get; }
    public PublishConfiguration Configuration { get; }
    public IReadOnlyList<PublishTarget> Targets { get; }
    public PositiveSeconds Timeout { get; }
    public DiagnosticCharacterLimit DiagnosticLimit { get; }
    public OutputItemLimit OutputItemLimit { get; }
    public long SourceDateEpoch { get; }

    private static string RequiredPath(string value, string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, name);
        if (value.IndexOf('\0') >= 0) throw new ArgumentException("Path contains NUL.", name);
        return value;
    }
}

public sealed record OutputItemObservation
{
    public OutputItemObservation(string canonicalPath, OutputItemKind kind, long byteLength, string? sha256, IEnumerable<byte> elfHeader, UnixFileMode unixFileMode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalPath);
        CanonicalPath = canonicalPath;
        Kind = Enum.IsDefined(kind) ? kind : throw new ArgumentOutOfRangeException(nameof(kind));
        ByteLength = byteLength >= 0 ? byteLength : throw new ArgumentOutOfRangeException(nameof(byteLength));
        Sha256 = sha256;
        ElfHeader = new ReadOnlyCollection<byte>((elfHeader ?? throw new ArgumentNullException(nameof(elfHeader))).Take(64).ToArray());
        UnixFileMode = unixFileMode;
    }
    public string CanonicalPath { get; }
    public OutputItemKind Kind { get; }
    public long ByteLength { get; }
    public string? Sha256 { get; }
    public IReadOnlyList<byte> ElfHeader { get; }
    public UnixFileMode UnixFileMode { get; }
}

public sealed record ProcessObservation
{
    public ProcessObservation(bool started, bool timedOut, bool cancelled, int exitCode, ulong standardOutputCharacters, ulong standardErrorCharacters, bool diagnosticLimitExceeded, bool diagnosticReadFailed = false)
    { Started = started; TimedOut = timedOut; Cancelled = cancelled; ExitCode = exitCode; StandardOutputCharacters = standardOutputCharacters; StandardErrorCharacters = standardErrorCharacters; DiagnosticLimitExceeded = diagnosticLimitExceeded; DiagnosticReadFailed = diagnosticReadFailed; }
    public bool Started { get; }
    public bool TimedOut { get; }
    public bool Cancelled { get; }
    public int ExitCode { get; }
    public ulong StandardOutputCharacters { get; }
    public ulong StandardErrorCharacters { get; }
    public bool DiagnosticLimitExceeded { get; }
    public bool DiagnosticReadFailed { get; }
    public bool Successful => Started && !TimedOut && !Cancelled && ExitCode == 0 && !DiagnosticLimitExceeded && !DiagnosticReadFailed;
}

public sealed record PublishRunObservation
{
    public PublishRunObservation(PublishTarget target, string outputRoot, ProcessObservation process, OutputItemLimit itemLimit, IEnumerable<OutputItemObservation> items)
    { Target = Enum.IsDefined(target) ? target : throw new ArgumentOutOfRangeException(nameof(target)); OutputRoot = Path.GetFullPath(outputRoot ?? throw new ArgumentNullException(nameof(outputRoot))); Process = process ?? throw new ArgumentNullException(nameof(process)); ItemLimit = itemLimit ?? throw new ArgumentNullException(nameof(itemLimit)); Items = BoundedMaterializer.Take(items, ItemLimit.Value, nameof(items)); }
    public PublishTarget Target { get; }
    public string OutputRoot { get; }
    public ProcessObservation Process { get; }
    public OutputItemLimit ItemLimit { get; }
    public IReadOnlyList<OutputItemObservation> Items { get; }
}

public sealed record PublishArtifactResult
{
    internal PublishArtifactResult(PublishTarget target, string rid, long byteLength, string sha256, string repeatSha256)
    { Target = target; Rid = rid; ByteLength = byteLength; Sha256 = sha256; RepeatSha256 = repeatSha256; }
    public PublishTarget Target { get; }
    public string Rid { get; }
    public long ByteLength { get; }
    public string Sha256 { get; }
    public string RepeatSha256 { get; }
    public bool Reproducible => StringComparer.Ordinal.Equals(Sha256, RepeatSha256);
}

public sealed record ReproduciblePublishResult
{
    internal ReproduciblePublishResult(InputTreeDigest treeDigest, PublishFailureCode failure, IReadOnlyList<PublishArtifactResult> artifacts, ulong stdoutCharacters, ulong stderrCharacters)
    { TreeDigest = treeDigest; Failure = failure; Artifacts = artifacts; StandardOutputCharacters = stdoutCharacters; StandardErrorCharacters = stderrCharacters; }
    public InputTreeDigest TreeDigest { get; }
    public PublishFailureCode Failure { get; }
    public IReadOnlyList<PublishArtifactResult> Artifacts { get; }
    public ulong StandardOutputCharacters { get; }
    public ulong StandardErrorCharacters { get; }
    public bool Successful => Failure == PublishFailureCode.None && Artifacts.Count == 2 && Artifacts.All(a => a.Reproducible);
}

internal static class PublishTargetCatalog
{
    public static string Rid(PublishTarget target) => target switch { PublishTarget.LinuxX64 => "linux-x64", PublishTarget.LinuxArm64 => "linux-arm64", _ => throw new ArgumentOutOfRangeException(nameof(target)) };
    public static ushort ElfMachine(PublishTarget target) => target switch { PublishTarget.LinuxX64 => 62, PublishTarget.LinuxArm64 => 183, _ => throw new ArgumentOutOfRangeException(nameof(target)) };
}

public sealed record PublishInvocation
{
    internal PublishInvocation(PublishFailureCode failure, IReadOnlyList<string> arguments) { Failure = failure; Arguments = arguments; }
    public PublishFailureCode Failure { get; }
    public IReadOnlyList<string> Arguments { get; }
}

internal static class BoundedMaterializer
{
    public static IReadOnlyList<T> Take<T>(IEnumerable<T>? source, ulong limit, string name)
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = new List<T>();
        try
        {
            foreach (var value in source)
            {
                if ((ulong)values.Count >= limit) throw new ArgumentException("Enumerable exceeds its closed bound.", name);
                if (value is null) throw new ArgumentException("Null item.", name);
                values.Add(value);
            }
        }
        catch (ArgumentException) { throw; }
        catch (Exception exception) { throw new ArgumentException("Enumerable failed during bounded consumption.", name, exception); }
        return new ReadOnlyCollection<T>(values);
    }
}

public static class ArtifactDigest
{
    public static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}
