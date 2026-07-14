using System.Reflection;
using System.Runtime.CompilerServices;
using TerraScale.ReproduciblePublish;

namespace TerraScale.Orchestrator.ContractTests;

public sealed class ReproduciblePublishTests
{
    [Test]
    public async Task CliRequiresExactClosedArgumentsAndRidOrder()
    {
        await Assert.That(Program.TryParse(Arguments(), out var request)).IsTrue();
        await Assert.That(request!.Targets).IsEquivalentTo([PublishTarget.LinuxX64, PublishTarget.LinuxArm64]);
        await Assert.That(Program.TryParse(Arguments().Concat(["--unknown", "value"]).ToArray(), out _)).IsFalse();
        await Assert.That(Program.TryParse(Arguments(rids: ["linux-arm64", "linux-x64"]), out _)).IsFalse();
        await Assert.That(Program.TryParse(Arguments(rids: ["linux-x64", "freebsd-x64"]), out _)).IsFalse();
        await Assert.That(Program.TryParse(Arguments(configuration: "Debug"), out _)).IsFalse();
    }

    [Test]
    public async Task RootPolicyRejectsTraversalAliasesAndOverlap()
    {
        await Assert.That(PublishPathPolicy.ValidateRoots("/repo", "/out/first", "/out/second")).IsEqualTo(PublishFailureCode.None);
        await Assert.That(PublishPathPolicy.ValidateRoots("/repo", "/out/a/../same", "/out/same")).IsEqualTo(PublishFailureCode.RootAlias);
        await Assert.That(PublishPathPolicy.ValidateRoots("/repo", "/repo/out", "/out/second")).IsEqualTo(PublishFailureCode.SourceOutputOverlap);
        await Assert.That(PublishPathPolicy.ValidateRoots("/repo/child", "/repo", "/out/second")).IsEqualTo(PublishFailureCode.SourceOutputOverlap);
        await Assert.That(PublishPathPolicy.IsConfined("/out/root", "/out/rooted/file")).IsFalse();
    }

    [Test]
    public async Task ElfParserRejectsTruncationMagicClassEndianAndMachine()
    {
        await Assert.That(ElfVerifier.Verify([], PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.Truncated);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxX64, magic: false), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.MagicMismatch);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxX64, elfClass: 1), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.ClassMismatch);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxX64, endian: 2), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.EndiannessMismatch);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxArm64), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.MachineMismatch);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxX64, elfType: 1), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.TypeMismatch);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxX64), PublishTarget.LinuxX64)).IsEqualTo(ElfFailureCode.None);
        await Assert.That(ElfVerifier.Verify(Header(PublishTarget.LinuxArm64), PublishTarget.LinuxArm64)).IsEqualTo(ElfFailureCode.None);
    }

    [Test]
    public async Task ExactDoublePublishProducesCanonicalArchitectureResults()
    {
        var result = Evaluate();
        await Assert.That(result.Successful).IsTrue();
        await Assert.That(result.Artifacts.Count).IsEqualTo(2);
        await Assert.That(result.Artifacts.All(a => a.Reproducible)).IsTrue();
        await Assert.That(result.Artifacts[0].Sha256).IsNotEqualTo(result.Artifacts[1].Sha256);
        await Assert.That(result.TreeDigest).IsEqualTo(Tree);
    }

    [Test]
    public async Task RepeatDigestOrArchitectureCollisionFailsClosed()
    {
        var mismatch = Evaluate(repeatX64Digest: Digest('b'));
        var collision = Evaluate(x64Digest: Digest('c'), arm64Digest: Digest('c'));
        await Assert.That(mismatch.Failure).IsEqualTo(PublishFailureCode.RepeatDigestMismatch);
        await Assert.That(collision.Failure).IsEqualTo(PublishFailureCode.ArchitectureDigestCollision);
    }

    [Test]
    public async Task MissingExtraSymlinkNonregularAndEscapeOutputsReject()
    {
        var missing = Evaluate(firstX64Items: []);
        var extra = Evaluate(firstX64Items: [Item(PublishTarget.LinuxX64, FirstRoot, Digest('a')), new(Path.Combine(FirstRoot, "publish/linux-x64/extra"), OutputItemKind.RegularFile, 1, Digest('e'), Header(PublishTarget.LinuxX64), ExecutableMode)]);
        var symlink = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/terrascale-orchestrator"), OutputItemKind.SymbolicLink, 0, null, [], 0)]);
        var special = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/terrascale-orchestrator"), OutputItemKind.Other, 0, null, [], 0)]);
        var escaped = Evaluate(firstX64Items: [new("/outside/terrascale-orchestrator", OutputItemKind.RegularFile, 20, Digest('a'), Header(PublishTarget.LinuxX64), ExecutableMode)]);
        var nested = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/nested/terrascale-orchestrator"), OutputItemKind.RegularFile, 20, Digest('a'), Header(PublishTarget.LinuxX64), ExecutableMode)]);
        await Assert.That(missing.Failure).IsEqualTo(PublishFailureCode.MissingExecutable);
        await Assert.That(extra.Failure).IsEqualTo(PublishFailureCode.ExtraOutput);
        await Assert.That(symlink.Failure).IsEqualTo(PublishFailureCode.SymbolicLink);
        await Assert.That(special.Failure).IsEqualTo(PublishFailureCode.NonRegularOutput);
        await Assert.That(escaped.Failure).IsEqualTo(PublishFailureCode.PathOutsideRoot);
        await Assert.That(nested.Failure).IsEqualTo(PublishFailureCode.MissingExecutable);
    }

    [Test]
    public async Task ScriptsTextAndWrongArchitectureNeverPassAsExecutable()
    {
        var script = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/terrascale-orchestrator"), OutputItemKind.RegularFile, 20, Digest('a'), "#!/bin/sh"u8.ToArray(), ExecutableMode)]);
        var wrongMachine = Evaluate(firstX64Items: [Item(PublishTarget.LinuxArm64, FirstRoot, Digest('a'), pathTarget: PublishTarget.LinuxX64)]);
        var objectFile = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/terrascale-orchestrator"), OutputItemKind.RegularFile, 20, Digest('a'), Header(PublishTarget.LinuxX64, elfType: 1), ExecutableMode)]);
        var notExecutable = Evaluate(firstX64Items: [new(Path.Combine(FirstRoot, "publish/linux-x64/terrascale-orchestrator"), OutputItemKind.RegularFile, 20, Digest('a'), Header(PublishTarget.LinuxX64), UnixFileMode.UserRead)]);
        await Assert.That(script.Failure).IsEqualTo(PublishFailureCode.ElfTruncated);
        await Assert.That(wrongMachine.Failure).IsEqualTo(PublishFailureCode.ElfMachineMismatch);
        await Assert.That(objectFile.Failure).IsEqualTo(PublishFailureCode.ElfTypeMismatch);
        await Assert.That(notExecutable.Failure).IsEqualTo(PublishFailureCode.NotExecutable);
    }

    [Test]
    public async Task TimeoutCancellationNonzeroAndDiagnosticsAreClosedFailures()
    {
        await Assert.That(Evaluate(firstX64Process: Process(timedOut: true)).Failure).IsEqualTo(PublishFailureCode.ProcessTimeout);
        await Assert.That(Evaluate(firstX64Process: Process(cancelled: true)).Failure).IsEqualTo(PublishFailureCode.Cancelled);
        await Assert.That(Evaluate(firstX64Process: Process(exitCode: 7)).Failure).IsEqualTo(PublishFailureCode.ProcessNonZeroExit);
        await Assert.That(Evaluate(firstX64Process: Process(diagnosticsExceeded: true)).Failure).IsEqualTo(PublishFailureCode.DiagnosticLimitExceeded);
    }

    [Test]
    public async Task OutputRootAndRidObservationReplayCannotSubstitute()
    {
        var request = Request();
        var first = Runs(FirstRoot, Digest('a'), Digest('c')).ToArray();
        first[0] = new PublishRunObservation(PublishTarget.LinuxX64, "/other/publish/linux-x64", Process(), new(20), first[0].Items);
        var rootReplay = PublishObservationVerifier.Evaluate(request, first, Runs(RepeatRoot, Digest('a'), Digest('c')));
        var ridReplay = PublishObservationVerifier.Evaluate(request, Runs(FirstRoot, Digest('a'), Digest('c')).Reverse(), Runs(RepeatRoot, Digest('a'), Digest('c')));
        await Assert.That(rootReplay.Failure).IsEqualTo(PublishFailureCode.PathOutsideRoot);
        await Assert.That(ridReplay.Failure).IsEqualTo(PublishFailureCode.UnexpectedRid);
    }

    [Test]
    public async Task FixedPublishInvocationUsesArgumentListNoRestoreAndDeterministicProperties()
    {
        var invocation = ReproduciblePublisher.CreateInvocation(Request(), PublishTarget.LinuxArm64, "/out/repeat/publish/linux-arm64", "/out/repeat/input");
        var arguments = invocation.Arguments;
        await Assert.That(invocation.Failure).IsEqualTo(PublishFailureCode.None);
        await Assert.That(arguments).Contains("--no-restore");
        await Assert.That(arguments).DoesNotContain("restore");
        await Assert.That(arguments).Contains("linux-arm64");
        await Assert.That(arguments).Contains("--property:Deterministic=true");
        await Assert.That(arguments).Contains("--property:ContinuousIntegrationBuild=true");
        await Assert.That(arguments.Any(a => a.StartsWith("--property:PathMap=", StringComparison.Ordinal))).IsTrue();
        await Assert.That(arguments.Any(a => a.Contains(';') || a.Contains("&&", StringComparison.Ordinal))).IsFalse();
        await Assert.That(ReproduciblePublisher.CreateInvocation(Request(), (PublishTarget)0, "/out", "/input").Failure).IsEqualTo(PublishFailureCode.InvalidArgument);
    }

    [Test]
    public async Task ResultIsSecretSafeAndCannotBePubliclyForged()
    {
        var result = Evaluate(firstX64Process: new ProcessObservation(true, false, false, 0, 12, 34, false));
        var serialized = $"{result.Failure}|{result.TreeDigest.Sha256}|{result.StandardOutputCharacters}|{result.StandardErrorCharacters}|{string.Join(',', result.Artifacts.Select(a => $"{a.Rid}:{a.Sha256}"))}";
        await Assert.That(serialized).DoesNotContain("token");
        await Assert.That(serialized).DoesNotContain("password");
        await Assert.That(typeof(ReproduciblePublishResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(PublishArtifactResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(ReproduciblePublisher).Assembly.GetReferencedAssemblies().Any(a => a.Name!.Contains("Git", StringComparison.OrdinalIgnoreCase))).IsFalse();
    }

    [Test]
    public async Task SuccessfulPublishResultHasOnlyTheRealAsynchronousOriginatingPublicFactory()
    {
        var assembly = typeof(ReproduciblePublisher).Assembly;
        var resultReturningMembers = assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Select(method => (Type: type, Method: method)))
            .Where(candidate => ReturnsPublishResult(candidate.Method.ReturnType))
            .ToArray();
        var nonOriginatingClones = resultReturningMembers
            .Where(candidate => IsNonOriginatingResultClone(candidate.Type, candidate.Method))
            .ToArray();
        var originatingFactories = resultReturningMembers.Except(nonOriginatingClones).ToArray();

        await Assert.That(nonOriginatingClones).HasSingleItem();
        await Assert.That(originatingFactories).HasSingleItem();
        await Assert.That(originatingFactories[0].Type).IsEqualTo(typeof(ReproduciblePublisher));
        await Assert.That(originatingFactories[0].Method.Name).IsEqualTo(nameof(ReproduciblePublisher.RunAsync));
        await Assert.That(originatingFactories[0].Method.IsStatic).IsTrue();
        await Assert.That(originatingFactories[0].Method.ReturnType).IsEqualTo(typeof(Task<ReproduciblePublishResult>));
        await Assert.That(originatingFactories.Any(candidate =>
            candidate.Method.ReturnType == typeof(ReproduciblePublishResult))).IsFalse();
        await Assert.That(typeof(ReproduciblePublishResult).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(property => property.SetMethod is { IsPublic: true })).IsFalse();
        await Assert.That(assembly.GetExportedTypes().Any(type =>
            type.FullName == "TerraScale.ReproduciblePublish.PublishObservationVerifier")).IsFalse();
        await Assert.That(typeof(PublishObservationVerifier).IsNotPublic).IsTrue();
        await Assert.That(typeof(OutputItemObservation).IsPublic).IsTrue();

        var friends = assembly.GetCustomAttributes<InternalsVisibleToAttribute>()
            .Select(attribute => attribute.AssemblyName)
            .ToArray();
        await Assert.That(friends).IsEquivalentTo(["TerraScale.Orchestrator.ContractTests"]);
    }

    [Test]
    public async Task CliAndRealPublisherPublicSignaturesRemainExact()
    {
        var run = typeof(ReproduciblePublisher).GetMethod(nameof(ReproduciblePublisher.RunAsync),
            BindingFlags.Public | BindingFlags.Static);
        await Assert.That(run).IsNotNull();
        await Assert.That(run!.ReturnType).IsEqualTo(typeof(Task<ReproduciblePublishResult>));
        await Assert.That(run.GetParameters().Select(parameter => parameter.ParameterType))
            .IsEquivalentTo([typeof(ReproduciblePublishRequest), typeof(CancellationToken)]);

        var main = typeof(Program).GetMethod(nameof(Program.Main), BindingFlags.Public | BindingFlags.Static);
        await Assert.That(main).IsNotNull();
        await Assert.That(main!.ReturnType).IsEqualTo(typeof(Task<int>));
        await Assert.That(main.GetParameters().Select(parameter => parameter.ParameterType))
            .IsEquivalentTo([typeof(string[])]);

        var parse = typeof(Program).GetMethod(nameof(Program.TryParse), BindingFlags.Public | BindingFlags.Static);
        await Assert.That(parse).IsNotNull();
        await Assert.That(parse!.ReturnType).IsEqualTo(typeof(bool));
        await Assert.That(parse.GetParameters().Select(parameter => parameter.ParameterType))
            .IsEquivalentTo([typeof(IReadOnlyList<string>), typeof(ReproduciblePublishRequest).MakeByRefType()]);
    }

    [Test]
    public async Task InputTreeDigestAndQuantitiesRejectMalformedValues()
    {
        await Assert.That(Throws<ArgumentException>(() => new InputTreeDigest("mutable"))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new PositiveSeconds(0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new DiagnosticCharacterLimit(0))).IsTrue();
        await Assert.That(ArtifactDigest.Sha256("stable"u8)).IsEqualTo(ArtifactDigest.Sha256("stable"u8));
        await Assert.That(CopiedInputVerifier.Compare(Digest('a'), Digest('a'), new(Digest('a')))).IsEqualTo(PublishFailureCode.None);
        await Assert.That(CopiedInputVerifier.Compare(Digest('a'), Digest('b'), new(Digest('a')))).IsEqualTo(PublishFailureCode.InputCopyMismatch);
        await Assert.That(CopiedInputVerifier.Compare(Digest('a'), Digest('a'), new(Digest('b')))).IsEqualTo(PublishFailureCode.InputDigestMismatch);
    }

    [Test]
    public async Task CanonicalInputDigestCannotBeSubstituted()
    {
        var root = Path.Combine(Path.GetTempPath(), $"terrascale-input-digest-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(Path.Combine(root, "input.txt"), "first");
            var first = ReproduciblePublisher.ComputeInputTreeDigest(root);
            await File.WriteAllTextAsync(Path.Combine(root, "input.txt"), "second");
            var second = ReproduciblePublisher.ComputeInputTreeDigest(root);
            await Assert.That(first).IsNotEqualTo(second);
            await Assert.That(CopiedInputVerifier.Compare(second.Sha256, second.Sha256, first)).IsEqualTo(PublishFailureCode.InputDigestMismatch);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Test]
    public async Task DiagnosticDrainIsBoundedWhenPipeNeverCloses()
    {
        var started = DateTime.UtcNow;
        var heldOpen = new HeldOpenTextReader();
        var result = await BoundedDiagnosticDrain.ObserveAsync(heldOpen, new(100), new(1));
        await Assert.That(result.TimedOut).IsTrue();
        await Assert.That(result.LimitExceeded).IsFalse();
        await Assert.That(result.ReadFailed).IsFalse();
        await Assert.That(heldOpen.Disposed).IsTrue();
        await Assert.That(DateTime.UtcNow - started).IsLessThan(TimeSpan.FromSeconds(5));

        var limited = await BoundedDiagnosticDrain.ObserveAsync(new StringReader("too much output"), new(2), new(1));
        await Assert.That(limited.LimitExceeded).IsTrue();
        await Assert.That(limited.TimedOut).IsFalse();

        var failed = await BoundedDiagnosticDrain.ObserveAsync(new ThrowingTextReader(), new(100), new(1));
        await Assert.That(failed.ReadFailed).IsTrue();
        await Assert.That(failed.TimedOut).IsFalse();
    }

    [Test]
    public async Task BoundedRunAndItemEnumerablesFailClosed()
    {
        var tooManyTargets = new[] { PublishTarget.LinuxX64, PublishTarget.LinuxArm64, PublishTarget.LinuxX64 };
        await Assert.That(Throws<ArgumentException>(() => new ReproduciblePublishRequest(SourceRoot, FirstRoot, RepeatRoot, Tree, PublishConfiguration.Release, tooManyTargets, new(60), new(1000), new(20), 1))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new PublishRunObservation(PublishTarget.LinuxX64, "/out", Process(), new(1), [Item(PublishTarget.LinuxX64, "/out/../out", Digest('a')), Item(PublishTarget.LinuxX64, "/out/../out", Digest('b'))]))).IsTrue();
        var result = PublishObservationVerifier.Evaluate(Request(), ThrowingRuns(), Runs(RepeatRoot, Digest('a'), Digest('c')));
        await Assert.That(result.Failure).IsEqualTo(PublishFailureCode.IoFailure);
    }

    [Test]
    public async Task SymlinkDirectoryRootIsRejectedBeforeTraversal()
    {
        var root = Path.Combine(Path.GetTempPath(), $"terrascale-publish-test-{Guid.NewGuid():N}");
        try
        {
            var source = Path.Combine(root, "source");
            var actual = Path.Combine(root, "actual");
            Directory.CreateDirectory(Path.Combine(source, "src/TerraScale.Orchestrator"));
            Directory.CreateDirectory(actual);
            await File.WriteAllTextAsync(Path.Combine(source, "src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj"), "<Project />");
            var link = Path.Combine(root, "linked-output");
            Directory.CreateSymbolicLink(link, actual);
            var request = new ReproduciblePublishRequest(source, link, Path.Combine(root, "repeat"), Tree, PublishConfiguration.Release,
                [PublishTarget.LinuxX64, PublishTarget.LinuxArm64], new(1), new(100), new(10), 1);
            var result = await ReproduciblePublisher.RunAsync(request);
            await Assert.That(result.Failure).IsEqualTo(PublishFailureCode.SymbolicLink);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private const string SourceRoot = "/repo";
    private const string FirstRoot = "/out/first";
    private const string RepeatRoot = "/out/repeat";
    private static InputTreeDigest Tree { get; } = new(Digest('f'));

    private static ReproduciblePublishRequest Request() => new(SourceRoot, FirstRoot, RepeatRoot, Tree, PublishConfiguration.Release,
        [PublishTarget.LinuxX64, PublishTarget.LinuxArm64], new(60), new(1000), new(20), 1_700_000_000);

    private static ReproduciblePublishResult Evaluate(
        string? x64Digest = null, string? arm64Digest = null, string? repeatX64Digest = null,
        IEnumerable<OutputItemObservation>? firstX64Items = null, ProcessObservation? firstX64Process = null)
    {
        x64Digest ??= Digest('a'); arm64Digest ??= Digest('c'); repeatX64Digest ??= x64Digest;
        var first = Runs(FirstRoot, x64Digest, arm64Digest).ToArray();
        if (firstX64Items is not null) first[0] = new(PublishTarget.LinuxX64, Path.Combine(FirstRoot, "publish/linux-x64"), firstX64Process ?? Process(), new(20), firstX64Items);
        else if (firstX64Process is not null) first[0] = new(PublishTarget.LinuxX64, Path.Combine(FirstRoot, "publish/linux-x64"), firstX64Process, new(20), first[0].Items);
        return PublishObservationVerifier.Evaluate(Request(), first, Runs(RepeatRoot, repeatX64Digest, arm64Digest));
    }

    private static IEnumerable<PublishRunObservation> Runs(string root, string x64Digest, string armDigest) =>
    [
        new(PublishTarget.LinuxX64, Path.Combine(root, "publish/linux-x64"), Process(), new(20), [Item(PublishTarget.LinuxX64, root, x64Digest)]),
        new(PublishTarget.LinuxArm64, Path.Combine(root, "publish/linux-arm64"), Process(), new(20), [Item(PublishTarget.LinuxArm64, root, armDigest)]),
    ];

    private static OutputItemObservation Item(PublishTarget headerTarget, string root, string digest, PublishTarget? pathTarget = null) =>
        new(Path.Combine(root, "publish", Rid(pathTarget ?? headerTarget), "terrascale-orchestrator"), OutputItemKind.RegularFile, 4096, digest, Header(headerTarget), ExecutableMode);

    private static ProcessObservation Process(bool timedOut = false, bool cancelled = false, int exitCode = 0, bool diagnosticsExceeded = false) => new(true, timedOut, cancelled, exitCode, 0, 0, diagnosticsExceeded);

    private static byte[] Header(PublishTarget target, bool magic = true, byte elfClass = 2, byte endian = 1, ushort elfType = 2)
    {
        var bytes = new byte[20];
        if (magic) { bytes[0] = 0x7f; bytes[1] = (byte)'E'; bytes[2] = (byte)'L'; bytes[3] = (byte)'F'; }
        bytes[4] = elfClass; bytes[5] = endian;
        bytes[16] = (byte)(elfType & 0xff); bytes[17] = (byte)(elfType >> 8);
        var machine = Machine(target);
        bytes[18] = (byte)(machine & 0xff); bytes[19] = (byte)(machine >> 8);
        return bytes;
    }

    private static string[] Arguments(string[]? rids = null, string configuration = "Release") =>
    [
        "--source-root", SourceRoot, "--first-output-root", FirstRoot, "--repeat-output-root", RepeatRoot,
        "--tree-digest", Digest('f'), "--configuration", configuration,
        "--rid", (rids ?? ["linux-x64", "linux-arm64"])[0], "--rid", (rids ?? ["linux-x64", "linux-arm64"])[1],
        "--timeout-seconds", "60", "--diagnostic-character-limit", "1000", "--output-item-limit", "20", "--source-date-epoch", "1700000000",
    ];

    private static IEnumerable<PublishRunObservation> ThrowingRuns()
    {
        yield return Runs(FirstRoot, Digest('a'), Digest('c')).First();
        throw new IOException("synthetic enumeration failure");
    }

    private static string Rid(PublishTarget target) => target == PublishTarget.LinuxX64 ? "linux-x64" : "linux-arm64";
    private static ushort Machine(PublishTarget target) => target == PublishTarget.LinuxX64 ? (ushort)62 : (ushort)183;
    private static bool ReturnsPublishResult(Type type) => type == typeof(ReproduciblePublishResult) ||
        type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>) &&
        type.GetGenericArguments().Single() == typeof(ReproduciblePublishResult);
    private static bool IsNonOriginatingResultClone(Type type, MethodInfo method) =>
        type == typeof(ReproduciblePublishResult) && type.IsSealed && !method.IsStatic &&
        method.Name == "<Clone>$" && method.ReturnType == type && method.GetParameters().Length == 0;
    private const UnixFileMode ExecutableMode = UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute;

    private static string Digest(char value) => new(value, 64);
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }

    private sealed class HeldOpenTextReader : TextReader
    {
        private readonly TaskCompletionSource released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Disposed { get; private set; }

        public override async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
        {
            await released.Task;
            return 0;
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            released.TrySetResult();
            base.Dispose(disposing);
        }
    }

    private sealed class ThrowingTextReader : TextReader
    {
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default) => ValueTask.FromException<int>(new IOException("synthetic read failure"));
    }
}
