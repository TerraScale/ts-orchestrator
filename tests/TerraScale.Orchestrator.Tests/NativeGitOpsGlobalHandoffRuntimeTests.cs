using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalHandoffRuntimeTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task SignedProtectedMainUsesOneExactLeaseAndThirtyDayWindow()
    {
        var authority = Authority(7);
        var signer = new TestSigner();
        string? repository = null;
        string? branch = null;
        string? commit = null;
        long epoch = 0;
        DateTimeOffset issuedAt = default;
        DateTimeOffset expiresAt = default;
        INativeGitOpsCellSpecSigner? observedSigner = null;
        Func<bool>? stillValid = null;
        var runtime = new NativeGitOpsGlobalHandoffRuntime(
            (valueRepository, valueBranch, valueCommit, valueEpoch, valueIssuedAt, valueExpiresAt,
                valueSigner, valueStillValid, _) =>
            {
                repository = valueRepository;
                branch = valueBranch;
                commit = valueCommit;
                epoch = valueEpoch;
                issuedAt = valueIssuedAt;
                expiresAt = valueExpiresAt;
                observedSigner = valueSigner;
                stillValid = valueStillValid;
                return Task.FromResult(Completed());
            },
            signer,
            () => authority,
            new FixedTimeProvider(Now));

        var receipt = await runtime.CoordinateAsync(Observation("main"), 7);

        await Assert.That(receipt.IsComplete).IsTrue();
        await Assert.That(repository).IsEqualTo(Repository);
        await Assert.That(branch).IsEqualTo("main");
        await Assert.That(commit).IsEqualTo("bffeb74224043ba2feb48d137756c8a9331c449a");
        await Assert.That(epoch).IsEqualTo(7);
        await Assert.That(issuedAt).IsEqualTo(Now);
        await Assert.That(expiresAt).IsEqualTo(Now.Add(NativeGitOpsGlobalHandoffRuntime.Validity));
        await Assert.That(observedSigner).IsSameReferenceAs(signer);
        await Assert.That(stillValid!()).IsTrue();

        authority = Authority(8, leader: false);
        await Assert.That(stillValid()).IsFalse();
    }

    [Test]
    public async Task InvalidSourceOrStaleLeaseNeverCrossesTheCoordinatorBoundary()
    {
        var calls = 0;
        var runtime = new NativeGitOpsGlobalHandoffRuntime(
            (_, _, _, _, _, _, _, _, _) =>
            {
                calls++;
                return Task.FromResult(Completed());
            },
            new TestSigner(),
            () => Authority(7),
            new FixedTimeProvider(Now));

        await Assert.That(async () => await runtime.CoordinateAsync(Observation("develop"), 7))
            .Throws<ArgumentException>();
        var stale = await runtime.CoordinateAsync(Observation("main"), 6);

        await Assert.That(stale.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost);
        await Assert.That(calls).IsEqualTo(0);
    }

    private static ForgejoBranchObservation Observation(string branch) => new(
        branch,
        isProtected: true,
        new(
            Repository,
            "bffeb74224043ba2feb48d137756c8a9331c449a",
            "117eb74224043ba2feb48d137756c8a9331c44ff",
            signatureVerified: true));

    private static NativeGitOpsGlobalHandoffCoordinationReceipt Completed()
    {
        var digest = new string('a', 64);
        var snapshot = new NativeGitOpsGlobalHandoffPublishSnapshot(
            Repository,
            "main",
            1,
            7,
            1,
            digest,
            digest,
            1,
            1,
            [new("gru", digest, 1)],
            1);
        return new(
            NativeGitOpsGlobalHandoffCoordinationDisposition.Completed,
            NativeGitOpsSignedHandoffJournalDisposition.Recorded,
            new(
                NativeGitOpsGlobalHandoffDispatchDisposition.Completed,
                NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded,
                snapshot,
                1),
            1);
    }

    private static RegionalAuthoritySnapshot Authority(long epoch, bool leader = true)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            leader ? "leader" : "follower",
            leader,
            epoch,
            epoch,
            now.AddSeconds(10),
            now,
            null);
    }

    private sealed class TestSigner : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom([1], out var signature);
            return signature!;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
