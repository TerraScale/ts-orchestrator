using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsSourceJournalTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string Blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
    private const string Commit2 = "cffeb74224043ba2feb48d137756c8a9331c449b";
    private const string Tree2 = "317eb74224043ba2feb48d137756c8a9331c44dd";
    private const string Blob2 = "417eb74224043ba2feb48d137756c8a9331c44cc";
    private const string Commit3 = "dffeb74224043ba2feb48d137756c8a9331c449c";
    private const string Tree3 = "517eb74224043ba2feb48d137756c8a9331c44bb";
    private const string Blob3 = "617eb74224043ba2feb48d137756c8a9331c44aa";
    private const string DigestV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV3 = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task ContentAddressedManifestAndCasPointerResumeAcrossJournalInstances()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var manifests = new TestManifestStore();
        var journal = new NativeGitOpsSourceJournal(ledger, manifests);
        var initial = SourcePlan(1, DigestV1);

        var recorded = await journal.RecordAsync("develop", initial, 7, 1, expected: null);
        var accepted = await new NativeGitOpsSourceJournal(ledger, manifests)
            .ReadAsync(Repository, "develop");
        var updatedPlan = SourcePlan(2, DigestV2, accepted, Commit2, Tree2, Blob2);
        var updated = await journal.RecordAsync("develop", updatedPlan, 7, 2, accepted);
        var current = await journal.ReadAsync(Repository, "develop");

        await Assert.That(recorded.Disposition).IsEqualTo(NativeGitOpsSourceJournalDisposition.Recorded);
        await Assert.That(updated.Disposition).IsEqualTo(NativeGitOpsSourceJournalDisposition.Recorded);
        await Assert.That(current).IsNotNull();
        await Assert.That(current!.Plan.Generation).IsEqualTo(2);
        await Assert.That(current.Plan.Digest).IsEqualTo(updatedPlan.Proposed.Digest);
        await Assert.That(current.Diff!.AcceptedGeneration).IsEqualTo(1);
        await Assert.That(current.Diff.ProposedGeneration).IsEqualTo(2);
        await Assert.That(current.Diff.Changes).HasSingleItem();
        await Assert.That(current.Diff.Changes[0].Kind).IsEqualTo(NativeGitOpsChangeKind.Update);
        await Assert.That(current.SourceFile.Content.Span.SequenceEqual(updatedPlan.SourceFile.Content.Span)).IsTrue();
        await Assert.That(manifests.PutCount).IsEqualTo(2);
    }

    [Test]
    public async Task RestartReconstructsGuardedRetirementFromTheDurableAcceptedBase()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var manifests = new TestManifestStore();
        var journal = new NativeGitOpsSourceJournal(ledger, manifests);
        await journal.RecordAsync("develop", SourcePlan(1, DigestV1), 7, 1, expected: null);
        var accepted = await journal.ReadAsync(Repository, "develop");
        var retirement = EmptySourcePlan(2, accepted!, Commit2, Tree2, Blob2);
        await journal.RecordAsync("develop", retirement, 7, 2, accepted);

        var recovered = await new NativeGitOpsSourceJournal(ledger, manifests)
            .ReadAsync(Repository, "develop");
        var source = new NativeGitOpsSourcePlan(
            recovered!.Revision,
            recovered.SourceFile,
            recovered.Plan,
            recovered.Diff!);
        var handoff = NativeGitOpsCellSpecCompiler.Compile(source);

        await Assert.That(recovered.Diff!.AcceptedGeneration).IsEqualTo(1);
        await Assert.That(recovered.Diff.Changes).HasSingleItem();
        await Assert.That(recovered.Diff.Changes[0].Kind)
            .IsEqualTo(NativeGitOpsChangeKind.GuardedRetirement);
        await Assert.That(handoff.Cells).HasSingleItem();
        await Assert.That(handoff.Cells[0].Changes[0].Kind)
            .IsEqualTo(NativeGitOpsChangeKind.GuardedRetirement);
    }

    [Test]
    public async Task CorruptAcceptedBaseFailsClosedAfterPointerAdvance()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var manifests = new TestManifestStore();
        var journal = new NativeGitOpsSourceJournal(ledger, manifests);
        var initial = SourcePlan(1, DigestV1);
        await journal.RecordAsync("develop", initial, 7, 1, expected: null);
        var accepted = await journal.ReadAsync(Repository, "develop");
        await journal.RecordAsync(
            "develop",
            SourcePlan(2, DigestV2, accepted, Commit2, Tree2, Blob2),
            7,
            2,
            accepted);
        manifests.Corrupt(initial.SourceFile.ContentSha256);

        await Assert.That(async () => await journal.ReadAsync(Repository, "develop"))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task CrashAfterBlobWriteResumesWithoutPartialAcceptance()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var manifests = new TestManifestStore();
        var source = SourcePlan(1, DigestV1);

        await Assert.That(async () => await new NativeGitOpsSourceJournal(ledger, manifests)
                .RecordAsync("develop", source, 7, 1, expected: null))
            .Throws<IOException>();
        var recovered = await new NativeGitOpsSourceJournal(ledger, manifests)
            .RecordAsync("develop", source, 7, 1, expected: null);
        var accepted = await new NativeGitOpsSourceJournal(ledger, manifests)
            .ReadAsync(Repository, "develop");

        await Assert.That(recovered.Disposition).IsEqualTo(NativeGitOpsSourceJournalDisposition.Recorded);
        await Assert.That(accepted!.Plan.Generation).IsEqualTo(1);
        await Assert.That(manifests.Values).HasSingleItem();
    }

    [Test]
    public async Task AuthoritySequenceAndConcurrentPointerUpdatesAreFenced()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var manifests = new TestManifestStore();
        var journal = new NativeGitOpsSourceJournal(ledger, manifests);
        await journal.RecordAsync("develop", SourcePlan(1, DigestV1), 8, 2, expected: null);
        var accepted = await journal.ReadAsync(Repository, "develop");
        var second = SourcePlan(2, DigestV2, accepted, Commit2, Tree2, Blob2);
        var competing = SourcePlan(2, DigestV3, accepted, Commit3, Tree3, Blob3);
        var equivocated = SourcePlan(2, DigestV2, accepted);

        var staleAuthority = await journal.RecordAsync("develop", second, 7, 3, accepted);
        var staleSequence = await journal.RecordAsync("develop", second, 8, 1, accepted);
        var identityConflict = await journal.RecordAsync("develop", equivocated, 8, 3, accepted);
        var results = await Task.WhenAll(
            journal.RecordAsync("develop", second, 8, 3, accepted),
            journal.RecordAsync("develop", competing, 8, 3, accepted));

        await Assert.That(staleAuthority.Disposition)
            .IsEqualTo(NativeGitOpsSourceJournalDisposition.StaleAuthority);
        await Assert.That(staleSequence.Disposition)
            .IsEqualTo(NativeGitOpsSourceJournalDisposition.StaleSequence);
        await Assert.That(identityConflict.Disposition)
            .IsEqualTo(NativeGitOpsSourceJournalDisposition.IdentityConflict);
        await Assert.That(results.Count(result =>
            result.Disposition == NativeGitOpsSourceJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(results.Count(result =>
            result.Disposition == NativeGitOpsSourceJournalDisposition.ConcurrentUpdate)).IsEqualTo(1);
    }

    [Test]
    public async Task CorruptOrMissingAcceptedManifestFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var manifests = new TestManifestStore();
        var journal = new NativeGitOpsSourceJournal(ledger, manifests);
        var source = SourcePlan(1, DigestV1);
        await journal.RecordAsync("main", source, 4, 1, expected: null);
        manifests.Corrupt(source.SourceFile.ContentSha256);

        await Assert.That(async () => await journal.ReadAsync(Repository, "main"))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task TopologySeparatesSmallCasPointersFromBoundedManifestObjects()
    {
        var topology = new GlobalNatsTopology(3);

        await Assert.That(topology.Releases.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(topology.Bundles.Bucket).IsEqualTo("GLOBAL_BUNDLES");
        await Assert.That(topology.Bundles.MaxBytes).IsEqualTo(1024L * 1024 * 1024);
        await Assert.That(topology.Bundles.NumberOfReplicas).IsEqualTo(3);
    }

    private static NativeGitOpsSourcePlan SourcePlan(
        long generation,
        string artifactDigest,
        NativeGitOpsAcceptedSource? accepted = null,
        string commit = Commit,
        string tree = Tree,
        string blob = Blob)
    {
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{artifactDigest}}","cells":["gru"]}]}
            """);
        var plan = NativeGitOpsManifest.Parse(content);
        var contentDigest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content));
        var revision = new ForgejoResolvedRevision(Repository, commit, tree, signatureVerified: true);
        var file = new ForgejoSourceFile(
            Repository,
            commit,
            NativeGitOpsSourceLoader.ManifestPath,
            blob,
            contentDigest,
            content);
        return new(revision, file, plan, NativeGitOpsDiff.Compare(accepted?.Plan, plan));
    }

    private static NativeGitOpsSourcePlan EmptySourcePlan(
        long generation,
        NativeGitOpsAcceptedSource accepted,
        string commit,
        string tree,
        string blob)
    {
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[]}
            """);
        var plan = NativeGitOpsManifest.Parse(content);
        return new(
            new(Repository, commit, tree, signatureVerified: true),
            new(
                Repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content)),
                content),
            plan,
            NativeGitOpsDiff.Compare(accepted.Plan, plan));
    }

    internal sealed class TestManifestStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal int PutCount { get; private set; }
        internal IReadOnlyCollection<byte[]> Values => values.Values;
        internal Action? AfterPut { get; set; }

        public Task PutAsync(
            string name,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PutCount++;
            values[name] = content.ToArray();
            AfterPut?.Invoke();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var content)) throw new IOException("Missing test manifest.");
            return Task.FromResult(content.ToArray());
        }

        internal void Corrupt(string contentSha256) =>
            values[$"native-gitops-manifest-{contentSha256}"] = "corrupt"u8.ToArray();
    }
}

