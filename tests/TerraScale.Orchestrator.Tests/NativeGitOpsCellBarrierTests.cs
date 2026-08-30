using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellBarrierTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ExactReceiptSetCompletesOneDeterministicAcceptanceBarrier()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var receipts = handoff.Cells.Select((spec, index) => Receipt(
            handoff,
            spec,
            epoch: 7,
            sequence: (ulong)(index + 11),
            revision: (ulong)(index + 21))).ToArray();

        var first = NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, receipts.Reverse());
        var second = NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, receipts);

        await Assert.That(first.IsComplete).IsTrue();
        await Assert.That(first.State).IsEqualTo(NativeGitOpsCellBarrierState.Complete);
        await Assert.That(first.MissingCells).IsEmpty();
        await Assert.That(string.Join(',', first.Receipts.Select(static receipt => receipt.Cell)))
            .IsEqualTo("fra,gru,sfo");
        await Assert.That(first.BarrierDigest).IsEqualTo(second.BarrierDigest);
        await Assert.That(first.BarrierDigest!.Length).IsEqualTo(64);
    }

    [Test]
    public async Task MissingRegionsRemainExplicitlyPendingWithoutABarrierDigest()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var gru = handoff.Cells.Single(static spec => spec.Cell == "gru");

        var barrier = NativeGitOpsCellBarrierEvaluator.Evaluate(
            descriptor,
            [Receipt(handoff, gru, 7, 1, 1)]);

        await Assert.That(barrier.State).IsEqualTo(NativeGitOpsCellBarrierState.Pending);
        await Assert.That(barrier.IsComplete).IsFalse();
        await Assert.That(string.Join(',', barrier.MissingCells)).IsEqualTo("fra,sfo");
        await Assert.That(barrier.BarrierDigest).IsNull();
    }

    [Test]
    public async Task DuplicateForeignAndMismatchedReceiptsFailClosed()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var gru = handoff.Cells.Single(static spec => spec.Cell == "gru");
        var receipt = Receipt(handoff, gru, 7, 1, 1);
        var foreign = receipt with
        {
            Cell = "iad",
            OperationId = $"gitops/{handoff.HandoffDigest}/iad",
        };
        var mismatched = receipt with
        {
            GlobalPlanDigest = "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        };

        await Assert.That(() => NativeGitOpsCellBarrierEvaluator.Evaluate(
                descriptor,
                [receipt, receipt]))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, [foreign]))
            .Throws<InvalidDataException>();
        await Assert.That(() => NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, [mismatched]))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task FencedTakeoverReceiptsProduceADifferentBarrierIdentity()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epoch7 = handoff.Cells.Select((spec, index) => Receipt(
            handoff,
            spec,
            7,
            (ulong)(index + 1),
            (ulong)(index + 1))).ToArray();
        var epoch8 = handoff.Cells.Select((spec, index) => Receipt(
            handoff,
            spec,
            8,
            (ulong)(index + 1),
            (ulong)(index + 2))).ToArray();

        var first = NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, epoch7);
        var takeover = NativeGitOpsCellBarrierEvaluator.Evaluate(descriptor, epoch8);

        await Assert.That(first.IsComplete).IsTrue();
        await Assert.That(takeover.IsComplete).IsTrue();
        await Assert.That(first.BarrierDigest).IsNotEqualTo(takeover.BarrierDigest);
    }

    private static NativeGitOpsAcceptedCellSpec Receipt(
        NativeGitOpsCellHandoff handoff,
        NativeGitOpsCellSpec spec,
        long epoch,
        ulong sequence,
        ulong revision) => new(
        spec.Cell,
        spec.Generation,
        spec.GlobalPlanDigest,
        handoff.HandoffDigest,
        spec.PayloadSha256,
        spec.Payload.ToArray(),
        epoch,
        1,
        $"gitops/{handoff.HandoffDigest}/{spec.Cell}",
        $"gitops/{spec.PayloadSha256}",
        1,
        Now.AddMinutes(-1),
        Now.AddMinutes(1),
        Now,
        sequence,
        "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        revision);

    private static NativeGitOpsCellHandoff Handoff()
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        const string digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{digest}}","cells":["gru","sfo","fra"]}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed)));
    }
}
