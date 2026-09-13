using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsLiveBarrierTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ExactSignedLiveSetCompletesDeterministicallyAcrossArrivalOrder()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs();
        var receipts = handoff.Cells.Select((cell, index) => Signed(
            Checkpoint(cell, epochs[cell.Cell], index + 1))).ToArray();

        var first = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor, epochs, receipts.Reverse(), Now, TimeSpan.Zero, new TestVerifier());
        var second = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor, epochs, receipts, Now, TimeSpan.Zero, new TestVerifier());

        await Assert.That(first.IsComplete).IsTrue();
        await Assert.That(first.State).IsEqualTo(NativeGitOpsLiveBarrierState.Complete);
        await Assert.That(first.MissingCells).IsEmpty();
        await Assert.That(string.Join(',', first.Receipts.Select(static value => value.Receipt.Cell)))
            .IsEqualTo("fra,gru,sfo");
        await Assert.That(first.BarrierDigest).IsEqualTo(second.BarrierDigest);
        await Assert.That(first.BarrierDigest!.Length).IsEqualTo(64);
    }

    [Test]
    public async Task MissingCellsStayExplicitAndProduceNoLiveBarrierDigest()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs();
        var gru = handoff.Cells.Single(static value => value.Cell == "gru");

        var barrier = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor,
            epochs,
            [Signed(Checkpoint(gru, epochs["gru"], 1))],
            Now,
            TimeSpan.Zero,
            new TestVerifier());

        await Assert.That(barrier.State).IsEqualTo(NativeGitOpsLiveBarrierState.Pending);
        await Assert.That(barrier.IsComplete).IsFalse();
        await Assert.That(string.Join(',', barrier.MissingCells)).IsEqualTo("fra,sfo");
        await Assert.That(barrier.BarrierDigest).IsNull();
    }

    [Test]
    public async Task SignatureSubstitutionDuplicateForeignStaleAndExpiredReceiptsFailClosed()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs();
        var gru = handoff.Cells.Single(static value => value.Cell == "gru");
        var valid = Signed(Checkpoint(gru, epochs["gru"], 1));
        var substituted = valid with
        {
            Receipt = valid.Receipt with { ConvergenceDigest = Hash("substituted") },
        };
        var expired = NativeGitOpsCellConvergenceReceipt.Sign(
            Checkpoint(gru, epochs["gru"], 1),
            Now.AddMinutes(-2),
            Now.AddMinutes(-1),
            new TestSigner());
        var staleEpoch = Signed(Checkpoint(gru, epochs["gru"] - 1, 1));
        var foreign = Signed(Checkpoint(gru, epochs["gru"], 1) with { Cell = "iad" });

        foreach (var invalid in new[]
        {
            new[] { substituted },
            new[] { expired },
            new[] { staleEpoch },
            new[] { foreign },
            new[] { valid, valid },
        })
            await Assert.That(() => NativeGitOpsLiveBarrierEvaluator.Evaluate(
                    descriptor,
                    epochs,
                    invalid,
                    Now,
                    TimeSpan.Zero,
                    new TestVerifier()))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task FencedTakeoverRequiresCurrentEpochAndChangesLiveBarrierIdentity()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var firstEpochs = Epochs();
        var firstReceipts = handoff.Cells.Select((cell, index) => Signed(
            Checkpoint(cell, firstEpochs[cell.Cell], index + 1))).ToArray();
        var first = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor, firstEpochs, firstReceipts, Now, TimeSpan.Zero, new TestVerifier());

        var takeoverEpochs = Epochs();
        takeoverEpochs["gru"]++;
        await Assert.That(() => NativeGitOpsLiveBarrierEvaluator.Evaluate(
                descriptor, takeoverEpochs, firstReceipts, Now, TimeSpan.Zero, new TestVerifier()))
            .Throws<InvalidDataException>();
        var takeoverReceipts = handoff.Cells.Select((cell, index) => Signed(
            Checkpoint(cell, takeoverEpochs[cell.Cell], index + 11))).ToArray();
        var takeover = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor, takeoverEpochs, takeoverReceipts, Now, TimeSpan.Zero, new TestVerifier());

        await Assert.That(takeover.IsComplete).IsTrue();
        await Assert.That(takeover.BarrierDigest).IsNotEqualTo(first.BarrierDigest);
    }

    [Test]
    public async Task OnlyConvergedCheckpointCanBeSignedAndValidationNeedsExactMaterial()
    {
        var handoff = Handoff();
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var gru = handoff.Cells.Single(static value => value.Cell == "gru");
        var checkpoint = Checkpoint(gru, 7, 1);
        var signer = new TestSigner();
        var signed = NativeGitOpsCellConvergenceReceipt.Sign(
            checkpoint, Now.AddMinutes(-1), Now.AddMinutes(1), signer);
        var validation = NativeGitOpsCellConvergenceReceipt.Validate(
            signed, descriptor, "gru", 7, Now, TimeSpan.Zero, new TestVerifier());

        await Assert.That(validation.IsValid).IsTrue();
        await Assert.That(signer.Material).IsNotNull();
        await Assert.That(signer.Material!.Value.Span.SequenceEqual(
            NativeGitOpsCellConvergenceReceipt.Material(signed.Receipt).Span)).IsTrue();
        await Assert.That(() => NativeGitOpsCellConvergenceReceipt.Sign(
                checkpoint with
                {
                    Decision = new(
                        NativeGitOpsCellConvergenceState.Pending,
                        NativeGitOpsCellConvergenceHoldReason.None,
                        new(
                            NativeGitOpsCellConvergenceIntentKind.Observe,
                            "platform",
                            checkpoint.Generation,
                            Hash("workload"),
                            null,
                            null),
                        null),
                },
                Now,
                Now.AddMinutes(1),
                signer))
            .Throws<ArgumentException>();
    }

    private static Dictionary<string, long> Epochs() => new(StringComparer.Ordinal)
    {
        ["fra"] = 9,
        ["gru"] = 7,
        ["sfo"] = 8,
    };

    private static NativeGitOpsCellConvergenceReceiptEnvelope Signed(
        NativeGitOpsCellConvergenceCheckpoint checkpoint) => NativeGitOpsCellConvergenceReceipt.Sign(
        checkpoint,
        Now.AddMinutes(-1),
        Now.AddMinutes(1),
        new TestSigner());

    private static NativeGitOpsCellConvergenceCheckpoint Checkpoint(
        NativeGitOpsCellSpec cell,
        long writerEpoch,
        int sequence) => new(
        cell.Cell,
        cell.Generation,
        cell.GlobalPlanDigest,
        Handoff().HandoffDigest,
        cell.PayloadSha256,
        writerEpoch,
        (ulong)sequence,
        Hash($"acceptance-signature-{cell.Cell}-{writerEpoch}"),
        (ulong)sequence,
        sequence,
        new(
            NativeGitOpsCellConvergenceState.Converged,
            NativeGitOpsCellConvergenceHoldReason.None,
            null,
            Hash($"live-{cell.Cell}-{writerEpoch}-{sequence}")),
        sequence,
        Hash($"previous-{cell.Cell}-{sequence}"),
        Hash($"checkpoint-{cell.Cell}-{writerEpoch}-{sequence}"),
        (ulong)sequence);

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

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed class TestSigner : INativeGitOpsCellConvergenceReceiptSigner
    {
        internal ReadOnlyMemory<byte>? Material { get; private set; }

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            Material = canonicalMaterial.ToArray();
            OpaqueSignature.TryCopyFrom(SHA256.HashData(canonicalMaterial.Span), out var signature);
            return signature!;
        }
    }

    private sealed class TestVerifier : INativeGitOpsCellConvergenceReceiptVerifier
    {
        public VerificationOutcome Verify(
            string cell,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(canonicalMaterial.Span),
                signature.Bytes)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }
}

