using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellInboxTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ValidDeliveryIsAcknowledgedOnlyAfterDurableAcceptance()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var inbox = new NativeGitOpsCellInbox(new(ledger, payloads));
        var wire = Wire([1, 2, 3]);
        var acknowledgements = 0;

        var receipt = await inbox.ProcessAsync(
            wire.Payload,
            wire.Headers,
            41,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1, 2, 3]),
            () => true,
            _ =>
            {
                acknowledgements++;
                return Task.CompletedTask;
            });
        var accepted = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).ReadAsync("gru");

        await Assert.That(receipt.Disposition).IsEqualTo(NativeGitOpsCellDeliveryDisposition.Acknowledged);
        await Assert.That(receipt.IsAcknowledged).IsTrue();
        await Assert.That(receipt.AcceptanceDisposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.Recorded);
        await Assert.That(acknowledgements).IsEqualTo(1);
        await Assert.That(accepted).IsNotNull();
        await Assert.That(accepted!.StreamSequence).IsEqualTo(41UL);
    }

    [Test]
    public async Task MalformedInvalidSignatureAndPreAcceptanceAuthorityLossAreNeverAcknowledged()
    {
        var malformedWire = Wire([1]);
        var duplicateHeaders = malformedWire.Headers.Concat([malformedWire.Headers.First()]);
        var malformedAcks = 0;
        var malformed = await Inbox().ProcessAsync(
            malformedWire.Payload,
            duplicateHeaders,
            1,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1]),
            () => true,
            _ =>
            {
                malformedAcks++;
                return Task.CompletedTask;
            });
        var invalidAcks = 0;
        var invalid = await Inbox().ProcessAsync(
            malformedWire.Payload,
            malformedWire.Headers,
            2,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([2]),
            () => true,
            _ =>
            {
                invalidAcks++;
                return Task.CompletedTask;
            });
        var authorityAcks = 0;
        var authority = await Inbox().ProcessAsync(
            malformedWire.Payload,
            malformedWire.Headers,
            3,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1]),
            () => false,
            _ =>
            {
                authorityAcks++;
                return Task.CompletedTask;
            });

        await Assert.That(malformed.Disposition).IsEqualTo(NativeGitOpsCellDeliveryDisposition.Malformed);
        await Assert.That(invalid.AcceptanceDisposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.ProtocolRejected);
        await Assert.That(invalid.ProtocolError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(authority.AcceptanceDisposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.StaleAuthority);
        await Assert.That(malformedAcks + invalidAcks + authorityAcks).IsEqualTo(0);
    }

    [Test]
    public async Task AuthorityLossAfterAcceptanceLeavesMessageForDuplicateRecovery()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var inbox = new NativeGitOpsCellInbox(new(ledger, payloads));
        var wire = Wire([3]);
        var checks = 0;

        var lost = await inbox.ProcessAsync(
            wire.Payload,
            wire.Headers,
            51,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([3]),
            () => ++checks == 1,
            _ => Task.CompletedTask);
        var acknowledgements = 0;
        var recovered = await new NativeGitOpsCellInbox(new(ledger, payloads)).ProcessAsync(
            wire.Payload,
            wire.Headers,
            51,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([3]),
            () => true,
            _ =>
            {
                acknowledgements++;
                return Task.CompletedTask;
            });

        await Assert.That(lost.Disposition)
            .IsEqualTo(NativeGitOpsCellDeliveryDisposition.AuthorityLostAfterAcceptance);
        await Assert.That(lost.IsAcknowledged).IsFalse();
        await Assert.That(recovered.AcceptanceDisposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.Duplicate);
        await Assert.That(recovered.IsAcknowledged).IsTrue();
        await Assert.That(acknowledgements).IsEqualTo(1);
    }

    [Test]
    public async Task AcknowledgementFailurePreservesDurableStateForRedelivery()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var wire = Wire([4]);
        var inbox = new NativeGitOpsCellInbox(new(ledger, payloads));

        await Assert.That(async () => await inbox.ProcessAsync(
                wire.Payload,
                wire.Headers,
                61,
                "gru",
                7,
                Now,
                TimeSpan.Zero,
                new TestVerifier([4]),
                () => true,
                _ => throw new IOException("simulated acknowledgement failure")))
            .Throws<IOException>();
        var durable = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).ReadAsync("gru");
        var recovered = await inbox.ProcessAsync(
            wire.Payload,
            wire.Headers,
            61,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([4]),
            () => true,
            _ => Task.CompletedTask);

        await Assert.That(durable).IsNotNull();
        await Assert.That(recovered.AcceptanceDisposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.Duplicate);
        await Assert.That(recovered.IsAcknowledged).IsTrue();
    }

    private static NativeGitOpsCellInbox Inbox() => new(new(
        new ForgejoWebhookJournalTests.TestLedger(),
        new TestPayloadStore()));

    private static NativeGitOpsCellWireMessage Wire(byte[] signature)
    {
        var handoff = Handoff();
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner(signature));
        return NativeGitOpsCellWireCodec.Encode(handoff, envelope);
    }

    private static NativeGitOpsCellHandoff Handoff()
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        const string digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"api","role":"Api","artifactDigest":"{{digest}}","cells":["gru"]}]}
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

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            signature.Bytes.SequenceEqual(expected) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }

    private sealed class TestPayloadStore : INativeGitOpsManifestStore
    {
        private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var content)) throw new IOException("Missing test payload.");
            return Task.FromResult(content.ToArray());
        }
    }
}
