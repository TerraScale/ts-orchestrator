using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class CommandSignedMaterialCodecTests
{
    [Test]
    public async Task CanonicalHashIsDeterministicAndCoversEveryMaterialField()
    {
        var original = ProtocolTestData.ValidEnvelope();
        var hash = CommandSignedMaterialCodec.Hash(original.SignedMaterial);
        await Assert.That(Convert.ToHexStringLower(hash))
            .IsEqualTo("b0441ae96a300dde1a88ca5d44f60af132ee165e93d869d545607bb70959130f");
        var alternatives = new[]
        {
            ProtocolTestData.ValidEnvelope(protocol: ProtocolTestData.Protocol(2)),
            ProtocolTestData.ValidEnvelope(cell: ProtocolTestData.Cell("sfo")),
            ProtocolTestData.ValidEnvelope(aggregate: ProtocolTestData.Aggregate("allocation/43")),
            ProtocolTestData.ValidEnvelope(generation: ProtocolTestData.Generation(11)),
            ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(8)),
            ProtocolTestData.ValidEnvelope(operation: ProtocolTestData.Operation("operation/def")),
            ProtocolTestData.ValidEnvelope(idempotency: ProtocolTestData.Idempotency("idempotency/def")),
            ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(-2)),
            ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(-1).AddTicks(1)),
            ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddMinutes(-1).ToOffset(TimeSpan.FromHours(1))),
            ProtocolTestData.ValidEnvelope(expiresAt: ProtocolTestData.Now.AddMinutes(2)),
            ProtocolTestData.ValidEnvelope(attempt: ProtocolTestData.Attempt(2)),
            ProtocolTestData.ValidEnvelope(payload: OpaquePayload.CopyFrom([1, 2, 3, 5])),
            ProtocolTestData.ValidEnvelope(digest: ProtocolTestData.Digest([1, 2, 3, 5])),
        };

        await Assert.That(CommandSignedMaterialCodec.Hash(
            ProtocolTestData.ValidEnvelope().SignedMaterial)).IsEquivalentTo(hash);
        foreach (var alternative in alternatives)
            await Assert.That(CommandSignedMaterialCodec.Hash(alternative.SignedMaterial))
                .IsNotEquivalentTo(hash);
    }

    [Test]
    public async Task InvalidWindowAndOversizedPayloadCannotReachASigner()
    {
        var invalidWindow = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now,
            expiresAt: ProtocolTestData.Now.AddSeconds(-1));
        var oversized = ProtocolTestData.ValidEnvelope(
            payload: OpaquePayload.CopyFrom(new byte[1024 * 1024 + 1]));

        await Assert.That(() => CommandSignedMaterialCodec.Hash(invalidWindow.SignedMaterial))
            .Throws<InvalidDataException>();
        await Assert.That(() => CommandSignedMaterialCodec.Hash(oversized.SignedMaterial))
            .Throws<InvalidDataException>();
    }
}
