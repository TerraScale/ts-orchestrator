using System.Text;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class OpaqueCommandBytesTests
{
    [Test]
    public async Task Opaque_values_copy_input_and_do_not_render_contents()
    {
        var source = Encoding.UTF8.GetBytes("not-for-logs");
        var expected = source.ToArray();
        var payload = OpaquePayload.CopyFrom(source);
        await Assert.That(PayloadDigest.TryCopyFrom(source, out var digest)).IsTrue();
        await Assert.That(OpaqueSignature.TryCopyFrom(source, out var signature)).IsTrue();

        source.AsSpan().Fill(0);
        var exportedCopy = payload.Bytes.ToArray();
        exportedCopy.AsSpan().Fill(255);

        await Assert.That(payload.Bytes.SequenceEqual(expected)).IsTrue();
        await Assert.That(digest!.Bytes.SequenceEqual(expected)).IsTrue();
        await Assert.That(signature!.Bytes.SequenceEqual(expected)).IsTrue();
        await Assert.That(payload.ToString()).DoesNotContain("not-for-logs");
        await Assert.That(digest.ToString()).DoesNotContain("not-for-logs");
        await Assert.That(signature.ToString()).DoesNotContain("not-for-logs");
    }

    [Test]
    public async Task Empty_payload_is_representable_but_digest_and_signature_are_not()
    {
        var payload = OpaquePayload.CopyFrom([]);

        await Assert.That(payload.Length).IsEqualTo(0);
        await Assert.That(PayloadDigest.TryCopyFrom([], out var digest)).IsFalse();
        await Assert.That(digest).IsNull();
        await Assert.That(OpaqueSignature.TryCopyFrom([], out var signature)).IsFalse();
        await Assert.That(signature).IsNull();
    }

    [Test]
    public async Task Equality_is_content_based()
    {
        var payloadA = OpaquePayload.CopyFrom([1, 2, 3]);
        var payloadB = OpaquePayload.CopyFrom([1, 2, 3]);
        var payloadC = OpaquePayload.CopyFrom([1, 2, 4]);

        await Assert.That(payloadA).IsEqualTo(payloadB);
        await Assert.That(payloadA).IsNotEqualTo(payloadC);
    }
}
