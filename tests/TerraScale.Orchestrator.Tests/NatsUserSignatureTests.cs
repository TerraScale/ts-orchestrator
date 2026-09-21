using System.Numerics;
using System.Text;
using NATS.Client.Core;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsUserSignatureTests
{
    // RFC 8032 section 7.1, TEST 2; public key encoded as a checksummed NATS user key.
    private const string ReferencePublicKey = "UA6UAF6D5BBYSWUSW4FKOTI3P26JZGBMZ4XMJFUMYDGVL4JK6RTAYUDN";
    private static readonly byte[] ReferenceSignature = Convert.FromHexString(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    [Test]
    public async Task Rfc8032_signature_verifies_and_message_signature_or_key_changes_fail()
    {
        var signature = Convert.ToBase64String(ReferenceSignature);
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [0x72], signature)).IsTrue();
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [0x73], signature)).IsFalse();
        await Assert.That(NatsUserSignature.Verify(NKeys.PublicKeyFromSeed(NKeys.CreateUserSeed()), [0x72], signature)).IsFalse();
        var changed = ReferenceSignature.ToArray();
        changed[0] ^= 1;
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [0x72], Convert.ToBase64String(changed))).IsFalse();
    }

    [Test]
    public async Task Noncanonical_scalars_and_small_order_public_keys_are_rejected()
    {
        var order = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);
        var malleated = ReferenceSignature.ToArray();
        var scalar = new BigInteger(malleated.AsSpan(32), isUnsigned: true) + order;
        scalar.ToByteArray(isUnsigned: true).CopyTo(malleated, 32);
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [0x72], Convert.ToBase64String(malleated))).IsFalse();

        // Identity R, S=0 satisfies a naive Ed25519 equation when A is the identity.
        var identityProof = new byte[64];
        identityProof[0] = 1;
        foreach (var key in new[]
                 {
                     "UAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVBG",
                     "UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABET7"
                 })
            await Assert.That(NatsUserSignature.Verify(key, [0x72], Convert.ToBase64String(identityProof))).IsFalse();
    }

    [Test]
    public async Task Invalid_encodings_key_kinds_and_request_bounds_fail_closed()
    {
        var signature = Convert.ToBase64String(ReferenceSignature);
        foreach (var key in new string?[]
                 {
                     null, "", ReferencePublicKey[..^1] + "A", ReferencePublicKey.ToLowerInvariant(),
                     NKeys.CreateUserSeed(), NKeys.PublicKeyFromSeed(NKeys.CreateAccountSeed()),
                     NKeys.PublicKeyFromSeed(NKeys.CreateOperatorSeed()), "U" + new string('!', 55)
                 })
            await Assert.That(NatsUserSignature.Verify(key, [0x72], signature)).IsFalse();
        foreach (var proof in new string?[] { null, "", signature.TrimEnd('='), signature + "\n", new('!', 88), signature[..^3] + "B==" })
            await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [0x72], proof)).IsFalse();
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, [], signature)).IsFalse();
        await Assert.That(NatsUserSignature.Verify(ReferencePublicKey, new byte[16_385], signature)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Nats_client_signatures_verify_for_seed_and_JWT_files_and_rotation_requires_reresolution(bool jwt)
    {
        var directory = Directory.CreateTempSubdirectory("ts-host-proof-");
        try
        {
            var path = Path.Combine(directory.FullName, "user.key");
            var seed = NKeys.CreateUserSeed();
            await NatsAuthenticationFilesTests.WritePrivateAsync(path, jwt ? NatsAuthenticationFilesTests.Credentials(seed) : seed);
            var authentication = NatsAuthenticationFiles.Resolve(jwt ? null : path, jwt ? path : null, "proof")!;
            var message = Encoding.UTF8.GetBytes("terrascale-host-request-test\nnode-1");
            var signature = authentication.SignUserRequest(message);
            await Assert.That(NatsUserSignature.Verify(authentication.PublicKey, message, Convert.ToBase64String(signature))).IsTrue();
            await Assert.That(() => authentication.SignUserRequest([])).Throws<ArgumentException>();
            await Assert.That(() => authentication.SignUserRequest(new byte[16_385])).Throws<ArgumentException>();

            var replacement = NKeys.CreateUserSeed();
            await NatsAuthenticationFilesTests.WritePrivateAsync(path, jwt ? NatsAuthenticationFilesTests.Credentials(replacement) : replacement);
            var error = await Assert.That(() => authentication.SignUserRequest(message)).Throws<InvalidOperationException>();
            await Assert.That(error!.Message).DoesNotContain(seed);
            await Assert.That(error.Message).DoesNotContain(replacement);
        }
        finally { directory.Delete(recursive: true); }
    }
}
