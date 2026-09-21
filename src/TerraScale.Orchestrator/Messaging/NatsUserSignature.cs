using NATS.Client.Core;
using NSec.Cryptography;

namespace TerraScale.Orchestrator.Messaging;

internal static class NatsUserSignature
{
    internal static bool Verify(string? publicKey, byte[] message, string? signature)
    {
        try
        {
            if (publicKey is not { Length: 56 } || !publicKey.StartsWith('U') ||
                publicKey.Any(static c => c is not (>= 'A' and <= 'Z' or >= '2' and <= '7')) ||
                message.Length is < 1 or > 16_384 || signature is not { Length: 88 })
                return false;
            var key = NKeys.Decode(publicKey);
            var proof = Convert.FromBase64String(signature);
            if (key.Length != 33 || key[0] != 160 || proof.Length != 64 ||
                Convert.ToBase64String(proof) != signature)
                return false;
            var algorithm = SignatureAlgorithm.Ed25519;
            return PublicKey.TryImport(algorithm, key.AsSpan(1), KeyBlobFormat.RawPublicKey, out var imported) &&
                imported is not null && algorithm.Verify(imported, message, proof);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or NatsException)
        {
            return false;
        }
    }
}
