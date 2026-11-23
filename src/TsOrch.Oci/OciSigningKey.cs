using System.Security.Cryptography;

namespace TsOrch.Oci;

public sealed record class OciSigningKey(string KeyId, RSA PrivateKey)
{
    public override string ToString() => nameof(OciSigningKey);
}
