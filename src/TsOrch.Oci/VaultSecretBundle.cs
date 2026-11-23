using System.Globalization;

namespace TsOrch.Oci;

public sealed record class VaultSecretBundle(string SecretId, string Value, long VersionNumber)
{
    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"VaultSecretBundle {{ SecretId = {SecretId}, VersionNumber = {VersionNumber} }}");
}
