using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Separate credentials and trust root required to host the private authoritative journal writer.</summary>
public sealed record NatsAuthoritativeJournalConfiguration(
    string NKeyFile,
    NatsTlsFiles Tls,
    byte[] AuthorityPublicKey)
{
    internal static NatsAuthoritativeJournalConfiguration? Resolve(
        string? nkeyFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        string? authorityPublicKeyFile)
    {
        var values = new[] { nkeyFile, caFile, certificateFile, keyFile, authorityPublicKeyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != values.Length)
            throw new ArgumentException("TS_ORCH_JOURNAL requires NKey, mTLS, and authority public-key files together.");

        var resolvedNkey = NatsCredentialFile.Resolve(nkeyFile, "TS_ORCH_JOURNAL_NATS_NKEY_FILE")!;
        var tls = NatsTlsFiles.Resolve(caFile, certificateFile, keyFile, "TS_ORCH_JOURNAL_NATS_TLS")!;
        var path = Path.GetFullPath(authorityPublicKeyFile!);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 8_192)
            throw new ArgumentException("TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE must identify a bounded authority public key file.");
        try
        {
            var pem = File.ReadAllText(path);
            if (!pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
                throw new CryptographicException("Authority verification material must be a public key.");
            using var authority = ECDsa.Create();
            authority.ImportFromPem(pem);
            if (authority.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("Authority verification key must use NIST P-256.");
            var publicKey = authority.ExportSubjectPublicKeyInfo();
            if (publicKey.Length == 0) throw new CryptographicException("Authority public key is empty.");
            return new(resolvedNkey, tls, publicKey);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.", exception);
        }
    }
}
