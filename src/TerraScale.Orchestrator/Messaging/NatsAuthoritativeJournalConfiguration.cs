using System.Security.Cryptography;
using NATS.Client.Core;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Separate credentials and trust root required to host the private authoritative journal writer.</summary>
public sealed record NatsAuthoritativeJournalConfiguration(
    string NKeyFile,
    NatsTlsFiles Tls,
    byte[] AuthorityPublicKey,
    string ReplySigningKeyFile,
    byte[] ReplySigningPublicKey,
    IReadOnlySet<string> EligibleControllerIdentities)
{
    internal static NatsAuthoritativeJournalConfiguration? Resolve(
        string? nkeyFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        string? authorityPublicKeyFile,
        string? replySigningKeyFile,
        string? eligibleControllerIdentities)
    {
        var values = new[] { nkeyFile, caFile, certificateFile, keyFile, authorityPublicKeyFile, replySigningKeyFile, eligibleControllerIdentities };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != values.Length)
            throw new ArgumentException("TS_ORCH_JOURNAL requires NKey, mTLS, authority public-key, reply signing-key, and eligible controller identities together.");

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
            var replyPath = ResolveReplySigningKey(replySigningKeyFile!);
            using var reply = ECDsa.Create();
            reply.ImportFromPem(File.ReadAllText(replyPath));
            var replyPublicKey = reply.ExportSubjectPublicKeyInfo();
            if (reply.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                replyPublicKey.AsSpan().SequenceEqual(publicKey))
                throw new CryptographicException("Reply signing key must be a distinct NIST P-256 key.");
            if (tls.HasSubjectPublicKeyInfo(publicKey) || tls.HasSubjectPublicKeyInfo(replyPublicKey))
                throw new CryptographicException("Authority keys must be distinct from the journal writer TLS identity.");
            var controllers = ParseControllerIdentities(eligibleControllerIdentities!);
            if (controllers.Contains(NatsCredentialFile.PublicKey(resolvedNkey)))
                throw new ArgumentException("TS_ORCH_JOURNAL_CONTROLLER_NKEYS must not contain the journal writer NKey public identity.");
            return new(resolvedNkey, tls, publicKey, replyPath, replyPublicKey, controllers);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.", exception);
        }
    }

    private static IReadOnlySet<string> ParseControllerIdentities(string value)
    {
        var identities = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.Ordinal);
        if (identities.Count == 0)
            throw new ArgumentException("TS_ORCH_JOURNAL_CONTROLLER_NKEYS must contain at least one NKey public identity.");
        try
        {
            foreach (var identity in identities)
            {
                if (!identity.StartsWith('U')) throw new FormatException();
                _ = NKeys.Decode(identity);
            }
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ArgumentException("TS_ORCH_JOURNAL_CONTROLLER_NKEYS contains an invalid user NKey public identity.", exception);
        }
        return identities;
    }

    private static string ResolveReplySigningKey(string value)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("NATS reply signing keys require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 8_192 ||
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                           UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must identify a bounded owner-private key file.");
        if (!File.ReadAllText(path).Contains("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
            throw new ArgumentException("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must contain a private key.");
        return path;
    }
}
