using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace TsOrch.Cli;

internal sealed record class SshPublicKey(string Line, string Fingerprint);

internal static class SshLogin
{
    public const string SignatureNamespace = "ts-orch";

    private const string KeyType = "ssh-ed25519";
    private const int Ed25519KeyLength = 32;

    public static async Task<OrchResult<CliSession>> LoginAsync(
        OrchHttp http,
        Uri baseUrl,
        string keyPath,
        string sessionFile,
        bool interactive,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        var keyResult = await ReadPublicKeyAsync(keyPath, interactive, cancellationToken);
        if (!keyResult.TryGetValue(out var key, out var keyError))
        {
            return keyError;
        }

        using var challengeRequest = OrchHttp.CreateRequest(
            HttpMethod.Post,
            baseUrl,
            "/api/auth/ssh/challenge",
            token: null,
            OrchHttp.JsonBody(new SshChallengeRequest(key.Fingerprint), ApiJsonContext.Default.SshChallengeRequest));
        var challengeResult = await http.SendJsonAsync(challengeRequest, ApiJsonContext.Default.SshChallengeResponse, OrchHttp.DefaultTimeout, cancellationToken);
        if (!challengeResult.TryGetValue(out var challenge, out var challengeError))
        {
            return challengeError;
        }

        if (challenge.Namespace != SignatureNamespace)
        {
            return new Validation($"The backplane asked for SSH namespace '{challenge.Namespace}', expected '{SignatureNamespace}'.");
        }

        var signatureResult = await SignAsync(keyPath, challenge.Nonce, interactive, cancellationToken);
        if (!signatureResult.TryGetValue(out var signature, out var signatureError))
        {
            return signatureError;
        }

        using var verifyRequest = OrchHttp.CreateRequest(
            HttpMethod.Post,
            baseUrl,
            "/api/auth/ssh/verify",
            token: null,
            OrchHttp.JsonBody(new SshVerifyRequest(challenge.ChallengeId, key.Line, signature), ApiJsonContext.Default.SshVerifyRequest));
        var verifyResult = await http.SendJsonAsync(verifyRequest, ApiJsonContext.Default.SshVerifyResponse, OrchHttp.DefaultTimeout, cancellationToken);
        if (!verifyResult.TryGetValue(out var verified, out var verifyError))
        {
            return verifyError;
        }

        var session = new CliSession(baseUrl.AbsoluteUri, verified.Token, verified.ExpiresAt, verified.Owner, verified.Role);
        var saved = await CliFiles.WritePrivateJsonAsync(sessionFile, session, CliJsonContext.Default.CliSession, cancellationToken);
        return saved switch
        {
            Done => session,
            OrchError error => error,
        };
    }

    public static bool KeyAvailable(string keyPath) => File.Exists(keyPath) || File.Exists(PublicKeyPath(keyPath));

    private static string PublicKeyPath(string keyPath) =>
        keyPath.EndsWith(".pub", StringComparison.Ordinal) ? keyPath : keyPath + ".pub";

    private static async Task<OrchResult<SshPublicKey>> ReadPublicKeyAsync(string keyPath, bool interactive, CancellationToken cancellationToken)
    {
        var publicKeyPath = PublicKeyPath(keyPath);
        var text = File.Exists(publicKeyPath)
            ? await CliFiles.ReadTextAsync(publicKeyPath, cancellationToken)
            : await DerivePublicKeyAsync(keyPath, interactive, cancellationToken);
        return text switch
        {
            string line => ParsePublicKey(line, publicKeyPath),
            OrchError error => error,
        };
    }

    private static async Task<OrchResult<string>> DerivePublicKeyAsync(string keyPath, bool interactive, CancellationToken cancellationToken)
    {
        if (!File.Exists(keyPath))
        {
            return new NotFound($"SSH key {keyPath} does not exist; pass --key or set {OperatorSettings.KeyVariable}.");
        }

        var derived = await ExternalProcess.RunAsync("ssh-keygen", ["-y", "-f", keyPath], interactive, cancellationToken);
        return derived switch
        {
            ProcessResult { ExitCode: 0 } output => output.Stdout,
            ProcessResult output => new Unauthorized($"ssh-keygen could not read the public key of {keyPath}: {output.Stderr.Trim()}"),
            OrchError error => error,
        };
    }

    private static OrchResult<SshPublicKey> ParsePublicKey(string text, string source)
    {
        var fields = text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var typeIndex = Array.IndexOf(fields, KeyType);
        if (typeIndex < 0 || typeIndex + 1 >= fields.Length || !Base64.IsValid(fields[typeIndex + 1]))
        {
            return new Validation($"{source} is not an {KeyType} public key; ts-orch signs in with Ed25519 keys only.");
        }

        var encoded = fields[typeIndex + 1];
        var blob = Convert.FromBase64String(encoded);
        if (!IsEd25519Blob(blob))
        {
            return new Validation($"{source} carries a malformed {KeyType} key blob.");
        }

        var fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
        return new SshPublicKey($"{KeyType} {encoded}", fingerprint);
    }

    private static bool IsEd25519Blob(ReadOnlySpan<byte> blob)
    {
        var type = Encoding.ASCII.GetBytes(KeyType);
        return blob.Length == 4 + type.Length + 4 + Ed25519KeyLength
            && BinaryPrimitives.ReadUInt32BigEndian(blob) == type.Length
            && blob.Slice(4, type.Length).SequenceEqual(type)
            && BinaryPrimitives.ReadUInt32BigEndian(blob[(4 + type.Length)..]) == Ed25519KeyLength;
    }

    private static Task<OrchResult<string>> SignAsync(string keyPath, string nonce, bool interactive, CancellationToken cancellationToken) =>
        CliFiles.WithScratchFileAsync(
            "challenge",
            nonce,
            async (challengeFile, token) =>
            {
                var signed = await ExternalProcess.RunAsync(
                    "ssh-keygen",
                    ["-Y", "sign", "-n", SignatureNamespace, "-f", keyPath, challengeFile],
                    interactive,
                    token);
                return signed switch
                {
                    ProcessResult { ExitCode: 0 } => await CliFiles.ReadTextAsync(challengeFile + ".sig", token),
                    ProcessResult output => new Unauthorized($"ssh-keygen could not sign the login challenge with {keyPath}: {output.Stderr.Trim()}"),
                    OrchError error => error,
                };
            },
            cancellationToken);
}
