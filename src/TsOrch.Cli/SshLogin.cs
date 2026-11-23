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

    public static async Task<Result<CliSession, Validation, Unauthorized, Forbidden, Unavailable>> LoginAsync(
        OrchHttp http,
        Uri baseUrl,
        string keyPath,
        string sessionFile,
        bool interactive,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        return await ReadPublicKeyAsync(keyPath, interactive, cancellationToken) switch
        {
            SshPublicKey key => await ChallengeAsync(http, baseUrl, key, keyPath, sessionFile, interactive, cancellationToken),
            Validation failure => failure,
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    public static bool KeyAvailable(string keyPath) => File.Exists(keyPath) || File.Exists(PublicKeyPath(keyPath));

    private static string PublicKeyPath(string keyPath) =>
        keyPath.EndsWith(".pub", StringComparison.Ordinal) ? keyPath : keyPath + ".pub";

    private static async Task<Result<CliSession, Validation, Unauthorized, Forbidden, Unavailable>> ChallengeAsync(
        OrchHttp http,
        Uri baseUrl,
        SshPublicKey key,
        string keyPath,
        string sessionFile,
        bool interactive,
        CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(
            HttpMethod.Post,
            baseUrl,
            "/api/auth/ssh/challenge",
            token: null,
            OrchHttp.JsonBody(new SshChallengeRequest(key.Fingerprint), ApiJsonContext.Default.SshChallengeRequest));
        return await http.SendJsonAsync(request, ApiJsonContext.Default.SshChallengeResponse, OrchHttp.DefaultTimeout, cancellationToken) switch
        {
            SshChallengeResponse challenge when challenge.Namespace != SignatureNamespace =>
                new Validation($"The backplane asked for SSH namespace '{challenge.Namespace}', expected '{SignatureNamespace}'."),
            SshChallengeResponse challenge => await SignAsync(keyPath, challenge.Nonce, interactive, cancellationToken) switch
            {
                string signature => await VerifyAsync(http, baseUrl, key, challenge, signature, sessionFile, cancellationToken),
                Unauthorized failure => failure,
                Forbidden failure => failure,
                Unavailable failure => failure,
            },
            Validation failure => failure,
            NotFound failure => new Unauthorized(failure.Message),
            Conflict failure => new Unavailable(failure.Message),
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    private static async Task<Result<CliSession, Validation, Unauthorized, Forbidden, Unavailable>> VerifyAsync(
        OrchHttp http,
        Uri baseUrl,
        SshPublicKey key,
        SshChallengeResponse challenge,
        string signature,
        string sessionFile,
        CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(
            HttpMethod.Post,
            baseUrl,
            "/api/auth/ssh/verify",
            token: null,
            OrchHttp.JsonBody(new SshVerifyRequest(challenge.ChallengeId, key.Line, signature), ApiJsonContext.Default.SshVerifyRequest));
        return await http.SendJsonAsync(request, ApiJsonContext.Default.SshVerifyResponse, OrchHttp.DefaultTimeout, cancellationToken) switch
        {
            SshVerifyResponse verified => await SaveAsync(
                new CliSession(baseUrl.AbsoluteUri, verified.Token, verified.ExpiresAt, verified.Owner, verified.Role),
                sessionFile,
                cancellationToken),
            Validation failure => failure,
            NotFound failure => new Unauthorized(failure.Message),
            Conflict failure => new Unavailable(failure.Message),
            Unauthorized failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };
    }

    private static async Task<Result<CliSession, Validation, Unauthorized, Forbidden, Unavailable>> SaveAsync(
        CliSession session,
        string sessionFile,
        CancellationToken cancellationToken) =>
        await CliFiles.WritePrivateJsonAsync(sessionFile, session, CliJsonContext.Default.CliSession, cancellationToken) switch
        {
            Done => session,
            Validation failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
        };

    private static async Task<Result<SshPublicKey, Validation, Unauthorized, Forbidden, Unavailable>> ReadPublicKeyAsync(
        string keyPath,
        bool interactive,
        CancellationToken cancellationToken)
    {
        var publicKeyPath = PublicKeyPath(keyPath);
        if (File.Exists(publicKeyPath))
        {
            return await CliFiles.ReadTextAsync(publicKeyPath, cancellationToken) switch
            {
                string line => ParsePublicKey(line, publicKeyPath) switch
                {
                    SshPublicKey key => key,
                    Validation failure => failure,
                },
                NotFound failure => new Validation(failure.Message),
                Forbidden failure => failure,
                Unavailable failure => failure,
            };
        }

        return await DerivePublicKeyAsync(keyPath, interactive, cancellationToken) switch
        {
            string line => ParsePublicKey(line, publicKeyPath) switch
            {
                SshPublicKey key => key,
                Validation failure => failure,
            },
            Validation failure => failure,
            Unauthorized failure => failure,
            Unavailable failure => failure,
        };
    }

    private static async Task<Result<string, Validation, Unauthorized, Unavailable>> DerivePublicKeyAsync(string keyPath, bool interactive, CancellationToken cancellationToken)
    {
        if (!File.Exists(keyPath))
        {
            return new Validation($"SSH key {keyPath} does not exist; pass --key or set {OperatorSettings.KeyVariable}.");
        }

        return await ExternalProcess.RunAsync("ssh-keygen", ["-y", "-f", keyPath], interactive, cancellationToken) switch
        {
            ProcessResult { ExitCode: 0 } output => output.Stdout,
            ProcessResult output => new Unauthorized($"ssh-keygen could not read the public key of {keyPath}: {output.Stderr.Trim()}"),
            Unavailable failure => failure,
        };
    }

    private static Result<SshPublicKey, Validation> ParsePublicKey(string text, string source)
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

    private static Task<Result<string, Unauthorized, Forbidden, Unavailable>> SignAsync(string keyPath, string nonce, bool interactive, CancellationToken cancellationToken) =>
        CliFiles.WithScratchFileAsync(
            "challenge",
            nonce,
            async (challengeFile, token) => await ExternalProcess.RunAsync(
                "ssh-keygen",
                ["-Y", "sign", "-n", SignatureNamespace, "-f", keyPath, challengeFile],
                interactive,
                token) switch
            {
                ProcessResult { ExitCode: 0 } => await CliFiles.ReadTextAsync(challengeFile + ".sig", token) switch
                {
                    string signature => signature,
                    NotFound failure => new Unavailable(failure.Message),
                    Forbidden failure => failure,
                    Unavailable failure => failure,
                },
                ProcessResult output => new Unauthorized($"ssh-keygen could not sign the login challenge with {keyPath}: {output.Stderr.Trim()}"),
                Unavailable failure => failure,
            },
            cancellationToken);
}
