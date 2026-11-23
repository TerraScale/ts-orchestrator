using System.Buffers.Binary;
using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TsOrch.Cli;

internal sealed record class SshPublicKey(string Line, string Fingerprint);

internal sealed record class SshKeyInvalid(string Message);

internal sealed record class SshKeyUnreadable(CliDiagnostic Diagnostic);

internal sealed record class SshChallengeNamespaceInvalid(string ActualNamespace);

internal sealed record class SshSigningFailed(string KeyPath, string Detail);

internal sealed record class SshChallengeFileUnavailable(string Path, string Detail);

internal sealed record class SshBackplaneRejected(BackplaneProblem Problem);

internal sealed record class SshSessionWriteFailed(CliDiagnostic Diagnostic);

internal readonly union SshLoginOutcome(CliSession, SshKeyInvalid, SshKeyUnreadable, ProcessLaunchFailed,
    SshChallengeNamespaceInvalid, SshSigningFailed, SshChallengeFileUnavailable, SshBackplaneRejected, SshSessionWriteFailed);

internal static class SshLogin
{
    public const string SignatureNamespace = "ts-orch";

    private const string KeyType = "ssh-ed25519";
    private const int Ed25519KeyLength = 32;

    public static async Task<SshLoginOutcome> LoginAsync(
        OrchHttp http, Uri baseUrl, string keyPath, string sessionFile, bool interactive, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        var read = await ReadPublicKeyAsync(keyPath, interactive, cancellationToken);
        return read switch
        {
            SshPublicKey key => await ChallengeAsync(http, baseUrl, key, keyPath, sessionFile, interactive, cancellationToken),
            SshKeyInvalid invalid => invalid,
            SshKeyUnreadable unreadable => unreadable,
            ProcessLaunchFailed failed => failed,
        };
    }

    public static bool KeyAvailable(string keyPath) => File.Exists(keyPath) || File.Exists(PublicKeyPath(keyPath));

    public static CliDiagnostic Describe(SshBackplaneRejected rejected) => rejected.Problem switch
    {
        BackplaneRequestRejected { Status: HttpStatusCode.NotFound } failure => CliDiagnostic.Permission(failure.Message),
        BackplaneRequestRejected { Status: HttpStatusCode.Conflict } failure => CliDiagnostic.Unavailable(failure.Message),
        BackplaneRequestRejected or BackplaneTransportFailed or BackplaneResponseInvalid or BackplaneAuthenticationFailed => CliDiagnostic.From(rejected.Problem),
    };

    public static CliDiagnostic Describe(SshChallengeNamespaceInvalid invalid) =>
        CliDiagnostic.Usage($"The backplane asked for SSH namespace '{invalid.ActualNamespace}', expected '{SignatureNamespace}'.");

    public static CliDiagnostic Describe(SshSigningFailed failed) =>
        CliDiagnostic.Permission($"ssh-keygen could not use {failed.KeyPath}: {failed.Detail}");

    public static CliDiagnostic Describe(SshChallengeFileUnavailable failed) =>
        CliDiagnostic.Unavailable($"SSH challenge file {failed.Path} is unavailable: {failed.Detail}");

    private static string PublicKeyPath(string keyPath) =>
        keyPath.EndsWith(".pub", StringComparison.Ordinal) ? keyPath : keyPath + ".pub";

    private static async Task<SshLoginOutcome> ChallengeAsync(
        OrchHttp http, Uri baseUrl, SshPublicKey key, string keyPath, string sessionFile, bool interactive, CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(HttpMethod.Post, baseUrl, "/api/auth/ssh/challenge", null,
            OrchHttp.JsonBody(new SshChallengeRequest(key.Fingerprint), ApiJsonContext.Default.SshChallengeRequest));
        return await http.SendJsonAsync(request, ApiJsonContext.Default.SshChallengeResponse, OrchHttp.DefaultTimeout,
            challenge => AnswerChallengeAsync(http, baseUrl, key, keyPath, sessionFile, interactive, challenge, cancellationToken),
            static problem => new SshBackplaneRejected(problem), cancellationToken);
    }

    private static async Task<SshLoginOutcome> AnswerChallengeAsync(
        OrchHttp http, Uri baseUrl, SshPublicKey key, string keyPath, string sessionFile, bool interactive,
        SshChallengeResponse challenge, CancellationToken cancellationToken)
    {
        if (challenge.Namespace != SignatureNamespace)
        {
            return new SshChallengeNamespaceInvalid(challenge.Namespace);
        }

        var signed = await SignAsync(keyPath, challenge.Nonce, interactive, cancellationToken);
        return signed switch
        {
            string signature => await VerifyAsync(http, baseUrl, key, challenge, signature, sessionFile, cancellationToken),
            SshSigningFailed failed => failed,
            SshChallengeFileUnavailable unavailable => unavailable,
            ProcessLaunchFailed failed => failed,
        };
    }

    private static async Task<SshLoginOutcome> VerifyAsync(OrchHttp http, Uri baseUrl, SshPublicKey key, SshChallengeResponse challenge,
        string signature, string sessionFile, CancellationToken cancellationToken)
    {
        using var request = OrchHttp.CreateRequest(HttpMethod.Post, baseUrl, "/api/auth/ssh/verify", null,
            OrchHttp.JsonBody(new SshVerifyRequest(challenge.ChallengeId, key.Line, signature), ApiJsonContext.Default.SshVerifyRequest));
        return await http.SendJsonAsync(request, ApiJsonContext.Default.SshVerifyResponse, OrchHttp.DefaultTimeout,
            verified => SaveAsync(new CliSession(baseUrl.AbsoluteUri, verified.Token, verified.ExpiresAt, verified.Owner, verified.Role), sessionFile, cancellationToken),
            static problem => new SshBackplaneRejected(problem), cancellationToken);
    }

    private static async Task<SshLoginOutcome> SaveAsync(CliSession session, string sessionFile, CancellationToken cancellationToken)
    {
        var written = await CliFiles.WritePrivateJsonAsync(sessionFile, session, CliJsonContext.Default.CliSession, cancellationToken);
        return written switch
        {
            PrivateFileWritten => session,
            PrivateFileTargetInvalid invalid => new SshSessionWriteFailed(CliDiagnostic.Usage(invalid.Message)),
            PrivateFileWriteDenied denied => new SshSessionWriteFailed(new CliDiagnostic("forbidden", $"Writing {denied.Path} is not allowed: {denied.Detail}", ExitCodes.NoPermission)),
            PrivateFileWriteInterrupted interrupted => new SshSessionWriteFailed(CliDiagnostic.Unavailable($"Writing {interrupted.Path} failed: {interrupted.Detail}")),
        };
    }

    private static async Task<SshPublicKeyRead> ReadPublicKeyAsync(string keyPath, bool interactive, CancellationToken cancellationToken)
    {
        var publicKeyPath = PublicKeyPath(keyPath);
        if (File.Exists(publicKeyPath))
        {
            var read = await CliFiles.ReadTextAsync(publicKeyPath, cancellationToken);
            return read switch
            {
                string line => ParseReadKey(line, publicKeyPath),
                CliFileReadProblem failure => new SshKeyUnreadable(CliFiles.Describe(failure)),
            };
        }

        if (!File.Exists(keyPath))
        {
            return new SshKeyInvalid($"SSH key {keyPath} does not exist; pass --key or set {OperatorSettings.KeyVariable}.");
        }

        var derived = await ExternalProcess.RunAsync("ssh-keygen", ["-y", "-f", keyPath], interactive, cancellationToken);
        return derived switch
        {
            ProcessResult { ExitCode: 0 } output => ParseReadKey(output.Stdout, keyPath),
            ProcessResult output => new SshKeyUnreadable(CliDiagnostic.Permission($"ssh-keygen could not read the public key of {keyPath}: {output.Stderr.Trim()}")),
            ProcessLaunchFailed failed => failed,
        };
    }

    private static SshPublicKeyRead ParseReadKey(string line, string path) =>
        ParsePublicKey(line, path) switch
        {
            SshPublicKey key => key,
            SshKeyInvalid invalid => invalid,
        };

    private static SshKeyParse ParsePublicKey(string text, string source)
    {
        var fields = text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var typeIndex = Array.IndexOf(fields, KeyType);
        if (typeIndex < 0 || typeIndex + 1 >= fields.Length || !Base64.IsValid(fields[typeIndex + 1]))
        {
            return new SshKeyInvalid($"{source} is not an {KeyType} public key; ts-orch signs in with Ed25519 keys only.");
        }

        var encoded = fields[typeIndex + 1];
        var blob = Convert.FromBase64String(encoded);
        if (!IsEd25519Blob(blob))
        {
            return new SshKeyInvalid($"{source} carries a malformed {KeyType} key blob.");
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

    private static async Task<SshChallengeSignature> SignAsync(string keyPath, string nonce, bool interactive, CancellationToken cancellationToken)
    {
        var scratch = await CreateChallengeFileAsync(nonce, cancellationToken);
        return scratch switch
        {
            ChallengeFile file => await SignFileAsync(file, keyPath, interactive, cancellationToken),
            SshChallengeFileUnavailable unavailable => unavailable,
        };
    }

    private static async Task<SshChallengeFile> CreateChallengeFileAsync(string nonce, CancellationToken cancellationToken)
    {
        DirectoryInfo? directory = null;
        var created = false;
        try
        {
            directory = Directory.CreateTempSubdirectory("ts-orch-");
            var path = Path.Combine(directory.FullName, "challenge");
            await File.WriteAllTextAsync(path, nonce, cancellationToken);
            created = true;
            return new ChallengeFile(directory, path);
        }
        catch (IOException exception)
        {
            return new SshChallengeFileUnavailable(directory?.FullName ?? Path.GetTempPath(), exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return new SshChallengeFileUnavailable(directory?.FullName ?? Path.GetTempPath(), exception.Message);
        }
        finally
        {
            if (!created)
            {
                directory?.Delete(recursive: true);
            }
        }
    }

    private static async Task<SshChallengeSignature> SignFileAsync(ChallengeFile file, string keyPath, bool interactive, CancellationToken cancellationToken)
    {
        try
        {
            var signed = await ExternalProcess.RunAsync("ssh-keygen", ["-Y", "sign", "-n", SignatureNamespace, "-f", keyPath, file.Path], interactive, cancellationToken);
            return signed switch
            {
                ProcessResult { ExitCode: 0 } => await ReadSignatureAsync(file.Path + ".sig", cancellationToken),
                ProcessResult output => new SshSigningFailed(keyPath, output.Stderr.Trim()),
                ProcessLaunchFailed failed => failed,
            };
        }
        finally
        {
            file.Directory.Delete(recursive: true);
        }
    }

    private static async Task<SshChallengeSignature> ReadSignatureAsync(string path, CancellationToken cancellationToken)
    {
        var read = await CliFiles.ReadTextAsync(path, cancellationToken);
        return read switch
        {
            string signature => signature,
            CliFileReadProblem failed => new SshChallengeFileUnavailable(path, CliFiles.Describe(failed).Message),
        };
    }

    private sealed record class ChallengeFile(DirectoryInfo Directory, string Path);

    private readonly union SshChallengeFile(ChallengeFile, SshChallengeFileUnavailable);

    private readonly union SshChallengeSignature(string, SshSigningFailed, SshChallengeFileUnavailable, ProcessLaunchFailed);

    private readonly union SshPublicKeyRead(SshPublicKey, SshKeyInvalid, SshKeyUnreadable, ProcessLaunchFailed);

    private readonly union SshKeyParse(SshPublicKey, SshKeyInvalid);
}
