using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsAuthenticationFilesTests
{
    [Test]
    public async Task Credentials_bind_the_JWT_subject_to_the_actual_user_seed()
    {
        var directory = Directory.CreateTempSubdirectory("ts-nats-credentials-");
        try
        {
            var seed = NKeys.CreateUserSeed();
            var path = Path.Combine(directory.FullName, "user.creds");
            await WritePrivateAsync(path, Credentials(seed));
            var authentication = NatsAuthenticationFiles.FromCredentialsFile(path, "TS_TEST");
            await Assert.That(authentication.PublicKey).IsEqualTo(NKeys.PublicKeyFromSeed(seed));
            await Assert.That(authentication.NKeyFile).IsNull();
            await Assert.That(authentication.Options.CredsFile).IsEqualTo(path);
            await Assert.That(() => NatsAuthenticationFiles.Resolve("unused", path, "TS_TEST"))
                .Throws<ArgumentException>();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    [Arguments("missing-jwt")]
    [Arguments("missing-seed")]
    [Arguments("duplicate-jwt")]
    [Arguments("duplicate-seed")]
    [Arguments("multiple-lines")]
    [Arguments("wrong-subject")]
    [Arguments("account-seed")]
    [Arguments("duplicate-subject")]
    [Arguments("duplicate-type")]
    [Arguments("duplicate-algorithm")]
    [Arguments("wrong-type")]
    [Arguments("wrong-version")]
    [Arguments("wrong-algorithm")]
    [Arguments("malformed-encoding")]
    [Arguments("padded-encoding")]
    [Arguments("noncanonical-encoding")]
    [Arguments("short-signature")]
    public async Task Ambiguous_or_mismatched_credentials_fail_without_disclosing_content(string corruption)
    {
        var directory = Directory.CreateTempSubdirectory("ts-nats-credentials-");
        try
        {
            var seed = NKeys.CreateUserSeed();
            var subject = NKeys.PublicKeyFromSeed(seed);
            var header = "{\"alg\":\"ed25519-nkey\",\"typ\":\"JWT\"}";
            var payload = JsonSerializer.Serialize(new { sub = subject, nats = new { type = "user", version = 2 } });
            var jwt = Encode(header) + "." + Encode(payload) + "." + Encode(new byte[64]);
            var jwtBlock = "-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n";
            var seedBlock = "-----BEGIN USER NKEY SEED-----\n" + seed + "\n------END USER NKEY SEED------\n";
            var contents = corruption switch
            {
                "missing-jwt" => seedBlock,
                "missing-seed" => jwtBlock,
                "duplicate-jwt" => jwtBlock + jwtBlock + seedBlock,
                "duplicate-seed" => jwtBlock + seedBlock + seedBlock,
                "multiple-lines" => jwtBlock + seedBlock.Replace(seed, seed + "\n" + seed, StringComparison.Ordinal),
                "wrong-subject" => jwtBlock + seedBlock.Replace(seed, NKeys.CreateUserSeed(), StringComparison.Ordinal),
                "account-seed" => Credentials(NKeys.CreateAccountSeed()),
                "duplicate-subject" => Malformed(header, payload.Replace("\"sub\":", "\"sub\":\"U-other\",\"sub\":", StringComparison.Ordinal)),
                "duplicate-type" => Malformed(header, payload.Replace("\"type\":", "\"type\":\"account\",\"type\":", StringComparison.Ordinal)),
                "duplicate-algorithm" => Malformed(header.Replace("\"alg\":", "\"alg\":\"none\",\"alg\":", StringComparison.Ordinal), payload),
                "wrong-type" => Malformed(header, payload.Replace("user", "account", StringComparison.Ordinal)),
                "wrong-version" => Malformed(header, payload.Replace(":2", ":1", StringComparison.Ordinal)),
                "wrong-algorithm" => Malformed(header.Replace("ed25519-nkey", "none", StringComparison.Ordinal), payload),
                "malformed-encoding" => jwtBlock.Replace(jwt, "!." + Encode(payload) + "." + Encode(new byte[64]), StringComparison.Ordinal) + seedBlock,
                "padded-encoding" => jwtBlock.Replace(jwt, jwt + "==", StringComparison.Ordinal) + seedBlock,
                "noncanonical-encoding" => jwtBlock.Replace(jwt, jwt[..^1] + "B", StringComparison.Ordinal) + seedBlock,
                "short-signature" => jwtBlock.Replace(jwt, Encode(header) + "." + Encode(payload) + "." + Encode(new byte[63]), StringComparison.Ordinal) + seedBlock,
                _ => throw new ArgumentOutOfRangeException(nameof(corruption)),
            };
            var path = Path.Combine(directory.FullName, "user.creds");
            await WritePrivateAsync(path, contents);
            var error = await Assert.That(() => NatsAuthenticationFiles.FromCredentialsFile(path, "TS_TEST"))
                .Throws<ArgumentException>();
            await Assert.That(error!.Message).DoesNotContain(seed);
            await Assert.That(error.Message).DoesNotContain(jwt);
            await Assert.That(error.InnerException).IsNull();

            string Malformed(string h, string p) => jwtBlock.Replace(jwt,
                Encode(h) + "." + Encode(p) + "." + Encode(new byte[64]), StringComparison.Ordinal) + seedBlock;
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    // Real signatures for file/configuration tests. Trust is established by the
    // server; these disposable issuers are never deployed to a NATS account.
    internal static string Credentials(string seed)
    {
        var issuer = NKeys.CreateAccountSeed();
        var header = Encode("{\"alg\":\"ed25519-nkey\",\"typ\":\"JWT\"}");
        var body = Encode(JsonSerializer.Serialize(new
        {
            iss = NKeys.PublicKeyFromSeed(issuer), sub = NKeys.PublicKeyFromSeed(seed),
            nats = new { type = "user", version = 2 },
        }));
        using var key = NKeys.FromSeed(issuer);
        var jwt = header + "." + body + "." + Encode(key.Sign(Encoding.ASCII.GetBytes(header + "." + body)));
        return $"-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n" +
               $"-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n";
    }

    internal sealed class SeedFile : IDisposable
    {
        internal SeedFile()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"ts-nats-seed-{Guid.NewGuid():N}.nk");
            File.WriteAllText(Path, NKeys.CreateUserSeed());
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        internal string Path { get; }
        public void Dispose() => File.Delete(Path);
    }

    [Test]
    public async Task NKey_factory_returns_the_key_identity_instead_of_the_filename()
    {
        using var seed = new SeedFile();
        var authentication = NatsAuthenticationFiles.FromNKeyFile(seed.Path);
        await Assert.That(authentication.PublicKey).IsEqualTo(NKeys.PublicKeyFromSeed(File.ReadAllText(seed.Path)));
    }

    private static string Encode(string text) => Encode(Encoding.UTF8.GetBytes(text));
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static async Task WritePrivateAsync(string path, string contents)
    {
        await File.WriteAllTextAsync(path, contents);
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
