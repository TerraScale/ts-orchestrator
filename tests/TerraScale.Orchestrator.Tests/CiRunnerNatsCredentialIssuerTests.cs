using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerNatsCredentialIssuerTests
{
    [Test]
    public async Task TypedIdentityConfigurationIsAllOrNothing()
    {
        var path = Path.Combine(Path.GetTempPath(), "runner-account.nk");
        var configuration = CiRunnerNatsIdentityConfiguration.Resolve(path, null);

        await Assert.That(configuration!.SigningKeyFile).IsEqualTo(path);
        await Assert.That(configuration.AccountPublicKey).IsNull();
        await Assert.That(CiRunnerNatsIdentityConfiguration.Resolve(null, null)).IsNull();
        await Assert.That(() => CiRunnerNatsIdentityConfiguration.Resolve(null, "ACCOUNT"))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE" ? path : null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task IssuedJwtIsShortLivedAccountSignedAndExactlyScoped()
    {
        if (!OperatingSystem.IsLinux()) return;
        var seed = NKeys.CreateAccountSeed();
        var path = await WriteSeedAsync(seed);
        try
        {
            using var signer = NatsAccountJwtSigner.Open(path);
            var topology = new GlobalNatsTopology(3);
            var registration = Registration(topology, "untrusted-product", "runner-static");
            var issuer = new CiRunnerNatsCredentialIssuer(topology, signer);
            using var credential = await issuer.IssueAsync(
                registration,
                "runner-static",
                DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
                TimeSpan.FromMinutes(75));

            var chunks = credential.Jwt.Split('.');
            using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(chunks[0]));
            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(chunks[1]));
            var root = payload.RootElement;
            var nats = root.GetProperty("nats");
            var plan = CiRunnerNatsPermissions.Create(topology, registration.Zone, "runner-static");

            await Assert.That(chunks.Length).IsEqualTo(3);
            await Assert.That(header.RootElement.GetProperty("typ").GetString()).IsEqualTo("JWT");
            await Assert.That(header.RootElement.GetProperty("alg").GetString()).IsEqualTo("ed25519-nkey");
            await Assert.That(root.GetProperty("iss").GetString()).IsEqualTo(signer.IssuerPublicKey);
            await Assert.That(root.GetProperty("sub").GetString()).IsEqualTo(credential.PublicKey);
            await Assert.That(root.GetProperty("jti").GetString()).IsEqualTo(credential.LeaseId);
            await Assert.That(credential.LeaseId.Length).IsEqualTo(52);
            await Assert.That(root.GetProperty("iat").GetInt64()).IsEqualTo(1_800_000_000);
            await Assert.That(root.GetProperty("exp").GetInt64()).IsEqualTo(1_800_004_500);
            await Assert.That(nats.GetProperty("pub").GetProperty("allow").EnumerateArray()
                .Select(static value => value.GetString()!).ToArray()).IsEquivalentTo(plan.Publish);
            await Assert.That(nats.GetProperty("sub").GetProperty("allow").EnumerateArray()
                .Select(static value => value.GetString()!).ToArray()).IsEquivalentTo(plan.Subscribe);
            await Assert.That(nats.GetProperty("subs").GetInt32()).IsEqualTo(32);
            await Assert.That(nats.GetProperty("data").GetInt32()).IsEqualTo(-1);
            await Assert.That(nats.GetProperty("payload").GetInt32()).IsEqualTo(128 * 1024);
            await Assert.That(nats.GetProperty("allowed_connection_types")[0].GetString())
                .IsEqualTo("STANDARD");
            await Assert.That(nats.GetProperty("type").GetString()).IsEqualTo("user");
            await Assert.That(nats.GetProperty("version").GetInt32()).IsEqualTo(2);
            await Assert.That(nats.TryGetProperty("bearer_token", out _)).IsFalse();
            await Assert.That(nats.TryGetProperty("issuer_account", out _)).IsFalse();

            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-runner-creds-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
            var credentialsPath = Path.Combine(directory, "runner.creds");
            try
            {
                await File.WriteAllTextAsync(credentialsPath, "sentinel");
                await Assert.That(() => credential.WriteCredentialsFile(credentialsPath))
                    .Throws<IOException>();
                await Assert.That(await File.ReadAllTextAsync(credentialsPath)).IsEqualTo("sentinel");
                File.Delete(credentialsPath);

                credential.WriteCredentialsFile(credentialsPath);
                await using var connection = new NatsConnection(new NatsOpts
                {
                    Url = "nats://127.0.0.1:1",
                    RetryOnInitialConnect = false,
                    ConnectTimeout = TimeSpan.FromMilliseconds(100),
                    AuthOpts = new NatsAuthOpts { CredsFile = credentialsPath },
                });
                var parsed = false;
                try
                {
                    await connection.ConnectAsync();
                }
                catch (NatsException exception)
                {
                    parsed = exception.Message.Contains("can not connect uris", StringComparison.Ordinal);
                }
                await Assert.That(parsed).IsTrue();
                await Assert.That(File.GetUnixFileMode(credentialsPath))
                    .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }

            var signingInput = Encoding.ASCII.GetBytes($"{chunks[0]}.{chunks[1]}");
            using var pair = NKeys.FromSeed(seed);
            await Assert.That(Base64Url.DecodeFromChars(chunks[2])).IsEquivalentTo(pair.Sign(signingInput));
            await Assert.That(credential.ToString()).DoesNotContain(credential.Jwt);
            _ = credential.CreateAuthCredential();
            credential.Dispose();
            await Assert.That(() => credential.CreateAuthCredential())
                .Throws<ObjectDisposedException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task ScopedSigningKeyNamesItsIssuerAccount()
    {
        if (!OperatingSystem.IsLinux()) return;
        var signingSeed = NKeys.CreateAccountSeed();
        var accountSeed = NKeys.CreateAccountSeed();
        var account = NKeys.PublicKeyFromSeed(accountSeed);
        var path = await WriteSeedAsync(signingSeed);
        try
        {
            using var signer = NatsAccountJwtSigner.Open(path, account);
            var topology = new GlobalNatsTopology(3);
            using var credential = await new CiRunnerNatsCredentialIssuer(topology, signer).IssueAsync(
                Registration(topology, "trusted-build", "runner-build"),
                "runner-build",
                DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
                TimeSpan.FromMinutes(5));
            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(credential.Jwt.Split('.')[1]));

            await Assert.That(payload.RootElement.GetProperty("nats")
                .GetProperty("issuer_account").GetString()).IsEqualTo(account);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task IssuanceRequiresExactConsumerAndBoundedWholeSecondLifetime()
    {
        if (!OperatingSystem.IsLinux()) return;
        var path = await WriteSeedAsync(NKeys.CreateAccountSeed());
        try
        {
            using var signer = NatsAccountJwtSigner.Open(path);
            var topology = new GlobalNatsTopology(3);
            var issuer = new CiRunnerNatsCredentialIssuer(topology, signer);
            var registration = Registration(topology, "untrusted-product", "runner-static");
            var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

            await Assert.That(async () => await issuer.IssueAsync(
                    registration with { Subject = "ts.orch.v1.global.ci.job.>" },
                    "runner-static",
                    now,
                    TimeSpan.FromMinutes(5)))
                .Throws<InvalidOperationException>();
            await Assert.That(async () => await issuer.IssueAsync(
                    registration,
                    "runner-static",
                    now,
                    TimeSpan.FromMinutes(75) + TimeSpan.FromSeconds(1)))
                .Throws<ArgumentOutOfRangeException>();
            await Assert.That(async () => await issuer.IssueAsync(
                    registration,
                    "runner-static",
                    now,
                    TimeSpan.FromMinutes(1) + TimeSpan.FromTicks(1)))
                .Throws<ArgumentOutOfRangeException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task AccountSigningCredentialRejectsWrongKeyTypeAndPublicFileMode()
    {
        if (!OperatingSystem.IsLinux()) return;
        var userPath = await WriteSeedAsync(NKeys.CreateUserSeed());
        var accountPath = await WriteSeedAsync(NKeys.CreateAccountSeed());
        try
        {
            await Assert.That(() => NatsAccountJwtSigner.Open(userPath)).Throws<ArgumentException>();
            File.SetUnixFileMode(accountPath, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => NatsAccountJwtSigner.Open(accountPath)).Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(userPath);
            File.Delete(accountPath);
        }
    }

    private static CiRunnerConsumerRegistration Registration(
        GlobalNatsTopology topology,
        string zone,
        string runner)
    {
        var consumer = topology.CiJobConsumer(zone, runner);
        return new(zone, consumer.Name!, consumer.FilterSubject!);
    }

    private static async Task<string> WriteSeedAsync(string seed)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var path = Path.Combine(Path.GetTempPath(), $"ts-orch-runner-account-{Guid.NewGuid():N}.nk");
        await File.WriteAllTextAsync(path, seed);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }
}
