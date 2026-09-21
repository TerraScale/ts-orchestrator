using System.Security.Cryptography;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostSessionConfigurationTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Internal_service_start_timeout_is_a_failure_while_caller_cancellation_stays_distinct(bool callerCancels)
    {
        using var material = new SessionMaterial();
        var store = DispatchProxy.Create<INatsKVStore, WithheldStoreStatus>();
        var authority = new RegionalHostSessionAuthority(store, material.Policy());
        await using var connection = new NatsConnection();
        using var caller = new CancellationTokenSource();
        if (callerCancels) caller.CancelAfter(TimeSpan.FromMilliseconds(100));
        var start = RegionalHostSessionService.StartAsync(connection, authority, caller.Token);
        if (callerCancels)
            await Assert.That(async () => _ = await start.WaitAsync(TimeSpan.FromSeconds(8))).Throws<OperationCanceledException>();
        else
        {
            var failure = await Assert.That(async () => _ = await start.WaitAsync(TimeSpan.FromSeconds(8))).Throws<TimeoutException>();
            await Assert.That(failure!.Message).IsEqualTo("The regional host-session service startup timed out.");
        }
    }

    [Test]
    public async Task Loaded_public_policy_verifies_enrollment_and_typed_configuration_resolves_its_path()
    {
        using var material = new SessionMaterial();
        using var file = new PolicyFile(material.ConfigurationJson());
        var configuration = RegionalHostSessionConfiguration.Load(file.Path, "gru")!;
        var now = material.Clock.GetUtcNow();
        await Assert.That(configuration.Policy.AllowsFreshEnrollment(material.Enroll(1), now, now.AddSeconds(30))).IsTrue();
        await Assert.That(RegionalHostSessionConfiguration.Load(null, "gru")).IsNull();
        using var runtimeFile = new PolicyFile(JsonSerializer.Serialize(new { schemaVersion = 1, hostSessionPolicyFile = file.Path }));
        var runtime = OrchestratorRuntimeConfiguration.Load(runtimeFile.Path)!;
        await Assert.That(runtime.GetEnvironmentValue("TS_ORCH_HOST_SESSION_POLICY_FILE")).IsEqualTo(file.Path);
    }

    [Test]
    [Arguments("schema")]
    [Arguments("cell")]
    [Arguments("unknown")]
    [Arguments("duplicate")]
    [Arguments("missing")]
    [Arguments("null")]
    [Arguments("role")]
    [Arguments("duplicate-role")]
    [Arguments("account")]
    [Arguments("lifetime")]
    [Arguments("grant-key")]
    [Arguments("signer-key")]
    [Arguments("trailing-key")]
    public async Task Invalid_controller_policy_is_rejected_before_connection(string mutation)
    {
        using var material = new SessionMaterial();
        var document = JsonNode.Parse(material.ConfigurationJson())!;
        switch (mutation)
        {
            case "schema": document["schemaVersion"] = 2; break;
            case "cell": document["cell"] = "fra"; break;
            case "unknown": document["unreviewed"] = true; break;
            case "missing": document.AsObject().Remove("enrollmentSignerKeyId"); break;
            case "null": document["roles"] = null; break;
            case "role": document["roles"]![0] = "unknown"; break;
            case "duplicate-role": document["roles"]![1] = "terrabase-member"; break;
            case "account": document["natsAccountPublicKey"] = material.Authentication.PublicKey; break;
            case "lifetime": document["maximumGrantLifetimeSeconds"] = 86401; break;
            case "grant-key": document["bootstrapTrust"]!["keys"]![0]!["subjectPublicKeyInfo"] = Convert.ToBase64String(new byte[32]); break;
            case "signer-key":
                using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                    document["enrollmentSignerPublicKey"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
                break;
            case "trailing-key":
                document["enrollmentSignerPublicKey"] = Convert.ToBase64String([
                    .. Convert.FromBase64String(document["enrollmentSignerPublicKey"]!.GetValue<string>()), 0]);
                break;
        }
        var json = document.ToJsonString();
        if (mutation == "duplicate") json = "{\"schemaVersion\":1," + json[1..];
        using var file = new PolicyFile(json);
        var exception = await Assert.That(() => RegionalHostSessionConfiguration.Load(file.Path, "gru")).Throws<Exception>();
        await Assert.That(exception is ArgumentException or InvalidDataException or JsonException or CryptographicException).IsTrue();
    }

    [Test]
    public async Task Policy_files_reject_writable_or_linked_material_and_oversized_documents()
    {
        using var material = new SessionMaterial();
        using var file = new PolicyFile(material.ConfigurationJson());
        var link = file.Path + ".link";
        try
        {
            File.CreateSymbolicLink(link, file.Path);
            await Assert.That(() => RegionalHostSessionConfiguration.Load(link, "gru")).Throws<ArgumentException>();
            if (OperatingSystem.IsLinux())
            {
                File.SetUnixFileMode(file.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite);
                await Assert.That(() => RegionalHostSessionConfiguration.Load(file.Path, "gru")).Throws<ArgumentException>();
            }
        }
        finally { File.Delete(link); }
        using var large = new PolicyFile(new string(' ', 32769));
        await Assert.That(() => RegionalHostSessionConfiguration.Load(large.Path, "gru")).Throws<ArgumentException>();
    }

    [Test]
    public async Task Session_authority_rejects_wrong_region_replication_and_host_role_before_NATS()
    {
        using var material = new SessionMaterial();
        using var file = new PolicyFile(material.ConfigurationJson());
        var configuration = RegionalHostSessionConfiguration.Load(file.Path, "gru")!;
        var options = new OrchestratorOptions(OrchestratorCommand.Check, "gru", "nats://127.0.0.1:1", 3);
        await Assert.That(async () => _ = await NatsRuntime.StartAsync(options, CancellationToken.None, hostSessions: configuration))
            .Throws<InvalidOperationException>();
        await Assert.That(() => configuration.ValidateStartup(options with { Cell = "fra" }, false)).Throws<InvalidOperationException>();
        await Assert.That(() => configuration.ValidateStartup(options with { Replicas = 1 }, false)).Throws<InvalidOperationException>();
        await Assert.That(() => configuration.ValidateStartup(options, true)).Throws<InvalidOperationException>();
    }

    private sealed class PolicyFile : IDisposable
    {
        internal PolicyFile(string contents)
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ts-session-policy-" + Guid.NewGuid().ToString("N") + ".json");
            File.WriteAllText(Path, contents);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        internal string Path { get; }
        public void Dispose() => File.Delete(Path);
    }

    public class WithheldStoreStatus : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.Name == nameof(INatsKVStore.GetStatusAsync)
                ? new ValueTask<NatsKVStatus>(WaitAsync((CancellationToken)args![0]!))
                : throw new NotSupportedException();

        private static async Task<NatsKVStatus> WaitAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("The withheld store must not return a status.");
        }
    }
}
