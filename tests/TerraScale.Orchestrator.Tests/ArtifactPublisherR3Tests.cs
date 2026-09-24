using System.Security.Cryptography;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery.Artifacts;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Operations;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel]
public sealed class ArtifactPublisherR3Tests
{
    [Test]
    [Arguments(0)]
    [Arguments(17)]
    public async Task Real_cli_concurrent_and_repeated_publication_is_readable_after_broker_restart_without_purge_authority(int tailBytes)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await using var cluster = await NatsControlR3L0cFixture.StartAsync(deadline.Token);
        await cluster.ProvisionAsync(deadline.Token);
        var bytes = RandomNumberGenerator.GetBytes(2 * ImmutableArtifactPublisher.ChunkBytes + tailBytes);
        var path = Path.Combine(cluster.DirectoryPath, "artifact");
        await File.WriteAllBytesAsync(path, bytes, deadline.Token);
        var results = await Task.WhenAll(Cli(cluster, path, false, deadline.Token), Cli(cluster, path, true, deadline.Token));
        await Assert.That(results.All(result => result == 0)).IsTrue();
        await using var controller = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        var objects = await controller.CreateJetStreamContext().CreateObjectStoreContext().GetObjectStoreAsync("ORCH_ARTIFACTS", deadline.Token);
        var digest = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));
        var before = (await objects.GetStatusAsync(deadline.Token)).Info.State;
        await Assert.That(before.Messages).IsEqualTo(tailBytes == 0 ? 3L : 4L);
        await Assert.That((await objects.GetBytesAsync("sha256-" + digest[7..], deadline.Token)).SequenceEqual(bytes)).IsTrue();
        // Exercise the actual controller cache reader as well as the SDK object reader.
        using var cache = new RegionalArtifactCache(new NatsRegionalArtifactDownloader(objects));
        var downloaded = await cache.ReadAsync(digest, 0, bytes.Length, deadline.Token);
        await Assert.That(downloaded.Bytes.SequenceEqual(bytes)).IsTrue();
        await cluster.KillMemberAsync(2, deadline.Token);
        await cluster.RestartMemberAsync(2, deadline.Token);
        await Assert.That(await Cli(cluster, path, false, deadline.Token)).IsEqualTo(0);
        var after = (await objects.GetStatusAsync(deadline.Token)).Info.State;
        await Assert.That(after.Messages).IsEqualTo(before.Messages);
        await Assert.That(after.Bytes).IsEqualTo(before.Bytes);
        await Assert.That(after.LastSeq).IsEqualTo(before.LastSeq);
        var permissions = RegionalNatsPermissions.Create("gru", "controller-1", cluster.Controller.PublicKey);
        await Assert.That(permissions.Publish.Any(subject => subject.Contains("PURGE", StringComparison.Ordinal))).IsFalse();
        await using var host = await cluster.ConnectAsync(cluster.HostAgent, cancellationToken: deadline.Token);
        await Assert.That(async () => _ = await NatsArtifactPublicationStore.OpenAsync(host.CreateJetStreamContext(), "gru", deadline.Token))
            .Throws<NatsException>();
    }

    [Test]
    [Arguments(1)]
    [Arguments(3)]
    public async Task Restricted_R3_lost_ack_retry_through_cli_resumes_the_same_durable_object(int lostAppend)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var cluster = await NatsControlR3L0cFixture.StartAsync(deadline.Token);
        await cluster.ProvisionAsync(deadline.Token);
        var bytes = RandomNumberGenerator.GetBytes(ImmutableArtifactPublisher.ChunkBytes + 17);
        var path = Path.Combine(cluster.DirectoryPath, "artifact");
        await File.WriteAllBytesAsync(path, bytes, deadline.Token);
        await using (var first = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token))
        {
            var store = await NatsArtifactPublicationStore.OpenAsync(first.CreateJetStreamContext(), "gru", deadline.Token);
            await using var snapshot = await ArtifactPublicationSnapshot.CaptureAsync(new MemoryStream(bytes), deadline.Token);
            await Assert.That(async () => _ = await new ImmutableArtifactPublisher(new LostAck(store, lostAppend)).PublishAsync(snapshot, deadline.Token))
                .Throws<IOException>();
        }
        await Assert.That(await Cli(cluster, path, true, deadline.Token)).IsEqualTo(0);
        await using var second = await cluster.ConnectAsync(cluster.ControllerTwo, cancellationToken: deadline.Token);
        var objects = await second.CreateJetStreamContext().CreateObjectStoreContext().GetObjectStoreAsync("ORCH_ARTIFACTS", deadline.Token);
        await Assert.That((await objects.GetStatusAsync(deadline.Token)).Info.State.Messages).IsEqualTo(3L);
        await Assert.That((await objects.GetBytesAsync("sha256-" + Convert.ToHexStringLower(SHA256.HashData(bytes)), deadline.Token))
            .SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    public async Task Real_cli_rejects_poisoned_existing_metadata_without_replacing_it()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var cluster = await NatsControlR3L0cFixture.StartAsync(deadline.Token);
        await cluster.ProvisionAsync(deadline.Token);
        byte[] bytes = [1, 2, 3, 4];
        var path = Path.Combine(cluster.DirectoryPath, "artifact");
        await File.WriteAllBytesAsync(path, bytes, deadline.Token);
        await using var controller = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        var objects = await controller.CreateJetStreamContext().CreateObjectStoreContext().GetObjectStoreAsync("ORCH_ARTIFACTS", deadline.Token);
        var name = "sha256-" + Convert.ToHexStringLower(SHA256.HashData(bytes));
        await objects.PutAsync(name, new byte[] { 9, 8 }, deadline.Token);
        var before = (await objects.GetStatusAsync(deadline.Token)).Info.State;
        await Assert.That(() => Cli(cluster, path, false, deadline.Token)).Throws<InvalidDataException>();
        var after = (await objects.GetStatusAsync(deadline.Token)).Info.State;
        await Assert.That(after.LastSeq).IsEqualTo(before.LastSeq);
        await Assert.That(after.Bytes).IsEqualTo(before.Bytes);
        await Assert.That((await objects.GetBytesAsync(name, deadline.Token)).SequenceEqual(new byte[] { 9, 8 })).IsTrue();
    }

    private static Task<int> Cli(NatsControlR3L0cFixture cluster, string file, bool second, CancellationToken cancellationToken)
    {
        var identity = second ? cluster.ControllerTwo : cluster.Controller;
        var environment = new Dictionary<string, string>
        {
            ["TS_ORCH_CELL"] = "gru",
            ["TS_ORCH_NATS_URL"] = $"tls://127.0.0.1:{cluster.ClientPorts[second ? 1 : 0]}",
            ["TS_ORCH_NATS_CREDENTIALS_FILE"] = identity.CredentialsFile,
            ["TS_ORCH_NATS_TLS_CA_FILE"] = cluster.CaFile,
            ["TS_ORCH_NATS_TLS_CERT_FILE"] = identity.CertificateFile,
            ["TS_ORCH_NATS_TLS_KEY_FILE"] = identity.KeyFile
        };
        return OperatorCli.ExecuteAsync(["artifact-push", "--file", file], environment.GetValueOrDefault, cancellationToken);
    }

    private sealed class LostAck(IArtifactPublicationStore inner, int lostAppend) : IArtifactPublicationStore
    {
        private int appended;
        public string Bucket => inner.Bucket;
        public Task<ArtifactPublicationMessage?> ReadNextAsync(string subject, ulong after, CancellationToken cancellationToken) =>
            inner.ReadNextAsync(subject, after, cancellationToken);
        public async Task<ulong?> AppendAsync(string subject, ReadOnlyMemory<byte> bytes, ulong expected, CancellationToken cancellationToken)
        {
            var sequence = await inner.AppendAsync(subject, bytes, expected, cancellationToken);
            if (sequence is not null && ++appended == lostAppend) throw new IOException("Injected lost durable append acknowledgement.");
            return sequence;
        }
    }
}
