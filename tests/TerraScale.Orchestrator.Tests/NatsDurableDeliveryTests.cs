using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Net;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

// Each of these tests owns one real NATS server (rootless Podman, JetStream enabled). They
// must not run alongside other NATS-server tests in this module: startup verification contends
// for the same bounded validation resources (repository validation lease).
[NotInParallel]
public sealed class NatsDurableDeliveryTests
{
    private const string Stream = "WORK";
    private const string Subject = "work.commands";

    [Test]
    public async Task TransportMessageIdWindowsSuppressDuplicatesAndSilentlySwallowConflictingPayloads()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await OneJetStream.StartAsync();

        var jetStream = server.JetStream();
        var stream = await jetStream.CreateStreamAsync(StreamConfig(
            DuplicateWindowPolicy.CellStreams.Window));
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(Stream, ConsumerConfig("ids"));

        // Same message id, same payload: the second publish is suppressed by the transport
        // window and the server SAYS SO in the acknowledgement (Duplicate == true). A retrying
        // publisher converges on that receipt instead of failing.
        (await jetStream.PublishAsync(Subject, "first", opts: PubOpts("m1"))).EnsureSuccess();
        await Assert.That(
            (await jetStream.PublishAsync(Subject, "first", opts: PubOpts("m1"))).Duplicate).IsTrue();
        // Same message id, DIFFERENT payload: the server still suppresses it — the second
        // payload is silently swallowed while the acknowledgement claims a benign duplicate.
        // This is exactly why the client-side identity-conflict termination exists: the
        // transport never surfaces the payload change on its own, and message ids must stay
        // derived from the exact content being stored.
        await Assert.That(
            (await jetStream.PublishAsync(Subject, "second", opts: PubOpts("m1"))).Duplicate).IsTrue();
        // A distinct message id is admitted and acknowledged as a fresh store.
        var admitted = await jetStream.PublishAsync(Subject, "third", opts: PubOpts("m2"));
        admitted.EnsureSuccess();
        await Assert.That(admitted.Duplicate).IsFalse();

        await stream.RefreshAsync();
        await Assert.That(stream.Info.State.Messages).IsEqualTo(2);

        var payloads = new List<string>();
        while (await NextAsync(consumer) is { } message)
        {
            payloads.Add(message.Data ?? string.Empty);
            await message.AckAsync(new AckOpts { DoubleAck = true });
        }

        await Assert.That(payloads).IsEquivalentTo(["first", "third"]);
        await Assert.That(payloads).DoesNotContain("second");
    }

    [Test]
    public async Task ConsumerRestartKeepsTheCursorAndRecreationReplaysThroughIdempotency()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await OneJetStream.StartAsync();

        var jetStream = server.JetStream();
        await jetStream.CreateStreamAsync(StreamConfig(
            DuplicateWindowPolicy.CellStreams.Window));
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(Stream, ConsumerConfig("replay"));

        // The "durable effect": an application journal keyed by message id. Its counts prove
        // that restarts, lost acknowledgements, and consumer recreation converge on exactly
        // one mutation per message — effectively-once through idempotency, never exactly-once.
        var effects = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var id in new[] { "w1", "w2", "w3" })
        {
            (await jetStream.PublishAsync(Subject, id, opts: PubOpts(id))).EnsureSuccess();
        }

        for (var processed = 0; processed < 2; processed++)
        {
            var message = await NextAsync(consumer);
            await Assert.That(message).IsNotNull();
            var id = message!.Data ?? string.Empty;
            effects[id] = effects.GetValueOrDefault(id) + 1;
            await message.AckAsync(new AckOpts { DoubleAck = true });
        }

        // Crash after the durable effect but before the acknowledgement of w3.
        var lost = await NextAsync(consumer);
        await Assert.That(lost).IsNotNull();
        var lostId = lost!.Data ?? string.Empty;
        effects[lostId] = effects.GetValueOrDefault(lostId) + 1;

        // Handler restart (new connection, same durable consumer): the cursor survived, so
        // only the unacknowledged w3 returns; the journal makes its replay idempotent.
        await server.ReconnectAsync();
        jetStream = server.JetStream();
        consumer = await jetStream.GetConsumerAsync(Stream, "replay");
        var redelivered = await NextAsync(consumer);
        await Assert.That(redelivered).IsNotNull();
        await Assert.That(redelivered!.Data).IsEqualTo(lostId);
        var replayedId = redelivered.Data ?? string.Empty;
        effects[replayedId] = effects.GetValueOrDefault(replayedId) + 1;
        await redelivered.AckAsync(new AckOpts { DoubleAck = true });
        await Assert.That(effects[replayedId]).IsEqualTo(2);
        await Assert.That(await NextAsync(consumer)).IsNull();
        await Assert.That(effects.Values.Order().ToArray()).IsEquivalentTo([1, 1, 2]);

        // Consumer recreation (deleted durable state): the fresh cursor replays EVERYTHING,
        // and the journal still converges on one mutation per message.
        await jetStream.DeleteConsumerAsync(Stream, "replay");
        consumer = await jetStream.CreateOrUpdateConsumerAsync(Stream, ConsumerConfig("replay"));
        var replayed = 0;
        while (await NextAsync(consumer) is { } message)
        {
            replayed++;
            var id = message.Data ?? string.Empty;
            effects[id] = effects.GetValueOrDefault(id) + 1;
            await message.AckAsync(new AckOpts { DoubleAck = true });
        }

        await Assert.That(replayed).IsEqualTo(3);
        await Assert.That(effects.Values.Order().ToArray()).IsEquivalentTo([2, 2, 3]);
        await consumer.RefreshAsync();
        await Assert.That(consumer.Info.NumAckPending).IsEqualTo(0);
    }

    [Test]
    public async Task ALostAcknowledgementRedeliversInsideTheBackoffBoundAndConverges()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await OneJetStream.StartAsync();

        var jetStream = server.JetStream();
        await jetStream.CreateStreamAsync(StreamConfig(
            DuplicateWindowPolicy.CellStreams.Window));
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(Stream, new ConsumerConfig("redeliver")
        {
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            FilterSubject = Subject,
            AckWait = TimeSpan.FromSeconds(1),
            MaxDeliver = 5,
            Backoff = [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5)],
            NumReplicas = 1,
        });
        (await jetStream.PublishAsync(Subject, "w1", opts: PubOpts("w1"))).EnsureSuccess();

        var effects = new Dictionary<string, int>(StringComparer.Ordinal);

        // Crash after the effect, before the acknowledgement.
        var first = await NextAsync(consumer);
        await Assert.That(first).IsNotNull();
        if (first!.Metadata is not { } firstMetadata) throw new InvalidOperationException("The first delivery has no metadata.");
        await Assert.That(firstMetadata.NumDelivered).IsEqualTo(1UL);
        effects["w1"] = 1;

        var elapsed = Stopwatch.StartNew();
        INatsJSMsg<string>? second;
        while ((second = await NextAsync(consumer, TimeSpan.FromSeconds(4))) is null)
        {
            await Assert.That(elapsed.Elapsed).IsLessThan(TimeSpan.FromSeconds(15));
        }

        elapsed.Stop();
        if (second!.Metadata is not { } secondMetadata) throw new InvalidOperationException("The redelivery has no metadata.");
        var redelivery = secondMetadata.NumDelivered;
        var id = second.Data ?? string.Empty;
        effects[id] = effects.GetValueOrDefault(id) + 1;
        await second.AckAsync(new AckOpts { DoubleAck = true });

        // The redelivery arrived with its delivery count advanced, inside the ack-wait plus
        // first-backoff bound, and the journal kept the mutation at exactly one.
        await Assert.That(redelivery).IsEqualTo(2UL);
        await Assert.That(elapsed.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(effects["w1"]).IsEqualTo(2);
        await consumer.RefreshAsync();
        await Assert.That(consumer.Info.NumAckPending).IsEqualTo(0);
        await Assert.That(await NextAsync(consumer)).IsNull();
    }

    [Test]
    public async Task RedeliveryStopsAtTheDeclaredDeliveryBoundWithNoFurtherAttempts()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await OneJetStream.StartAsync();

        var jetStream = server.JetStream();
        await jetStream.CreateStreamAsync(StreamConfig(
            DuplicateWindowPolicy.CellStreams.Window));
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(Stream, new ConsumerConfig("bounded")
        {
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            DeliverPolicy = ConsumerConfigDeliverPolicy.All,
            FilterSubject = Subject,
            AckWait = TimeSpan.FromSeconds(1),
            MaxDeliver = 3,
            Backoff = [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)],
            NumReplicas = 1,
        });
        (await jetStream.PublishAsync(Subject, "poison", opts: PubOpts("poison"))).EnsureSuccess();

        // Negative-acknowledge every delivery: the budget must exhaust at exactly the
        // declared cap and never deliver again — the bound that keeps a poison payload from
        // burning unbounded redelivery work.
        var deliveries = new List<ulong>();
        var deadline = Stopwatch.StartNew();
        while (await NextAsync(consumer, TimeSpan.FromSeconds(4)) is { } message)
        {
            if (message.Metadata is not { } metadata) throw new InvalidOperationException("A delivery has no metadata.");
            deliveries.Add(metadata.NumDelivered);
            await message.NakAsync();
            if (deadline.Elapsed > TimeSpan.FromSeconds(20)) break;
        }

        await Assert.That(deliveries).IsEquivalentTo([1UL, 2UL, 3UL]);

        // No fourth delivery: the budget stopped at the declared cap and the pending set is
        // drained — exhaustion is bounded and observable, never a silent busy loop.
        await Assert.That(await NextAsync(consumer, TimeSpan.FromSeconds(2))).IsNull();
        for (var attempt = 0; attempt < 25; attempt++)
        {
            await consumer.RefreshAsync();
            if (consumer.Info.NumAckPending == 0) break;
            await Task.Delay(200);
        }

        await consumer.RefreshAsync();
        await Assert.That(consumer.Info.NumAckPending).IsEqualTo(0);
    }

    private static NatsJSPubOpts PubOpts(string messageId) =>
        new() { MsgId = messageId, RetryAttempts = 3, RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250) };

    private static StreamConfig StreamConfig(TimeSpan duplicateWindow) => new(Stream, [Subject])
    {
        Storage = StreamConfigStorage.File,
        Retention = StreamConfigRetention.Limits,
        Discard = StreamConfigDiscard.Old,
        DuplicateWindow = duplicateWindow,
        NumReplicas = 1,
    };

    private static ConsumerConfig ConsumerConfig(string name) => new(name)
    {
        AckPolicy = ConsumerConfigAckPolicy.Explicit,
        DeliverPolicy = ConsumerConfigDeliverPolicy.All,
        FilterSubject = Subject,
        AckWait = TimeSpan.FromSeconds(1),
        MaxDeliver = 5,
        Backoff = [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5)],
        NumReplicas = 1,
    };

    private static async Task<INatsJSMsg<string>?> NextAsync(
        INatsJSConsumer consumer,
        TimeSpan? expires = null)
    {
        var message = await consumer.NextAsync<string>(
            opts: new NatsJSNextOpts { Expires = expires ?? TimeSpan.FromSeconds(2) });
        message?.EnsureSuccess();
        return message;
    }

    /// <summary>
    /// One real NATS server with JetStream enabled, running as its own hardened rootless
    /// Podman container under the repository's local-server lease. Mirrors the private
    /// <c>OneNodeJetStream</c> lane of the operation-journal tests; it stays private so no
    /// shared test primitive changes.
    /// </summary>
    private sealed class OneJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private readonly ContainerizedNatsCluster containerCluster;
        private readonly LocalNatsServerLease.Handle lease;
        private Process? process;
        private NatsClient? client;
        private Task? processOutput;
        private INatsJSContext? jetStream;
        private int disposed;

        private OneJetStream(
            string directory,
            string configuration,
            int port,
            ContainerizedNatsCluster containerCluster,
            LocalNatsServerLease.Handle lease)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
            this.containerCluster = containerCluster;
            this.lease = lease;
        }

        public static async Task<OneJetStream> StartAsync()
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-durable-delivery-{Guid.NewGuid():N}");
            OneJetStream? server = null;
            try
            {
                Directory.CreateDirectory(directory);
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                var configuration = Path.Combine(directory, "nats.conf");
                await File.WriteAllTextAsync(
                    configuration,
                    $"port: {port}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
                var containerCluster = await ContainerizedNatsCluster.CreateAsync(directory, [port]);
                server = new OneJetStream(directory, configuration, port, containerCluster, lease);
                await server.ConnectAsync();
                return server;
            }
            catch (Exception startupFailure)
            {
                if (server is not null)
                {
                    try
                    {
                        await server.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                else
                {
                    var owner = new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease);
                    try
                    {
                        await owner.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                throw;
            }
        }

        public INatsJSContext JetStream() =>
            jetStream ?? throw new InvalidOperationException("The fixture is not connected.");

        /// <summary>Simulates a handler restart: a fresh client connection to the same server.</summary>
        public async Task ReconnectAsync()
        {
            if (client is not null) await client.DisposeAsync();
            client = null;
            jetStream = null;
            var connected = new NatsClient(new NatsOpts
            {
                Url = $"nats://127.0.0.1:{port}",
                ConnectTimeout = TimeSpan.FromSeconds(1),
            });
            try
            {
                await connected.ConnectAsync();
                client = connected;
                jetStream = client.CreateJetStreamContext();
            }
            catch
            {
                await connected.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
            var cleanup = new LocalNatsServerLease.Cleanup();
            try
            {
                if (client is not null &&
                    await cleanup.AttemptAsync(() => client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5))))
                    client = null;
                if (process is not null)
                {
                    if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                        cleanup.Attempt(process.Dispose))
                        process = null;
                }
                if (processOutput is not null &&
                    await cleanup.AttemptAsync(() => processOutput.WaitAsync(TimeSpan.FromSeconds(1))))
                    processOutput = null;
                await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
                if (await lease.ReleaseIfCleanAsync(cleanup))
                {
                    Volatile.Write(ref disposed, 2);
                    LocalNatsServerLease.CompleteRetention(this);
                }
                cleanup.ThrowIfFailed();
            }
            finally
            {
                if (Volatile.Read(ref disposed) == 1)
                {
                    LocalNatsServerLease.Retain(this);
                    Volatile.Write(ref disposed, 0);
                }
            }
        }

        private async Task ConnectAsync()
        {
            process = containerCluster.Start(configuration);
            processOutput = Task.WhenAll(
                process.StandardOutput.ReadToEndAsync(),
                process.StandardError.ReadToEndAsync());
            for (var attempt = 0; attempt < 50; attempt++)
            {
                client = new NatsClient(new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                });
                try
                {
                    await client.ConnectAsync();
                    jetStream = client.CreateJetStreamContext();
                    return;
                }
                catch (NatsException) when (attempt < 49)
                {
                    await client.DisposeAsync();
                    client = null;
                    jetStream = null;
                    await Task.Delay(50);
                }
            }
            throw new InvalidOperationException("The containerized NATS server did not accept a local JetStream connection.");
        }
    }
}

