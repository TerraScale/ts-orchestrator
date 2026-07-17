using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiJobMessageMetadata(
    string Subject,
    string Stream,
    string Consumer,
    ulong StreamSequence,
    ulong ConsumerSequence,
    ulong DeliveryCount,
    int MessageSize);

internal sealed record RepositoryCiJobExecutionDeliveryReceipt(
    RepositoryCiJobDeliveryReceipt Delivery,
    CiRunnerExecutionCoordinatorReceipt? Execution);

/// <summary>
/// Pulls one raw command from an already-reconciled runner-specific consumer and delegates its
/// validation, durable acceptance, and double acknowledgement to the runner inbox.
/// </summary>
internal sealed class RepositoryCiJobNatsConsumer
{
    private static readonly TimeSpan ExecutionProgressInterval = TimeSpan.FromSeconds(10);
    private readonly INatsJSConsumer consumer;
    private readonly RepositoryCiJobInbox inbox;
    private readonly ConsumerConfig configuration;
    private readonly string runner;

    internal RepositoryCiJobNatsConsumer(
        INatsJSConsumer consumer,
        RepositoryCiJobInbox inbox,
        GlobalNatsTopology topology,
        string zone,
        string runner)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CiJobConsumer(zone, runner);
        this.runner = runner;
    }

    internal async Task<RepositoryCiJobDeliveryReceipt?> NextAsync(
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        CancellationToken cancellationToken = default)
    {
        var prepared = await NextPreparedAsync(
            now, allowedClockSkew, wait, signatureVerifier, cancellationToken);
        if (prepared is null) return null;
        if (!prepared.Receipt.CanAcknowledge) return prepared.Receipt;
        await AcknowledgeAsync(prepared.Message, cancellationToken);
        return prepared.Receipt with { Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged };
    }

    /// <summary>
    /// Keeps the JetStream delivery alive while INV-005 execution is fenced and acknowledges only
    /// after the execution journal contains a terminal result.
    /// </summary>
    internal async Task<RepositoryCiJobExecutionDeliveryReceipt?> NextAndExecuteAsync(
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        Func<RepositoryCiAcceptedJob, CancellationToken, Task<CiRunnerExecutionCoordinatorReceipt>> execute,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        var prepared = await NextPreparedAsync(
            now, allowedClockSkew, wait, signatureVerifier, cancellationToken);
        if (prepared is null) return null;
        if (!prepared.Receipt.CanAcknowledge) return new(prepared.Receipt, null);
        if (IsTerminal(prepared.Receipt.Execution))
        {
            await AcknowledgeAsync(prepared.Message, cancellationToken);
            return new(prepared.Receipt with
            {
                Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged,
            }, null);
        }

        var execution = await ExecuteWithProgressAsync(
            token => execute(prepared.Receipt.Acceptance!, token),
            token => prepared.Message.AckProgressAsync(cancellationToken: token).AsTask(),
            ExecutionProgressInterval,
            cancellationToken);
        if (!IsTerminal(execution.Execution)) return new(prepared.Receipt, execution);
        await AcknowledgeAsync(prepared.Message, cancellationToken);
        return new(prepared.Receipt with
        {
            Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged,
        }, execution);
    }

    private async Task<PreparedDelivery?> NextPreparedAsync(
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));
        if (wait <= TimeSpan.Zero || wait > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(wait));
        var message = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = wait },
            cancellationToken: cancellationToken);
        if (message is null) return null;
        message.EnsureSuccess();
        var metadata = message.Metadata;
        if (message.Data is null || message.Headers is null || metadata is not { } observed ||
            !ValidMetadata(new(
                message.Subject,
                observed.Stream,
                observed.Consumer,
                observed.Sequence.Stream,
                observed.Sequence.Consumer,
                observed.NumDelivered,
                message.Size), configuration))
            return new(message, Malformed());

        var receipt = await inbox.PrepareAsync(
            message.Data,
            Flatten(message.Headers),
            observed.Sequence.Stream,
            runner,
            now,
            allowedClockSkew,
            signatureVerifier,
            cancellationToken);
        return new(message, receipt);
    }

    internal static async Task<CiRunnerExecutionCoordinatorReceipt> ExecuteWithProgressAsync(
        Func<CancellationToken, Task<CiRunnerExecutionCoordinatorReceipt>> execute,
        Func<CancellationToken, Task> progress,
        TimeSpan interval,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execute);
        ArgumentNullException.ThrowIfNull(progress);
        if (interval <= TimeSpan.Zero || interval > ExecutionProgressInterval)
            throw new ArgumentOutOfRangeException(nameof(interval));
        using var progressFailed = new CancellationTokenSource();
        using var executionCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            progressFailed.Token);
        using var stopProgress = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var executionTask = execute(executionCancellation.Token);
        var progressTask = MaintainProgressAsync(progress, interval, stopProgress.Token);
        if (await Task.WhenAny(executionTask, progressTask) == progressTask)
        {
            var failure = await progressTask;
            if (failure is not null)
            {
                progressFailed.Cancel();
                try
                {
                    await executionTask;
                }
                catch
                {
                }
                throw new InvalidDataException("The CI runner lost its JetStream delivery lease.", failure);
            }
        }

        CiRunnerExecutionCoordinatorReceipt result;
        try
        {
            result = await executionTask;
        }
        finally
        {
            stopProgress.Cancel();
        }
        var progressFailure = await progressTask;
        if (progressFailure is not null)
            throw new InvalidDataException("The CI runner lost its JetStream delivery lease.", progressFailure);
        return result;
    }

    private static async Task<Exception?> MaintainProgressAsync(
        Func<CancellationToken, Task> progress,
        TimeSpan interval,
        CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(interval, cancellationToken);
                await progress(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static bool IsTerminal(RepositoryCiJobExecutionSnapshot? execution) =>
        execution?.Phase is RepositoryCiJobExecutionPhase.Succeeded or RepositoryCiJobExecutionPhase.Failed;

    private static Task AcknowledgeAsync(
        INatsJSMsg<byte[]> message,
        CancellationToken cancellationToken) =>
        message.AckAsync(
            new AckOpts { DoubleAck = true },
            cancellationToken: cancellationToken).AsTask();

    internal static bool ValidMetadata(
        RepositoryCiJobMessageMetadata metadata,
        ConsumerConfig configuration) =>
        metadata.Subject == configuration.FilterSubject &&
        metadata.Stream == GlobalNatsTopology.CiStream &&
        metadata.Consumer == configuration.Name &&
        metadata.StreamSequence > 0 && metadata.ConsumerSequence > 0 &&
        metadata.DeliveryCount is > 0 and <= 5 &&
        metadata.MessageSize is > 0 and <= RepositoryCiJobWireCodec.MaximumWireBytes;

    internal static IReadOnlyList<KeyValuePair<string, string>> Flatten(NatsHeaders headers)
    {
        var values = new List<KeyValuePair<string, string>>(RepositoryCiJobWireCodec.ExpectedHeaderCount + 1);
        foreach (var header in headers)
        {
            foreach (var value in header.Value)
            {
                values.Add(new(header.Key, value ?? string.Empty));
                if (values.Count == RepositoryCiJobWireCodec.ExpectedHeaderCount + 1) return values;
            }
        }
        return values;
    }

    private static RepositoryCiJobDeliveryReceipt Malformed() => new(
        RepositoryCiJobDeliveryDisposition.Malformed,
        RepositoryCiJobAcceptanceDisposition.Unspecified,
        CommandValidationError.MalformedEnvelope,
        null);

    private sealed record PreparedDelivery(
        INatsJSMsg<byte[]> Message,
        RepositoryCiJobDeliveryReceipt Receipt);
}
