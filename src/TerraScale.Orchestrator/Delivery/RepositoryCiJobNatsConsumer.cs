using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Protocol.Messaging;

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
    private static readonly TimeSpan ExecutionRecoveryInterval = TimeSpan.FromSeconds(5);
    private const int MaximumExecutionRecoveryWaits = 720;
    private readonly INatsJSConsumer consumer;
    private readonly RepositoryCiJobInbox inbox;
    private readonly ConsumerConfig configuration;
    private readonly string runner;
    private readonly NatsMessageIdDeduplication? deduplication;

    internal RepositoryCiJobNatsConsumer(
        INatsJSConsumer consumer,
        RepositoryCiJobInbox inbox,
        GlobalNatsTopology topology,
        string zone,
        string runner,
        NatsMessageIdDeduplication? deduplication = null)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CiJobConsumer(zone, runner);
        this.runner = runner;
        this.deduplication = deduplication;
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
        if (prepared.TerminatedConflictingIdentity) return prepared.Receipt;
        if (prepared.SuppressReplay)
        {
            await AcknowledgeAsync(prepared.Message, cancellationToken);
            return prepared.Receipt with { Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged };
        }
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
        if (prepared.TerminatedConflictingIdentity) return new(prepared.Receipt, null);
        if (prepared.SuppressReplay)
        {
            await AcknowledgeAsync(prepared.Message, cancellationToken);
            return new(prepared.Receipt with
            {
                Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged,
            }, null);
        }
        if (!prepared.Receipt.CanAcknowledge) return new(prepared.Receipt, null);
        if (IsTerminal(prepared.Receipt.Execution))
        {
            await AcknowledgeAsync(prepared.Message, cancellationToken);
            return new(prepared.Receipt with
            {
                Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged,
            }, null);
        }
        if (prepared.Receipt.Acceptance is not { } accepted)
            throw new InvalidDataException("An acknowledgeable CI delivery has no accepted command.");

        var execution = await ExecuteWithProgressAsync(
            token => ExecuteUntilSettledAsync(
                inner => execute(accepted, inner),
                inner => Task.Delay(ExecutionRecoveryInterval, inner),
                MaximumExecutionRecoveryWaits,
                token),
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

        var headers = Flatten(message.Headers);
        if (deduplication is { } guard &&
            TryMessageIdentity(headers, out var messageId, out var digest))
        {
            // Transport suppression beneath the operation-level idempotency key. The window
            // records an identity only after its durable effect was proven, so a suppressed
            // replay is a verified idempotent replay; a conflicting digest under the same
            // identity is a deterministic conflict and terminates with terminal evidence.
            var action = DuplicateWindowDelivery.Decide(guard.Inspect(messageId, digest, now));
            if (action == DuplicateWindowDeliveryAction.AcknowledgeSuppressedReplay)
                return new(message, SuppressedReplay(), SuppressReplay: true);
            if (action == DuplicateWindowDeliveryAction.TerminateConflictingIdentity)
            {
                Console.Error.WriteLine(ConflictingIdentityWarning(messageId, observed.Sequence.Stream));
                await message.AckTerminateAsync(cancellationToken: cancellationToken);
                return new(message, ConflictingIdentity(), TerminatedConflictingIdentity: true);
            }
        }

        var receipt = await inbox.PrepareAsync(
            message.Data,
            headers,
            observed.Sequence.Stream,
            runner,
            now,
            allowedClockSkew,
            signatureVerifier,
            cancellationToken);
        if (receipt.CanAcknowledge && deduplication is { } completed &&
            TryMessageIdentity(headers, out var completedId, out var completedDigest))
        {
            completed.Record(completedId, completedDigest, now);
        }

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

    internal static async Task<CiRunnerExecutionCoordinatorReceipt> ExecuteUntilSettledAsync(
        Func<CancellationToken, Task<CiRunnerExecutionCoordinatorReceipt>> execute,
        Func<CancellationToken, Task> wait,
        int maximumWaits,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        ArgumentNullException.ThrowIfNull(wait);
        if (maximumWaits < 0) throw new ArgumentOutOfRangeException(nameof(maximumWaits));

        for (var waits = 0;; waits++)
        {
            var receipt = await execute(cancellationToken);
            if (!ShouldRetry(receipt) || waits == maximumWaits) return receipt;
            await wait(cancellationToken);
        }
    }

    private static bool ShouldRetry(CiRunnerExecutionCoordinatorReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (IsTerminal(receipt.Execution)) return false;
        return receipt.Disposition is (CiRunnerExecutionCoordinatorDisposition.NotAcquired or
                CiRunnerExecutionCoordinatorDisposition.LeaseLost) &&
            receipt.ExecutionDisposition is (RepositoryCiJobExecutionDisposition.Duplicate or
                RepositoryCiJobExecutionDisposition.LeaseHeld or
                RepositoryCiJobExecutionDisposition.StaleLease or
                RepositoryCiJobExecutionDisposition.Contention);
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

    /// <summary>
    /// The transport window suppressed this exact identity after its durable effect was proven:
    /// an idempotent replay, not a reprocessed command.
    /// </summary>
    private static RepositoryCiJobDeliveryReceipt SuppressedReplay() => new(
        RepositoryCiJobDeliveryDisposition.Prepared,
        RepositoryCiJobAcceptanceDisposition.Duplicate,
        CommandValidationError.None,
        null);

    /// <summary>
    /// The same message identity arrived with a different payload digest: a deterministic
    /// conflict, terminated with terminal evidence rather than redelivered.
    /// </summary>
    private static RepositoryCiJobDeliveryReceipt ConflictingIdentity() => new(
        RepositoryCiJobDeliveryDisposition.Rejected,
        RepositoryCiJobAcceptanceDisposition.IdentityConflict,
        CommandValidationError.None,
        null);

    /// <summary>
    /// Extracts the in-band message identity (job id plus canonical payload digest) of one
    /// runner command. Missing or empty values fail open to the journal path: the operation
    /// idempotency key remains the authority.
    /// </summary>
    internal static bool TryMessageIdentity(
        IReadOnlyList<KeyValuePair<string, string>> headers,
        out string messageId,
        out string digest)
    {
        messageId = string.Empty;
        digest = string.Empty;
        ArgumentNullException.ThrowIfNull(headers);
        foreach (var header in headers)
        {
            if (string.Equals(header.Key, RepositoryCiJobWireCodec.JobIdHeader, StringComparison.Ordinal))
                messageId = header.Value;
            else if (string.Equals(header.Key, RepositoryCiJobWireCodec.PayloadSha256Header, StringComparison.Ordinal))
                digest = header.Value;
        }

        return messageId is { Length: >= 1 and <= 128 } && digest is { Length: >= 1 and <= 128 };
    }

    /// <summary>
    /// The loud, bounded operator line for a terminated identity conflict: the same message id
    /// carried two different payloads, so the second delivery was terminated with evidence.
    /// </summary>
    internal static string ConflictingIdentityWarning(string messageId, ulong streamSequence)
    {
        var boundedIdentity = messageId.Trim().Length <= 128
            ? messageId.Trim()
            : messageId.Trim()[..128];
        return
            $"CI runner command identity conflict (job {boundedIdentity}, stream sequence {streamSequence}): " +
            "the same message id arrived with a different payload digest; the conflicting delivery was " +
            "terminated with terminal evidence instead of being redelivered. Operator action required: " +
            "inspect the CI job journal for this identity.";
    }

    private sealed record PreparedDelivery(
        INatsJSMsg<byte[]> Message,
        RepositoryCiJobDeliveryReceipt Receipt,
        bool SuppressReplay = false,
        bool TerminatedConflictingIdentity = false);
}

