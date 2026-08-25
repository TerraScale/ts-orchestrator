using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Closed, redacted wire contract for the private runtime-lifecycle journal bridge.
/// This protocol carries no host plan, secret, credential, provider identifier, or exception text.
/// </summary>
internal static class RuntimeLifecycleNatsProtocol
{
    internal const int SchemaVersion = 1;
    internal const int MaximumCheckpointBytes = 16 * 1024;
    internal const string ReadAction = "runtime-lifecycle-read";
    internal const string CreateAction = "runtime-lifecycle-create";
    internal const string UpdateAction = "runtime-lifecycle-update";

    internal static string Subject(string cell, string operation) =>
        TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(
            RequireCell(cell), operation);

    internal static string ReplySubject(string cell, string callerIdentity, string nonce) =>
        TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject(
            RequireCell(cell), callerIdentity, nonce);

    internal static string Key(RuntimeLifecycleOperationKey operationKey)
    {
        ArgumentNullException.ThrowIfNull(operationKey);
        return "runtime." + operationKey.Value;
    }

    internal static bool IsKey(string? key) => key is { Length: 72 } && key.StartsWith("runtime.", StringComparison.Ordinal) &&
        key.AsSpan(8).ToString().All(Uri.IsHexDigit);

    internal static string Serialize(RuntimeLifecycleCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        var value = JsonSerializer.Serialize(checkpoint, RuntimeLifecycleJournalJsonContext.Default.RuntimeLifecycleCheckpoint);
        if (System.Text.Encoding.UTF8.GetByteCount(value) > MaximumCheckpointBytes)
            throw new InvalidDataException("Runtime lifecycle checkpoint exceeds its journal bound.");
        return value;
    }

    internal static bool TryDeserialize(
        string? value,
        [NotNullWhen(true)] out RuntimeLifecycleCheckpoint? checkpoint)
    {
        checkpoint = null;
        try
        {
            if (string.IsNullOrWhiteSpace(value) || System.Text.Encoding.UTF8.GetByteCount(value) > MaximumCheckpointBytes)
                return false;
            var deserialized = JsonSerializer.Deserialize(value, RuntimeLifecycleJournalJsonContext.Default.RuntimeLifecycleCheckpoint);
            if (deserialized is null || Serialize(deserialized) != value)
                return false;
            checkpoint = deserialized;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    internal static bool IsCheckpoint(RuntimeLifecycleCheckpoint? checkpoint, string cell, string key, ulong revision)
    {
        try
        {
            return checkpoint is not null && revision > 0 && checkpoint.SchemaVersion == RuntimeLifecycleContract.SchemaVersion &&
                checkpoint.Cell?.Value == cell && Key(checkpoint.OperationKey) == key && checkpoint.JournalRevision == revision &&
                Enum.IsDefined(checkpoint.Driver) && Enum.IsDefined(checkpoint.Role) && Enum.IsDefined(checkpoint.Action) &&
                Enum.IsDefined(checkpoint.Phase) && Enum.IsDefined(checkpoint.CallStatus) &&
                Enum.IsDefined(checkpoint.CompensationPolicy) && Enum.IsDefined(checkpoint.TerminalStatus) &&
                Enum.IsDefined(checkpoint.ErrorCode) && checkpoint.CompensationPolicy == RuntimeLifecycleCompensationPolicy.None &&
                checkpoint.EventDigest == RuntimeLifecycleFingerprint.Event(checkpoint);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NullReferenceException)
        {
            return false;
        }
    }

    internal static bool IsGenesis(RuntimeLifecycleCheckpoint checkpoint) =>
        checkpoint.PreviousEventDigest.Sha256 == RuntimeLifecycleFingerprint.Hash("runtime-lifecycle-genesis-v1") &&
        checkpoint.Phase == RuntimeLifecyclePhase.Proposed;

    internal static bool IsChained(RuntimeLifecycleCheckpoint current, RuntimeLifecycleCheckpoint next) =>
        current.JournalRevision < ulong.MaxValue && next.PreviousEventDigest == current.EventDigest &&
        next.JournalRevision == current.JournalRevision + 1;

    internal static string ProofBinding(
        string action,
        int schemaVersion,
        string cell,
        string key,
        ulong expectedRevision,
        ulong writerEpoch,
        string requestId,
        string? checkpoint)
    {
        return RuntimeLifecycleFingerprint.Hash(string.Join('|', "runtime-lifecycle-nats-proof-v1", action,
            schemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), cell, key,
            expectedRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            writerEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture), requestId, checkpoint ?? string.Empty));
    }

    internal static bool IsRequest(int schemaVersion, string? cell, string? key, string? requestId) =>
        schemaVersion == SchemaVersion && IsCell(cell) && IsKey(key) && requestId is { Length: 32 } &&
        requestId.All(static character => char.IsAsciiHexDigit(character));

    internal static bool IsCell(string? value) => value is { Length: > 0 and <= 63 } &&
        value.All(static character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static string RequireCell(string value) => IsCell(value) ? value : throw new ArgumentOutOfRangeException(nameof(value));
}

internal sealed record NatsRuntimeLifecycleJournalReadRequest(
    int SchemaVersion,
    string Cell,
    string Key,
    string RequestId,
    NatsOperationJournalMutationAuthorityProof Authority) : INatsOperationJournalMutationRequest;

internal sealed record NatsRuntimeLifecycleJournalWriteRequest(
    int SchemaVersion,
    string Cell,
    string Key,
    ulong ExpectedRevision,
    ulong WriterEpoch,
    string Checkpoint,
    string RequestId,
    NatsOperationJournalMutationAuthorityProof Authority) : INatsOperationJournalMutationRequest;

internal sealed record NatsRuntimeLifecycleJournalReply(
    int SchemaVersion,
    int Status,
    ulong Revision,
    string? Checkpoint,
    string RequestDigest,
    string Signature)
{
    internal string Payload() => string.Join('|', SchemaVersion, Status, Revision, Checkpoint ?? string.Empty, RequestDigest);
}

[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(RuntimeLifecycleCheckpoint))]
internal sealed partial class RuntimeLifecycleJournalJsonContext : JsonSerializerContext;
