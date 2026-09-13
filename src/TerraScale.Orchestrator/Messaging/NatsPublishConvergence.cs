using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Publish-side convergence for message-id deduplicated JetStream publishes. The client
/// library's <c>EnsureSuccess</c> treats an in-window duplicate <c>Nats-Msg-Id</c> as an
/// exception, but every Orchestrator message id is derived deterministically from the exact
/// content being stored (payload digest, attempt, fencing token, or writer epoch): a duplicate
/// acknowledgement therefore PROVES the same message is already durably stored, and a retry
/// after a lost acknowledgement must converge on that receipt instead of throwing until the
/// stream's duplicate window expires. Only a server error is a failure.
/// </summary>
internal static class NatsPublishConvergence
{
    /// <summary>
    /// Ensures the publish reached durable storage, accepting a duplicate message id as the
    /// converged receipt of the identical message. Returns true when the server reported the
    /// duplicate (already stored by an earlier attempt inside the window).
    /// </summary>
    internal static bool EnsureStored(this PubAckResponse acknowledgement)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        if (acknowledgement.Error is not null)
            throw new NATS.Client.JetStream.NatsJSApiException(acknowledgement.Error);
        return acknowledgement.Duplicate;
    }
}

