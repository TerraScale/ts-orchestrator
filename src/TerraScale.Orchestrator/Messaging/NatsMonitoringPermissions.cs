using System.Collections.ObjectModel;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// The exact, minimum <c>$SYS</c> read subjects the monitoring contract may consume.
/// Every subject here is a read-only system-service request or an advisory
/// subscription; the monitoring identity is granted exactly these plus its inbox.
/// Adding a subject to this list is a permission change and requires review — the
/// pure isolation tests enumerate the full list.
/// </summary>
internal static class NatsMonitoringSubjects
{
    /// <summary>Bounded connection census (connections and reconnect counts).</summary>
    internal const string Connections = "$SYS.REQ.SERVER.PING.CONNZ";

    /// <summary>Bounded route census.</summary>
    internal const string Routes = "$SYS.REQ.SERVER.PING.ROUTEZ";

    /// <summary>Outbound gateway link state: the mesh-partition signal.</summary>
    internal const string Gateways = "$SYS.REQ.SERVER.PING.GATEWAYZ";

    /// <summary>Server process and JetStream resource use (memory, storage).</summary>
    internal const string Server = "$SYS.REQ.SERVER.PING.VARZ";

    /// <summary>JetStream domains, streams, consumers, memory, and storage totals.</summary>
    internal const string JetStream = "$SYS.REQ.SERVER.PING.JSZ";

    /// <summary>Account census. Stream/consumer detail comes from the JSZ detail shape, never a wider subject.</summary>
    internal const string Accounts = "$SYS.REQ.SERVER.PING.ACCOUNTZ";

    /// <summary>Account advisories: slow consumer, leader change, authentication failure, max deliveries.</summary>
    internal const string AccountAdvisories = "$SYS.ACCOUNT.*.ADVISORY.>";

    /// <summary>JetStream advisories: resource pressure and stream/consumer lifecycle.</summary>
    internal const string JetStreamAdvisories = "$SYS.JETSTREAM.ADVISORY.>";

    /// <summary>Every request-reply monitoring subject, in stable order.</summary>
    internal static IReadOnlyList<string> Requests { get; } =
    [
        Accounts,
        Connections,
        Gateways,
        JetStream,
        Routes,
        Server
    ];

    /// <summary>Every advisory subscription subject, in stable order.</summary>
    internal static IReadOnlyList<string> AdvisorySubscriptions { get; } =
    [
        AccountAdvisories,
        JetStreamAdvisories
    ];

    /// <summary>True only for the exact monitoring subjects this contract defines.</summary>
    internal static bool IsMonitoringSubject(string subject) =>
        Requests.Contains(subject, StringComparer.Ordinal) ||
        AdvisorySubscriptions.Contains(subject, StringComparer.Ordinal);

    /// <summary>
    /// True when a subject is covered by one of the two advisory subscription
    /// wildcards. Used to admit advisory deliveries without widening the allowlist.
    /// </summary>
    internal static bool IsAdvisoryDeliverySubject(string subject)
    {
        if (subject.StartsWith("$SYS.ACCOUNT.", StringComparison.Ordinal))
        {
            var rest = subject["$SYS.ACCOUNT.".Length..];
            var index = rest.IndexOf(".ADVISORY.", StringComparison.Ordinal);
            // Exactly one bounded account token between the root and the advisory
            // segment, and at least one subject token after it.
            return index > 0 &&
                   !rest.AsSpan(0, index).Contains('.') &&
                   !rest.AsSpan(0, index).Contains('*') &&
                   !rest.AsSpan(0, index).Contains('>') &&
                   rest[(index + ".ADVISORY.".Length)..].Length > 0;
        }
        if (subject.StartsWith("$SYS.JETSTREAM.ADVISORY.", StringComparison.Ordinal))
            return subject["$SYS.JETSTREAM.ADVISORY.".Length..].Length > 0;
        return false;
    }
}

/// <summary>
/// The read-only NATS permission plan for the monitoring identity. The plan is the
/// single source the account model grants from: the exact monitoring subjects plus
/// an inbox subscription, and nothing else. It cannot publish control work, mutate
/// JetStream, read customer/product payloads, access secret material, or cross the
/// control/product trust boundary, because it grants no other subject at all.
/// </summary>
internal sealed record NatsMonitoringPermissionPlan
{
    internal NatsMonitoringPermissionPlan(IEnumerable<string> publish, IEnumerable<string> subscribe)
    {
        Publish = Array.AsReadOnly(publish.Order(StringComparer.Ordinal).ToArray());
        Subscribe = Array.AsReadOnly(subscribe.Order(StringComparer.Ordinal).ToArray());
        // The plan is the single source the account model grants from, so it
        // validates itself: only the exact read-only system request subjects may
        // be published, and only the advisory subscriptions and the inbox may be
        // subscribed. A hostile grant (control work, JetStream mutation, KV or
        // object reads, product subjects, anything else) is rejected at
        // construction instead of being granted verbatim.
        foreach (var subject in Publish)
            if (!NatsMonitoringSubjects.Requests.Contains(subject, StringComparer.Ordinal))
                throw new ArgumentException(
                    $"The monitoring permission plan may not publish '{subject}': only the exact read-only $SYS request subjects are grantable.",
                    nameof(publish));
        foreach (var subject in Subscribe)
            if (!NatsMonitoringSubjects.AdvisorySubscriptions.Contains(subject, StringComparer.Ordinal) &&
                subject != "_INBOX.>")
                throw new ArgumentException(
                    $"The monitoring permission plan may not subscribe '{subject}': only the advisory subscriptions and the inbox are grantable.",
                    nameof(subscribe));
    }

    internal ReadOnlyCollection<string> Publish { get; }
    internal ReadOnlyCollection<string> Subscribe { get; }
}

internal static class NatsMonitoringPermissions
{
    /// <summary>
    /// The monitoring plan: publish only the read-only system-service request
    /// subjects, subscribe only to advisories and its own inbox.
    /// </summary>
    internal static NatsMonitoringPermissionPlan Create() => new(
        NatsMonitoringSubjects.Requests,
        NatsMonitoringSubjects.AdvisorySubscriptions.Append("_INBOX.>"));

    /// <summary>
    /// Subject classes the monitoring plan must never be able to touch. These drive
    /// the pure isolation tests and the fixture permission-denial tests; they are
    /// derived from the canonical taxonomy so the denial surface tracks the real
    /// control plane, not a copy of it.
    /// </summary>
    internal static class Forbidden
    {
        /// <summary>Control work: regional command and internal journal subjects for every cell.</summary>
        internal static IReadOnlyList<string> ControlPublish(string cell) =>
        [
            NatsSubjectTaxonomy.DirectDeliverySubject(cell),
            NatsSubjectTaxonomy.OperationJournalCreateSubject(cell),
            NatsSubjectTaxonomy.OperationJournalUpdateSubject(cell),
            NatsSubjectTaxonomy.RegionalFamilyPattern(cell, NatsSubjectTaxonomy.DesiredFamilySegment),
            NatsSubjectTaxonomy.RegionalFamilyPattern(cell, NatsSubjectTaxonomy.ObservationFamilySegment)
        ];

        /// <summary>Global control-plane work subjects.</summary>
        internal static IReadOnlyList<string> GlobalControlPublish() =>
        [
            NatsSubjectTaxonomy.GlobalCellSpecPrefix + ".>",
            NatsSubjectTaxonomy.CiJobSubjectPrefix + ".>",
            NatsSubjectTaxonomy.GlobalDirectoryQuerySubject
        ];

        /// <summary>JetStream mutation and management APIs.</summary>
        internal static IReadOnlyList<string> JetStreamMutation() =>
        [
            "$JS.API.STREAM.CREATE.>",
            "$JS.API.STREAM.UPDATE.>",
            "$JS.API.STREAM.DELETE.>",
            "$JS.API.STREAM.PURGE.>",
            "$JS.API.CONSUMER.CREATE.>",
            "$JS.API.CONSUMER.DELETE.>",
            "$JS.API.CONSUMER.DURABLE.CREATE.>",
            "$JS.ACK.>",
            "$JS.FC.>"
        ];

        /// <summary>Secret-bearing and journal material.</summary>
        internal static IReadOnlyList<string> SecretAndJournalReads() =>
        [
            "$KV.ORCH_OPERATIONS.>",
            "$KV.ORCH_OPERATION_PROOFS.>",
            "$KV.ORCH_RUNTIME.>",
            "$KV.ORCH_DELIVERY.>",
            "$O.CELL_BUNDLES.>",
            "$O.ORCH_PROTOCOL_PACKAGE.>"
        ];

        /// <summary>
        /// Product-plane subjects. The product plane is not rooted under the
        /// Orchestrator control taxonomy; monitoring must hold no product-plane
        /// grant at all, so the isolation boundary is proven against the reserved
        /// audit and agent namespaces plus an explicit product root.
        /// </summary>
        internal static IReadOnlyList<string> ProductPlane() =>
        [
            "product.>",
            $"{NatsSubjectTaxonomy.Root}.{NatsSubjectTaxonomy.RegionalAuditPrefixSegment}.>",
            $"{NatsSubjectTaxonomy.Root}.{NatsSubjectTaxonomy.RegionalAgentPrefixSegment}.>"
        ];
    }

    /// <summary>
    /// True when a granted subject pattern can carry the candidate subject. Patterns
    /// support a single-token <c>*</c> and a trailing <c>&gt;</c> (which must be the
    /// last token), matching NATS subscription semantics. Used by the isolation
    /// tests to prove no forbidden subject is reachable through any grant.
    /// </summary>
    internal static bool Grants(IReadOnlyCollection<string> granted, string subject)
    {
        var candidate = subject.Split('.');
        foreach (var pattern in granted)
        {
            if (pattern == subject) return true;
            var tokens = pattern.Split('.');
            var trailing = tokens.Length > 0 && tokens[^1] == ">";
            var bounded = trailing ? tokens.Length - 1 : tokens.Length;
            if (bounded == 0) continue;
            if (!trailing && bounded != candidate.Length) continue;
            if (trailing && candidate.Length < bounded) continue;
            var matched = true;
            for (var index = 0; index < bounded; index++)
            {
                var token = tokens[index];
                if (token == "*") continue;
                if (token == ">") { matched = false; break; }
                if (!string.Equals(token, candidate[index], StringComparison.Ordinal))
                {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
        return false;
    }
}

