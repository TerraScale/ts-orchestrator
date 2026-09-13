namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// Every NATS capability named by the frozen feature-adoption contract. The enum is the
/// machine-readable completeness key: the matrix must disposition each member exactly once.
/// </summary>
public enum NatsCapability
{
    Unspecified = 0,
    CorePubSub,
    RequestReply,
    ServicesAndDiscovery,
    QueueGroups,
    Headers,
    MessageIds,
    JetStreamStreams,
    DurableConsumers,
    Acknowledgement,
    RedeliveryAndBackoff,
    FlowControl,
    KeyValueCasAndWatch,
    ObjectStore,
    Accounts,
    Jwts,
    NKeys,
    Mtls,
    ImportsAndExports,
    Gateways,
    Advisories,
    SystemMonitoring,
    Snapshots,
    RollingCompatibility,
}

public enum NatsCapabilityDisposition
{
    Unspecified = 0,
    /// <summary>Adopted: every attribute below is frozen and adapters must conform.</summary>
    Accept,
    /// <summary>Not adopted yet: the revisit trigger is recorded and no adapter may assume it.</summary>
    Defer,
    /// <summary>Excluded: adapters must not use it.</summary>
    Reject,
}

/// <summary>Owner roles are a closed set so responsibility cannot drift into prose.</summary>
public enum NatsCapabilityOwner
{
    Unspecified = 0,
    RegionalControlRuntime,
    GlobalAuthorityRuntime,
    GlobalDirectoryRuntime,
    MessagingContracts,
    DeliveryContracts,
    CiRuntime,
    SecurityAndIdentity,
    InfrastructureBootstrap,
    Observability,
    StorageAndSnapshots,
}

public enum NatsDataClass
{
    Unspecified = 0,
    ControlCommand,
    AuthoritativeState,
    CoordinationRecord,
    ProjectionSnapshot,
    EvidenceArtifact,
    OperationalTelemetry,
    OperatorQuery,
}

public enum NatsDurabilityClass
{
    Unspecified = 0,
    /// <summary>Replicated file-backed JetStream state (R3 streams, KV, Object Store).</summary>
    ReplicatedDurableFile,
    /// <summary>Bounded retention durable state (limits retention, capped age/bytes).</summary>
    DurableBounded,
    /// <summary>Ephemeral in-memory delivery; loss is safe and callers retry.</summary>
    Ephemeral,
}

public enum NatsOrderingClass
{
    Unspecified = 0,
    /// <summary>JetStream per-subject FIFO.</summary>
    PerSubjectFifo,
    /// <summary>Total order enforced by one fenced writer epoch per aggregate.</summary>
    PerAggregateEpoch,
    /// <summary>No ordering guarantee; consumers must tolerate reordering.</summary>
    Unordered,
}

/// <summary>
/// One frozen capability disposition. Accepted entries carry owner, data class, durability,
/// ordering, security boundary, failure mode, observability requirement, and landed evidence.
/// Deferred entries carry a revisit trigger; rejected entries carry an exclusion rationale.
/// </summary>
public sealed record NatsCapabilityEntry(
    NatsCapability Capability,
    NatsCapabilityDisposition Disposition,
    NatsCapabilityOwner Owner,
    NatsDataClass DataClass,
    NatsDurabilityClass Durability,
    NatsOrderingClass Ordering,
    string SecurityBoundary,
    string FailureMode,
    string ObservabilityRequirement,
    string? RevisitTriggerOrRejectionRationale = null,
    string? LandedEvidence = null)
{
    internal bool IsWellFormed =>
        Capability != NatsCapability.Unspecified
        && Disposition != NatsCapabilityDisposition.Unspecified
        && (Disposition == NatsCapabilityDisposition.Accept
            ? Owner != NatsCapabilityOwner.Unspecified
               && DataClass != NatsDataClass.Unspecified
               && Durability != NatsDurabilityClass.Unspecified
               && Ordering != NatsOrderingClass.Unspecified
               && IsPresent(SecurityBoundary)
               && IsPresent(FailureMode)
               && IsPresent(ObservabilityRequirement)
               && IsPresent(LandedEvidence)
            : IsPresent(RevisitTriggerOrRejectionRationale));

    private static bool IsPresent(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512;
}

/// <summary>
/// The frozen NATS feature-adoption matrix. Canonical document:
/// <c>docs/contracts/nats-capability-matrix.md</c>. Drift tests bind this table to the
/// document and pin every disposition.
/// </summary>
public static class NatsCapabilityMatrix
{
    public static readonly IReadOnlyList<NatsCapabilityEntry> Entries = CreateEntries();

    public static NatsCapabilityEntry? Find(NatsCapability capability) =>
        Entries.SingleOrDefault(entry => entry.Capability == capability);

    /// <summary>Completeness proof: every capability named by the contract has exactly one well-formed disposition.</summary>
    public static bool IsComplete => !CompletenessViolations().Any();

    public static IReadOnlyList<string> CompletenessViolations()
    {
        var violations = new List<string>();
        var seen = new HashSet<NatsCapability>();
        foreach (var entry in Entries)
        {
            if (entry.Capability == NatsCapability.Unspecified)
            {
                violations.Add("The matrix contains an unspecified capability.");
                continue;
            }

            if (!seen.Add(entry.Capability))
            {
                violations.Add($"The matrix dispositions {entry.Capability} more than once.");
            }

            if (!entry.IsWellFormed)
            {
                violations.Add($"The {entry.Capability} entry is not well formed.");
            }
        }

        foreach (var capability in Enum.GetValues<NatsCapability>())
        {
            if (capability != NatsCapability.Unspecified && !seen.Contains(capability))
            {
                violations.Add($"The matrix does not disposition {capability}.");
            }
        }

        return violations;
    }

    private static NatsCapabilityEntry Accept(
        NatsCapability capability,
        NatsCapabilityOwner owner,
        NatsDataClass dataClass,
        NatsDurabilityClass durability,
        NatsOrderingClass ordering,
        string securityBoundary,
        string failureMode,
        string observability,
        string landedEvidence) => new(
            capability,
            NatsCapabilityDisposition.Accept,
            owner,
            dataClass,
            durability,
            ordering,
            securityBoundary,
            failureMode,
            observability,
            LandedEvidence: landedEvidence);

    private static NatsCapabilityEntry Defer(
        NatsCapability capability,
        NatsCapabilityOwner owner,
        string revisitTrigger) => new(
            capability,
            NatsCapabilityDisposition.Defer,
            owner,
            NatsDataClass.Unspecified,
            NatsDurabilityClass.Unspecified,
            NatsOrderingClass.Unspecified,
            string.Empty,
            string.Empty,
            string.Empty,
            RevisitTriggerOrRejectionRationale: revisitTrigger);

    private static NatsCapabilityEntry Reject(
        NatsCapability capability,
        NatsCapabilityOwner owner,
        string rationale) => new(
            capability,
            NatsCapabilityDisposition.Reject,
            owner,
            NatsDataClass.Unspecified,
            NatsDurabilityClass.Unspecified,
            NatsOrderingClass.Unspecified,
            string.Empty,
            string.Empty,
            string.Empty,
            RevisitTriggerOrRejectionRationale: rationale);

    private static NatsCapabilityEntry[] CreateEntries() =>
    [
        Accept(
            NatsCapability.CorePubSub,
            NatsCapabilityOwner.RegionalControlRuntime,
            NatsDataClass.OperationalTelemetry,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Control account subject permissions; publish only taxonomy subjects; no product-plane subjects.",
            "Lost publications are safe: hints, heartbeats, and fanout are advisory and consumers reconcile from durable state.",
            "Drop/latency counters per subject namespace; no alert may depend on a lossy hint.",
            "NatsRuntime service endpoints and request/reply use core pub/sub; RegionalRuntimeMembership heartbeats go through the bounded ORCH_RUNTIME KV bucket."),
        Accept(
            NatsCapability.RequestReply,
            NatsCapabilityOwner.RegionalControlRuntime,
            NatsDataClass.OperatorQuery,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Typed endpoints only; callers hold scoped subscribe permissions plus _INBOX; no-responder surfaces as an error, never silence.",
            "Timeout/no-responder is caller-visible; callers retry with the same idempotency key.",
            "Request latency and no-responder rate per endpoint; bounded timeouts are pinned by the contract.",
            "NatsRuntime health/status/members endpoints; GlobalCellDirectoryServiceRuntime serves " +
                NatsSubjectTaxonomy.GlobalDirectoryQuerySubject + "."),
        Accept(
            NatsCapability.ServicesAndDiscovery,
            NatsCapabilityOwner.RegionalControlRuntime,
            NatsDataClass.OperatorQuery,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "$SRV subjects stay account-scoped; only declared endpoints are registered; discovery complements workload DNS/LB discovery.",
            "Missing service or endpoint metadata fails the caller closed (NatsRuntime verifies discovery at startup).",
            "Service/endpoint presence, queue-group membership, and per-endpoint latency/error statistics.",
            "NatsRuntime registers terrascale_orchestrator_<cell> with health/status/members endpoints and verifies $SRV.INFO readback."),
        Accept(
            NatsCapability.QueueGroups,
            NatsCapabilityOwner.RegionalControlRuntime,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Queue groups may distribute only equivalent-worker work; the single authoritative writer is always chosen by a KV CAS lease, never by a queue group.",
            "Any group member may answer; answers must be equivalent; authoritative writes are fenced by epoch checks.",
            "Group size, member churn, and duplicate-answer rejections per group.",
            "NatsTopology.ServiceQueueGroup and OperationJournalWriterQueueGroup; DirectDelivery/DirectDeliveryCoordinators fence writes by lease epoch."),
        Accept(
            NatsCapability.Headers,
            NatsCapabilityOwner.MessagingContracts,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Headers carry only contract-defined TS-* metadata; never secrets, credentials, or payload body.",
            "Missing or malformed required headers fail closed at the wire codec before dispatch.",
            "Header validation rejection counts by header name.",
            "TS-* envelope headers in NativeGitOpsCellWireCodec, DirectDeliveryCommandWire, and NatsRuntime startup verification."),
        Accept(
            NatsCapability.MessageIds,
            NatsCapabilityOwner.MessagingContracts,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.DurableBounded,
            NatsOrderingClass.Unordered,
            "Transport-level suppression only, bounded by each stream's duplicate window; never an exactly-once claim.",
            "A duplicate outside the window is admitted; operation-level idempotency keys remain the authority.",
            "Duplicate-suppression counters next to idempotency-replay counters so the two layers stay distinguishable.",
            "MsgId on every JetStream publish (ForgejoEventPublisher, NativeGitOps publishers, NatsRuntime startup) with 2m/24h duplicate windows in NatsTopology/GlobalNatsTopology."),
        Accept(
            NatsCapability.JetStreamStreams,
            NatsCapabilityOwner.InfrastructureBootstrap,
            NatsDataClass.AuthoritativeState,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Streams are infrastructure-provisioned; controllers validate exact configuration and never create/update streams at runtime.",
            "Controller start fails closed on any stream configuration mismatch; limits retention bounds age and bytes.",
            "Stream depth, age, bytes, discarded counts, and replica health per critical stream.",
            "NatsTopology Streams (CELL_SPEC, CELL_OPERATIONS, CELL_EVENTS) and GlobalNatsTopology Streams (GLOBAL_SPEC, GLOBAL_CI) validated by NatsOperationJournalStore."),
        Accept(
            NatsCapability.DurableConsumers,
            NatsCapabilityOwner.InfrastructureBootstrap,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Consumers are provisioned with closed profiles; controllers may only create/open/ack their named consumer.",
            "A missing or mismatched consumer fails controller check/run closed rather than being created at runtime.",
            "Consumer lag, pending, redelivery counts, and exact-profile validation failures.",
            "StartupConsumer, CellSpecConsumer, CiConsumer, CiRuntimeProofConsumer, CiJobConsumer profiles with exact-match startup validation (NatsRuntime.OpenExactConsumerAsync)."),
        Accept(
            NatsCapability.Acknowledgement,
            NatsCapabilityOwner.DeliveryContracts,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Explicit-ack consumers only; a worker acknowledges only after the durable effect is journaled or an idempotent replay is proven; long work sends progress.",
            "A crash before ack means redelivery; the idempotency key makes the replay safe; authority loss after acceptance withholds the ack.",
            "Ack latency after durable effect, progress-heartbeat age, and authority-lost-after-acceptance counts.",
            "NativeGitOpsCellInbox double-acks after journal acceptance; RepositoryCiJobNatsConsumer sends AckProgressAsync; ForgejoCiEventConsumer terminally acks deterministic conflicts."),
        Accept(
            NatsCapability.RedeliveryAndBackoff,
            NatsCapabilityOwner.DeliveryContracts,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Bounded by the consumer profile: at most 5 deliveries with a 1s/5s/15s/30s backoff ladder; ack wait is derived from the first backoff interval.",
            "Exhaustion stops redelivery only with terminal evidence; no message may disappear silently.",
            "Redelivery histograms, exhaustion counts, and final-delivery warnings by subject.",
            "Consumer profiles in NatsTopology/GlobalNatsTopology; final-delivery warning and Nak-with-delay in ForgejoCiEventConsumer."),
        Accept(
            NatsCapability.FlowControl,
            NatsCapabilityOwner.InfrastructureBootstrap,
            NatsDataClass.OperationalTelemetry,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "$JS.FC grants are granted only to identities that own the consuming stream/bucket; the global authority never receives durable/pull/ack shapes for watch-only buckets.",
            "A stalled consumer that stops answering flow control is marked slow and surfaced, never silently dropped.",
            "Slow-consumer advisories and outstanding flow-control latency per consumer.",
            "Explicit $JS.FC permission grants in GlobalNatsPermissions; the GlobalNatsAccessContract account model grants them only to the owning stream or bucket identity."),
        Accept(
            NatsCapability.KeyValueCasAndWatch,
            NatsCapabilityOwner.RegionalControlRuntime,
            NatsDataClass.CoordinationRecord,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerAggregateEpoch,
            "KV provides leases, epochs, and small coordination records only; the operation stream stays the durable explanation/history; journal KV stores are denied to controllers.",
            "CAS conflict is a normal outcome: the loser re-observes and retries; ambiguity holds instead of creating a competing writer.",
            "CAS conflict rate, lease age, watch lag, and journal-store denial attempts.",
            "RegionalAuthorityCoordinator CAS leases/epochs; GlobalCellDirectoryRuntime watches cell.>; GlobalNatsPermissions grants inbox-delivered ephemeral watch consumers only."),
        Accept(
            NatsCapability.ObjectStore,
            NatsCapabilityOwner.StorageAndSnapshots,
            NatsDataClass.EvidenceArtifact,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Small signed bundles, protocol packages, and evidence only; never the build registry or backup system; secrets never enter objects.",
            "Missing or byte-unequal protocol package fails startup closed; bundle digests are content-addressed.",
            "Object counts/bytes per bucket and integrity-check failures.",
            "CELL_BUNDLES, GLOBAL_BUNDLES, CI_RUNNER_BUNDLES, ORCH_PROTOCOL_PACKAGE with byte-exact verification in NatsRuntime."),
        Accept(
            NatsCapability.Accounts,
            NatsCapabilityOwner.SecurityAndIdentity,
            NatsDataClass.CoordinationRecord,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.Unordered,
            "Hard namespaces: system, global authority, global directory, regional control, CI, audit/export, operator, product, test; capability determines the account, never caller-supplied credentials.",
            "An identity in the wrong account simply lacks permissions; cross-plane authorization is structurally impossible.",
            "Account-scoped auth failures and permission denials feed security alerts.",
            "GlobalNatsAccountNames and GlobalNatsAccessContract account split; distinct control/product planes in the NatsSubjectTaxonomy account model."),
        Defer(
            NatsCapability.Jwts,
            NatsCapabilityOwner.SecurityAndIdentity,
            "Operator/account/user JWT issuance and the JWT/NKey administration toolchain are unselected (phase1-nats-l0c-foundation outcome); adopt only after the L0C lane pins the toolchain and rotating account-signing-key procedure."),
        Accept(
            NatsCapability.NKeys,
            NatsCapabilityOwner.SecurityAndIdentity,
            NatsDataClass.CoordinationRecord,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "NKey authentication for controllers, writer, infrastructure, directory, and operator identities; every command rejects every NATS credential family it does not own before file resolution.",
            "Anonymous connections must be denied (startup verifies); a missing NKey fails closed.",
            "Authentication failure counts by identity family; anonymous-denial verification at startup.",
            "OrchestratorOptions.NatsNKeyFile, NatsRuntime.VerifyAnonymousDeniedAsync, CiRunnerNatsCredentialIssuer, GlobalNatsAccessContract identity separation."),
        Accept(
            NatsCapability.Mtls,
            NatsCapabilityOwner.SecurityAndIdentity,
            NatsDataClass.CoordinationRecord,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "mTLS proves machine/workload transport identity for clients, routes, and gateways; it never replaces NKey/JWT authorization; global endpoints require absolute tls:// URLs.",
            "TLS failure is a startup/connection failure; no plaintext fallback path exists.",
            "Certificate expiry freshness, handshake failures, and per-endpoint TLS mode.",
            "NatsRuntime NatsTlsOpts Require mode; NatsTlsFiles; infrastructure mTLS required by NatsOperationJournalProvisioner."),
        Accept(
            NatsCapability.ImportsAndExports,
            NatsCapabilityOwner.SecurityAndIdentity,
            NatsDataClass.OperatorQuery,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Least-privilege service import/export across accounts within one cluster only (the directory query service); cross-cluster/region stream or service import/export is rejected — the gateway mesh is the only cross-cluster path and no stream may span regions.",
            "A missing import/export makes the cross-account call fail closed with no-responder.",
            "Import/export presence checks per account pair; any undeclared cross-account subject is a security alert.",
            "GlobalNatsServiceImport/Export for " + NatsSubjectTaxonomy.GlobalDirectoryQuerySubject +
                " in GlobalNatsAccessContract; no cross-region stream exists in either topology."),
        Accept(
            NatsCapability.Gateways,
            NatsCapabilityOwner.InfrastructureBootstrap,
            NatsDataClass.CoordinationRecord,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Launch topology is a full mTLS gateway mesh (not hub-and-spoke) inside one offline control-plane operator domain; local streams and actions stay regional; explicit known clusters with constrained account traffic.",
            "Gateway loss isolates regions; regional control stays autonomous and pre-authorized regional work continues.",
            "Gateway link state, latency, and isolated-region duration; expansion beyond the mesh envelope requires a new owner decision.",
            "Gateway membership validated by MessagingPolicyEngine plane policies (docs/architecture/orchestrator.md launch-control topology); no production gateway adapter is deployed yet."),
        Accept(
            NatsCapability.Advisories,
            NatsCapabilityOwner.Observability,
            NatsDataClass.OperationalTelemetry,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "Authenticated $SYS subjects only for remote status; advisories are read, never acted on as authority.",
            "A missed advisory degrades monitoring only; it never changes control decisions.",
            "Slow-consumer, quorum/leader-change, and auth-failure advisories are alert inputs.",
            "docs/architecture/orchestrator.md system-account monitoring contract; observability adapters consume advisories (design-binding; see unresolved measurements)."),
        Accept(
            NatsCapability.SystemMonitoring,
            NatsCapabilityOwner.Observability,
            NatsDataClass.OperationalTelemetry,
            NatsDurabilityClass.Ephemeral,
            NatsOrderingClass.Unordered,
            "HTTP monitoring binds to loopback or an isolated host-management address only, scraped locally; remote status goes through authenticated $SYS subjects; the monitoring port has no application auth boundary and is never internet- or workload-exposed.",
            "Monitoring loss blinds operators without affecting control correctness.",
            "Server/account/connection/consumer health and quorum state feed Grafana and alerts.",
            "docs/architecture/orchestrator.md NATS monitoring rules; dev-lab and production monitoring adapters tracked as an unresolved measurement."),
        Accept(
            NatsCapability.Snapshots,
            NatsCapabilityOwner.StorageAndSnapshots,
            NatsDataClass.EvidenceArtifact,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerSubjectFifo,
            "Snapshots carry a signed stream position and schema version; restore replays from that position and refuses an older snapshot over a newer accepted epoch; journal KV stores deny snapshot/restore APIs to controllers.",
            "Restore never regresses accepted epochs; product data never enters control backups and control state never enters product backups.",
            "Snapshot freshness, restore attempts, and refusal counts by reason.",
            "SignedSnapshot/SnapshotRestore pure core; journal stores provisioned by NatsOperationJournalProvisioner with snapshot/restore APIs denied to controllers; stream/KV snapshot-restore exercise is an L0C gate."),
        Accept(
            NatsCapability.RollingCompatibility,
            NatsCapabilityOwner.MessagingContracts,
            NatsDataClass.ControlCommand,
            NatsDurabilityClass.ReplicatedDurableFile,
            NatsOrderingClass.PerAggregateEpoch,
            "N and N-1 interoperate for commands, snapshots, schema reads, and leadership transfer; upgrades proceed one plane and one failure domain at a time and cannot remove the last candidate or drop either plane below its disruption budget.",
            "An upgrade cannot proceed without current and rollback artifacts in the regional survival bundle; N-1 nodes fail closed on N-major documents.",
            "Per-version interop matrix results and rollback outcomes per failure domain.",
            "MessagingPolicyEngine.DecideCompatibility (Commands, Snapshots, SchemaReads, LeadershipTransfer); forward-only schema migration discipline in RepositoryCiJobJournal."),
    ];
}

