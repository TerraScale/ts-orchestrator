using System.Diagnostics.CodeAnalysis;

namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

/// <summary>
/// Machine-readable registry of the permanent stable contract identifiers
/// defined by the GOAL.md "Stable contract identifiers" tables. The canonical
/// text below is copied verbatim from GOAL.md and never changes in place.
/// Registry rules encoded here: identifiers are permanent; a replacement
/// decision marks the old identifier superseded through
/// <see cref="Supersessions"/> and adds a new identifier; the meaning of a
/// live identifier is never edited. <see cref="SupersessionViolations"/>
/// reports every breach of those rules, so it must stay empty.
/// </summary>
public static class StableIdentifierRegistry
{
    /// <summary>Revision of the GOAL.md identifier tables this registry transcribes.</summary>
    public const string RegistryRevision = "2026-08-29";

    private static readonly IReadOnlyDictionary<RequirementId, string> RequirementTexts = new Dictionary<RequirementId, string>
    {
        [RequirementId.FromValue("REQ-ORCH-001")] = "GRU runs the permanent global authority.",
        [RequirementId.FromValue("REQ-ORCH-002")] = "Every global and regional controller group has three replicas and one active leader.",
        [RequirementId.FromValue("REQ-ORCH-003")] = "Every NATS control domain uses JetStream file storage with three replicas.",
        [RequirementId.FromValue("REQ-ORCH-004")] = "Every active Region operates safely during GRU or WAN loss from its last accepted policy.",
        [RequirementId.FromValue("REQ-ORCH-005")] = "GRU receives the complete regional journal after connectivity returns.",
        [RequirementId.FromValue("REQ-ORCH-006")] = "The Orchestrator bootstraps and owns the greenfield OCI estate without Pulumi or OpenTofu.",
        [RequirementId.FromValue("REQ-ORCH-007")] = "OCI mutations use typed, region-scoped provider actuators and durable journals.",
        [RequirementId.FromValue("REQ-ORCH-008")] = "The scheduler places only admitted immutable workloads on eligible hosts.",
        [RequirementId.FromValue("REQ-ORCH-009")] = "TerraBase placement follows database-selected Regions and RF=2 active Members per Region and Partition.",
        [RequirementId.FromValue("REQ-ORCH-010")] = "Dashboard and Database API run at least two instances per qualified Region.",
        [RequirementId.FromValue("REQ-ORCH-011")] = "Orchestrator provisions workload identity, trust bundles, rotation, and bootstrap grants.",
        [RequirementId.FromValue("REQ-ORCH-012")] = "Orchestrator operates Cloudflare global and strict regional routing for no more than twenty active Regions.",
        [RequirementId.FromValue("REQ-ORCH-013")] = "Delivery admits exact artifacts, provenance, configuration, migrations, and rollback anchors.",
        [RequirementId.FromValue("REQ-ORCH-014")] = "Autoscaling uses sustained typed capacity reports and preserves hard safety ceilings.",
        [RequirementId.FromValue("REQ-ORCH-015")] = "Every long-running action exposes durable exact progress and a terminal receipt.",
        [RequirementId.FromValue("REQ-ORCH-016")] = "Regional and global control state has backup, restore, corruption, and total-rebuild evidence.",
        [RequirementId.FromValue("REQ-ORCH-017")] = "Operators receive typed plans, holds, approvals, progress, and redacted evidence.",
        [RequirementId.FromValue("REQ-ORCH-018")] = "The production release qualifies GRU, SFO, FRA, ARM64 control hosts, ARM64 and x86_64 TerraBase workload hosts, OCI, NATS, systemd, containerd, Block Volume, Vault, Object Storage, and Cloudflare.",
        [RequirementId.FromValue("REQ-ORCH-019")] = "The architecture supports a deterministic twenty-Region simulation before the fourth Region is published.",
        [RequirementId.FromValue("REQ-ORCH-020")] = "No customer-serving request requires a live Orchestrator or NATS lookup.",
        [RequirementId.FromValue("REQ-ORCH-021")] = "The production repository, solution, runtime, and artifact contain no embedded development-host composition or DevHost dependency.",
        [RequirementId.FromValue("REQ-ORCH-022")] = "Every production upgrade creates and qualifies a parallel regional candidate before cutover.",
        [RequirementId.FromValue("REQ-ORCH-023")] = "Every host publishes admitted capacity, reserved capacity, allocatable capacity, pressure, shutdown, and reclamation state.",
        [RequirementId.FromValue("REQ-ORCH-024")] = "Every workload uses a closed execution mode, restart policy, priority class, preemption policy, network lease, and filesystem-reclamation contract.",
        [RequirementId.FromValue("REQ-ORCH-025")] = "Resource status, list, and watch APIs expose conditions, `observedGeneration`, stable pagination, resumable progress, compaction recovery, and bounded overload behavior.",
        [RequirementId.FromValue("REQ-ORCH-026")] = "Dependency-aware deletion uses durable typed blockers and verified absence before final removal.",
        [RequirementId.FromValue("REQ-ORCH-027")] = "Reconcile, reconnect, health, and provider work queues are bounded, fair, coalesced by resource, and safe under retry storms.",
        [RequirementId.FromValue("REQ-ORCH-028")] = "Rebalancing and consolidation preserve disruption budgets, failure headroom, surge capacity, storage safety, and a measured net benefit.",
    };

    private static readonly IReadOnlyDictionary<InvariantId, string> InvariantTexts = new Dictionary<InvariantId, string>
    {
        [InvariantId.FromValue("INV-ORCH-001")] = "One exact authority term may mutate one control scope.",
        [InvariantId.FromValue("INV-ORCH-002")] = "Global policy has one writer in GRU.",
        [InvariantId.FromValue("INV-ORCH-003")] = "Regional mutation requires the current local term and local NATS quorum.",
        [InvariantId.FromValue("INV-ORCH-004")] = "An isolated Region cannot create a new global generation.",
        [InvariantId.FromValue("INV-ORCH-005")] = "Desired state never erases a provider or TerraBase observation.",
        [InvariantId.FromValue("INV-ORCH-006")] = "Every external mutation is preceded by durable authorized intent.",
        [InvariantId.FromValue("INV-ORCH-007")] = "Unknown provider outcome is reconciled before retry or compensation.",
        [InvariantId.FromValue("INV-ORCH-008")] = "One provider resource has one active lifecycle owner.",
        [InvariantId.FromValue("INV-ORCH-009")] = "Tags and discovery never grant mutation authority.",
        [InvariantId.FromValue("INV-ORCH-010")] = "A stale leader cannot complete a new accepted mutation.",
        [InvariantId.FromValue("INV-ORCH-011")] = "A committed provider target remains fixed across leadership change.",
        [InvariantId.FromValue("INV-ORCH-012")] = "NATS never carries customer data or TerraBase correctness state.",
        [InvariantId.FromValue("INV-ORCH-013")] = "TerraBase alone accepts membership and retirement.",
        [InvariantId.FromValue("INV-ORCH-014")] = "Scale-in cannot reduce required durability or recovery headroom.",
        [InvariantId.FromValue("INV-ORCH-015")] = "Secrets and private keys never enter desired state, NATS, telemetry, receipts, or Git.",
        [InvariantId.FromValue("INV-ORCH-016")] = "A release activates only the exact qualified digest and configuration.",
        [InvariantId.FromValue("INV-ORCH-017")] = "Catalog discovery and catalog publication are separate transitions.",
        [InvariantId.FromValue("INV-ORCH-018")] = "A retired `RegionCode`, Member identity, replica epoch, volume identity, or bootstrap generation is never reused unsafely.",
        [InvariantId.FromValue("INV-ORCH-019")] = "Admission and backpressure protect workloads before capacity arrives.",
        [InvariantId.FromValue("INV-ORCH-020")] = "Telemetry cannot authorize a destructive operation.",
        [InvariantId.FromValue("INV-ORCH-021")] = "An active allocation is never mutated in place during release.",
        [InvariantId.FromValue("INV-ORCH-022")] = "Development composition, credentials, trust roots, and authority paths cannot enter a production artifact or state store.",
        [InvariantId.FromValue("INV-ORCH-023")] = "Production traffic cannot reach a candidate before its exact generation satisfies minimum healthy time and every required gate.",
        [InvariantId.FromValue("INV-ORCH-024")] = "One active allocation owns one unique, durable IP and port lease for each bound endpoint.",
        [InvariantId.FromValue("INV-ORCH-025")] = "A resource cannot disappear while a current typed deletion blocker, live dependent, or unverified external resource remains.",
        [InvariantId.FromValue("INV-ORCH-026")] = "Status cannot claim a desired generation applied until `observedGeneration` equals that generation.",
        [InvariantId.FromValue("INV-ORCH-027")] = "Host pressure stops new placement before eviction, and planned shutdown drains admitted work before poweroff.",
        [InvariantId.FromValue("INV-ORCH-028")] = "Queue overload sheds, delays, or coalesces work without dropping durable intent or creating unbounded memory use.",
    };

    private static readonly IReadOnlyDictionary<SecurityRuleId, string> SecurityRuleTexts = new Dictionary<SecurityRuleId, string>
    {
        [SecurityRuleId.FromValue("SEC-ORCH-001")] = "Every privileged network boundary uses TLS 1.3 and mutual workload identity.",
        [SecurityRuleId.FromValue("SEC-ORCH-002")] = "NATS servers use mTLS; clients also use scoped NKey and JWT identities.",
        [SecurityRuleId.FromValue("SEC-ORCH-003")] = "Global, regional, host-agent, CI, monitoring, and infrastructure identities have disjoint permissions.",
        [SecurityRuleId.FromValue("SEC-ORCH-004")] = "Regional OCI credentials cannot mutate another Region or the tenancy root.",
        [SecurityRuleId.FromValue("SEC-ORCH-005")] = "GRU global controllers do not hold ordinary regional OCI mutation credentials.",
        [SecurityRuleId.FromValue("SEC-ORCH-006")] = "Secret configuration contains references and version identities only.",
        [SecurityRuleId.FromValue("SEC-ORCH-007")] = "Private keys are non-exportable where OCI Vault supports the required operation.",
        [SecurityRuleId.FromValue("SEC-ORCH-008")] = "Bootstrap credentials expire or are revoked after handoff.",
        [SecurityRuleId.FromValue("SEC-ORCH-009")] = "Artifacts require immutable digest, signature, provenance, SBOM, and vulnerability disposition.",
        [SecurityRuleId.FromValue("SEC-ORCH-010")] = "No ordinary operation requires inbound SSH.",
        [SecurityRuleId.FromValue("SEC-ORCH-011")] = "Break-glass access is time-bound, approved, recorded, and automatically revoked.",
        [SecurityRuleId.FromValue("SEC-ORCH-012")] = "Logs, traces, metrics, errors, fixtures, and receipts redact secret and customer content before emission.",
        [SecurityRuleId.FromValue("SEC-ORCH-013")] = "Development trust roots, certificates, credentials, tokens, and secret defaults never enter production state, images, packages, or deployments.",
        [SecurityRuleId.FromValue("SEC-ORCH-014")] = "A workload receives network, port, filesystem, device, secret, and peer access only through its admitted allocation contract.",
    };

    private static readonly IReadOnlyDictionary<StateMachineId, string> StateMachineTexts = new Dictionary<StateMachineId, string>
    {
        [StateMachineId.FromValue("SM-ORCH-BOOTSTRAP")] = "Empty tenancy to accepted GRU authority",
        [StateMachineId.FromValue("SM-ORCH-GLOBAL-AUTHORITY")] = "Global leader election, renewal, fencing, and replacement",
        [StateMachineId.FromValue("SM-ORCH-REGIONAL-AUTHORITY")] = "Regional leader election, renewal, fencing, and replacement",
        [StateMachineId.FromValue("SM-ORCH-REGION-ADMISSION")] = "Planned Region to owner-approved catalog publication",
        [StateMachineId.FromValue("SM-ORCH-REGION-REMOVAL")] = "Routing fence through final retention and deletion receipts",
        [StateMachineId.FromValue("SM-ORCH-PROVIDER-OPERATION")] = "Prepared intent through exact provider terminal outcome",
        [StateMachineId.FromValue("SM-ORCH-HOST-LIFECYCLE")] = "Host request, creation, enrollment, admission, drain, and retirement",
        [StateMachineId.FromValue("SM-ORCH-WORKLOAD-LIFECYCLE")] = "Artifact admission through allocation, minimum health, service, drain, and verified stop",
        [StateMachineId.FromValue("SM-ORCH-MEMBER-ADD")] = "TerraBase identity allocation through membership acceptance",
        [StateMachineId.FromValue("SM-ORCH-MEMBER-REPLACE")] = "Failed seat through verified replacement and safe retirement",
        [StateMachineId.FromValue("SM-ORCH-CAPACITY")] = "Pressure observation through scale, rebalance, or admission refusal",
        [StateMachineId.FromValue("SM-ORCH-RELEASE")] = "Immutable blue through parallel green creation, qualification, atomic cutover, rollback window, and blue retirement",
        [StateMachineId.FromValue("SM-ORCH-RECONNECT")] = "Regional isolation through journal upload and reconciled generation",
        [StateMachineId.FromValue("SM-ORCH-TRUST-ROTATION")] = "New trust generation through overlap and old-generation retirement",
        [StateMachineId.FromValue("SM-ORCH-CONTROL-RESTORE")] = "Backup selection through new fenced recovery generation",
        [StateMachineId.FromValue("SM-ORCH-NODE-PRESSURE")] = "Pressure detection through cordon, reclaim, drain, recovery, or failed-host replacement",
        [StateMachineId.FromValue("SM-ORCH-WORKLOAD-RESTART")] = "Failure through bounded backoff, stable recovery, rollback, or digest quarantine",
        [StateMachineId.FromValue("SM-ORCH-RESOURCE-DELETION")] = "Deletion request through dependent drain, blocker release, external absence, and tombstone retention",
    };

    private static readonly IReadOnlyDictionary<StableErrorId, string> StableErrorTexts = new Dictionary<StableErrorId, string>
    {
        [StableErrorId.FromValue("ERR-ORCH-AUTHORITY-UNAVAILABLE")] = "The required authority quorum or current term is unavailable.",
        [StableErrorId.FromValue("ERR-ORCH-STALE-TERM")] = "A command, executor, or observation belongs to an older authority term.",
        [StableErrorId.FromValue("ERR-ORCH-GENERATION-CONFLICT")] = "Desired, applied, or observed generations cannot be reconciled automatically.",
        [StableErrorId.FromValue("ERR-ORCH-REGION-ISOLATED")] = "The requested action is outside the Region's admitted survival policy.",
        [StableErrorId.FromValue("ERR-ORCH-OUTCOME-UNKNOWN")] = "An external mutation may have occurred and needs observation.",
        [StableErrorId.FromValue("ERR-ORCH-OWNERSHIP-MISMATCH")] = "Positive resource ownership does not match the requested operation.",
        [StableErrorId.FromValue("ERR-ORCH-EVIDENCE-INCOMPLETE")] = "Required current and complete evidence is missing.",
        [StableErrorId.FromValue("ERR-ORCH-CAPACITY-UNAVAILABLE")] = "No eligible placement satisfies resources and safety reserves.",
        [StableErrorId.FromValue("ERR-ORCH-BUDGET-APPROVAL-REQUIRED")] = "A safe operation exceeds the automatic budget but not the hard ceiling.",
        [StableErrorId.FromValue("ERR-ORCH-PROVIDER-LIMIT")] = "A provider quota, capacity, or account ceiling blocks the action.",
        [StableErrorId.FromValue("ERR-ORCH-TERRABASE-HOLD")] = "TerraBase has not accepted the required membership, frontier, or retirement state.",
        [StableErrorId.FromValue("ERR-ORCH-ARTIFACT-DENIED")] = "Artifact identity, signature, provenance, architecture, or rollback evidence failed.",
        [StableErrorId.FromValue("ERR-ORCH-REGION-NOT-QUALIFIED")] = "A Region cannot receive customer traffic or placement.",
        [StableErrorId.FromValue("ERR-ORCH-RESTORE-GENERATION-CONFLICT")] = "A restore might overlap a live control generation.",
        [StableErrorId.FromValue("ERR-ORCH-CANDIDATE-NOT-READY")] = "The exact candidate has not passed minimum health, compatibility, routing, or required tests.",
        [StableErrorId.FromValue("ERR-ORCH-WORKLOAD-QUARANTINED")] = "The artifact and configuration pair exceeded its restart or health-failure budget.",
        [StableErrorId.FromValue("ERR-ORCH-DELETION-BLOCKED")] = "A current dependent, safety hold, or external resource prevents deletion.",
        [StableErrorId.FromValue("ERR-ORCH-WATCH-EXPIRED")] = "The resume point is below retained journal history and the client must relist.",
    };

    // A replacement decision maps the retired identifier value to its
    // replacement here and adds the replacement to its kind's table above. It
    // never edits the retired identifier's canonical text. The table starts
    // empty because no identifier has been replaced.
    private static readonly IReadOnlyDictionary<string, string> SupersederValues =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public static IReadOnlyDictionary<RequirementId, string> Requirements => RequirementTexts;

    public static IReadOnlyDictionary<InvariantId, string> Invariants => InvariantTexts;

    public static IReadOnlyDictionary<SecurityRuleId, string> SecurityRules => SecurityRuleTexts;

    public static IReadOnlyDictionary<StateMachineId, string> StateMachines => StateMachineTexts;

    public static IReadOnlyDictionary<StableErrorId, string> StableErrors => StableErrorTexts;

    public static IReadOnlyDictionary<string, string> Supersessions => SupersederValues;

    public static bool TryGetText(RequirementId identifier, [NotNullWhen(true)] out string? text) => TryGetText(RequirementTexts, identifier, out text);

    public static bool TryGetText(InvariantId identifier, [NotNullWhen(true)] out string? text) => TryGetText(InvariantTexts, identifier, out text);

    public static bool TryGetText(SecurityRuleId identifier, [NotNullWhen(true)] out string? text) => TryGetText(SecurityRuleTexts, identifier, out text);

    public static bool TryGetText(StateMachineId identifier, [NotNullWhen(true)] out string? text) => TryGetText(StateMachineTexts, identifier, out text);

    public static bool TryGetText(StableErrorId identifier, [NotNullWhen(true)] out string? text) => TryGetText(StableErrorTexts, identifier, out text);

    public static RequirementId? SupersededBy(RequirementId identifier) =>
        SupersederValues.TryGetValue(identifier.Value, out var replacement) && RequirementId.TryCreate(replacement, out var superseder)
            ? superseder
            : null;

    public static InvariantId? SupersededBy(InvariantId identifier) =>
        SupersederValues.TryGetValue(identifier.Value, out var replacement) && InvariantId.TryCreate(replacement, out var superseder)
            ? superseder
            : null;

    public static SecurityRuleId? SupersededBy(SecurityRuleId identifier) =>
        SupersederValues.TryGetValue(identifier.Value, out var replacement) && SecurityRuleId.TryCreate(replacement, out var superseder)
            ? superseder
            : null;

    public static StateMachineId? SupersededBy(StateMachineId identifier) =>
        SupersederValues.TryGetValue(identifier.Value, out var replacement) && StateMachineId.TryCreate(replacement, out var superseder)
            ? superseder
            : null;

    public static StableErrorId? SupersededBy(StableErrorId identifier) =>
        SupersederValues.TryGetValue(identifier.Value, out var replacement) && StableErrorId.TryCreate(replacement, out var superseder)
            ? superseder
            : null;

    /// <summary>
    /// Reports every breach of the supersession rules: retired or replacement
    /// values that are not registered identifiers of the same kind,
    /// self-supersession, and supersession cycles. The list must stay empty.
    /// </summary>
    public static IReadOnlyList<string> SupersessionViolations()
    {
        var violations = new List<string>();
        foreach (var (retired, replacement) in SupersederValues)
        {
            var retiredKind = TryClassify(retired);
            var replacementKind = TryClassify(replacement);
            if (retiredKind is null)
            {
                violations.Add($"{retired} is not a registered identifier.");
            }

            if (replacementKind is null)
            {
                violations.Add($"{replacement} is not a registered identifier.");
            }

            if (retiredKind is not null && replacementKind is not null && retiredKind != replacementKind)
            {
                violations.Add($"{retired} and {replacement} belong to different identifier kinds.");
            }

            if (string.Equals(retired, replacement, StringComparison.Ordinal))
            {
                violations.Add($"{retired} supersedes itself.");
            }
        }

        foreach (var retired in SupersederValues.Keys)
        {
            var visited = new HashSet<string>(StringComparer.Ordinal);
            var current = retired;
            while (SupersederValues.TryGetValue(current, out var next))
            {
                if (!visited.Add(current))
                {
                    violations.Add($"{retired} participates in a supersession cycle at {current}.");
                    break;
                }

                current = next;
            }
        }

        return violations;
    }

    private static bool TryGetText<TId>(IReadOnlyDictionary<TId, string> texts, TId identifier, [NotNullWhen(true)] out string? text)
        where TId : notnull
    {
        if (texts.TryGetValue(identifier, out var canonical))
        {
            text = canonical;
            return true;
        }

        text = null;
        return false;
    }

    private static StableIdentifierKind? TryClassify(string value) =>
        RequirementTexts.TryGetValue(RequirementId.FromValue(value), out _) ? StableIdentifierKind.Requirement
            : InvariantTexts.TryGetValue(InvariantId.FromValue(value), out _) ? StableIdentifierKind.Invariant
            : SecurityRuleTexts.TryGetValue(SecurityRuleId.FromValue(value), out _) ? StableIdentifierKind.SecurityRule
            : StateMachineTexts.TryGetValue(StateMachineId.FromValue(value), out _) ? StableIdentifierKind.StateMachine
            : StableErrorTexts.TryGetValue(StableErrorId.FromValue(value), out _) ? StableIdentifierKind.StableError
            : null;
}

