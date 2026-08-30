// Port of src/TerraScale.Orchestrator/Protocol/Messaging/NatsCapabilityMatrix.cs.
package protocol

import "strings"

// NatsCapability mirrors the NatsCapability enum: every NATS capability named
// by the frozen feature-adoption contract. The enum is the machine-readable
// completeness key: the matrix must disposition each member exactly once.
type NatsCapability int

const (
	NatsCapabilityUnspecified          NatsCapability = 0
	NatsCapabilityCorePubSub           NatsCapability = 1
	NatsCapabilityRequestReply         NatsCapability = 2
	NatsCapabilityServicesAndDiscovery NatsCapability = 3
	NatsCapabilityQueueGroups          NatsCapability = 4
	NatsCapabilityHeaders              NatsCapability = 5
	NatsCapabilityMessageIds           NatsCapability = 6
	NatsCapabilityJetStreamStreams     NatsCapability = 7
	NatsCapabilityDurableConsumers     NatsCapability = 8
	NatsCapabilityAcknowledgement      NatsCapability = 9
	NatsCapabilityRedeliveryAndBackoff NatsCapability = 10
	NatsCapabilityFlowControl          NatsCapability = 11
	NatsCapabilityKeyValueCasAndWatch  NatsCapability = 12
	NatsCapabilityObjectStore          NatsCapability = 13
	NatsCapabilityAccounts             NatsCapability = 14
	NatsCapabilityJwts                 NatsCapability = 15
	NatsCapabilityNKeys                NatsCapability = 16
	NatsCapabilityMtls                 NatsCapability = 17
	NatsCapabilityImportsAndExports    NatsCapability = 18
	NatsCapabilityGateways             NatsCapability = 19
	NatsCapabilityAdvisories           NatsCapability = 20
	NatsCapabilitySystemMonitoring     NatsCapability = 21
	NatsCapabilitySnapshots            NatsCapability = 22
	NatsCapabilityRollingCompatibility NatsCapability = 23
)

func (c NatsCapability) String() string {
	switch c {
	case NatsCapabilityCorePubSub:
		return "CorePubSub"
	case NatsCapabilityRequestReply:
		return "RequestReply"
	case NatsCapabilityServicesAndDiscovery:
		return "ServicesAndDiscovery"
	case NatsCapabilityQueueGroups:
		return "QueueGroups"
	case NatsCapabilityHeaders:
		return "Headers"
	case NatsCapabilityMessageIds:
		return "MessageIds"
	case NatsCapabilityJetStreamStreams:
		return "JetStreamStreams"
	case NatsCapabilityDurableConsumers:
		return "DurableConsumers"
	case NatsCapabilityAcknowledgement:
		return "Acknowledgement"
	case NatsCapabilityRedeliveryAndBackoff:
		return "RedeliveryAndBackoff"
	case NatsCapabilityFlowControl:
		return "FlowControl"
	case NatsCapabilityKeyValueCasAndWatch:
		return "KeyValueCasAndWatch"
	case NatsCapabilityObjectStore:
		return "ObjectStore"
	case NatsCapabilityAccounts:
		return "Accounts"
	case NatsCapabilityJwts:
		return "Jwts"
	case NatsCapabilityNKeys:
		return "NKeys"
	case NatsCapabilityMtls:
		return "Mtls"
	case NatsCapabilityImportsAndExports:
		return "ImportsAndExports"
	case NatsCapabilityGateways:
		return "Gateways"
	case NatsCapabilityAdvisories:
		return "Advisories"
	case NatsCapabilitySystemMonitoring:
		return "SystemMonitoring"
	case NatsCapabilitySnapshots:
		return "Snapshots"
	case NatsCapabilityRollingCompatibility:
		return "RollingCompatibility"
	default:
		return "Unspecified"
	}
}

// NatsCapabilityDisposition mirrors the NatsCapabilityDisposition enum.
type NatsCapabilityDisposition int

const (
	NatsCapabilityDispositionUnspecified NatsCapabilityDisposition = 0
	// NatsCapabilityDispositionAccept: adopted; every attribute below is
	// frozen and adapters must conform.
	NatsCapabilityDispositionAccept NatsCapabilityDisposition = 1
	// NatsCapabilityDispositionDefer: not adopted yet; the revisit trigger is
	// recorded and no adapter may assume it.
	NatsCapabilityDispositionDefer NatsCapabilityDisposition = 2
	// NatsCapabilityDispositionReject: excluded; adapters must not use it.
	NatsCapabilityDispositionReject NatsCapabilityDisposition = 3
)

func (d NatsCapabilityDisposition) String() string {
	switch d {
	case NatsCapabilityDispositionAccept:
		return "Accept"
	case NatsCapabilityDispositionDefer:
		return "Defer"
	case NatsCapabilityDispositionReject:
		return "Reject"
	default:
		return "Unspecified"
	}
}

// NatsCapabilityOwner mirrors the NatsCapabilityOwner enum: owner roles are a
// closed set so responsibility cannot drift into prose.
type NatsCapabilityOwner int

const (
	NatsCapabilityOwnerUnspecified             NatsCapabilityOwner = 0
	NatsCapabilityOwnerRegionalControlRuntime  NatsCapabilityOwner = 1
	NatsCapabilityOwnerGlobalAuthorityRuntime  NatsCapabilityOwner = 2
	NatsCapabilityOwnerGlobalDirectoryRuntime  NatsCapabilityOwner = 3
	NatsCapabilityOwnerMessagingContracts      NatsCapabilityOwner = 4
	NatsCapabilityOwnerDeliveryContracts       NatsCapabilityOwner = 5
	NatsCapabilityOwnerCiRuntime               NatsCapabilityOwner = 6
	NatsCapabilityOwnerSecurityAndIdentity     NatsCapabilityOwner = 7
	NatsCapabilityOwnerInfrastructureBootstrap NatsCapabilityOwner = 8
	NatsCapabilityOwnerObservability           NatsCapabilityOwner = 9
	NatsCapabilityOwnerStorageAndSnapshots     NatsCapabilityOwner = 10
)

// NatsDataClass mirrors the NatsDataClass enum.
type NatsDataClass int

const (
	NatsDataClassUnspecified          NatsDataClass = 0
	NatsDataClassControlCommand       NatsDataClass = 1
	NatsDataClassAuthoritativeState   NatsDataClass = 2
	NatsDataClassCoordinationRecord   NatsDataClass = 3
	NatsDataClassProjectionSnapshot   NatsDataClass = 4
	NatsDataClassEvidenceArtifact     NatsDataClass = 5
	NatsDataClassOperationalTelemetry NatsDataClass = 6
	NatsDataClassOperatorQuery        NatsDataClass = 7
)

// NatsDurabilityClass mirrors the NatsDurabilityClass enum.
type NatsDurabilityClass int

const (
	NatsDurabilityClassUnspecified NatsDurabilityClass = 0
	// NatsDurabilityClassReplicatedDurableFile: replicated file-backed
	// JetStream state (R3 streams, KV, Object Store).
	NatsDurabilityClassReplicatedDurableFile NatsDurabilityClass = 1
	// NatsDurabilityClassDurableBounded: bounded retention durable state
	// (limits retention, capped age/bytes).
	NatsDurabilityClassDurableBounded NatsDurabilityClass = 2
	// NatsDurabilityClassEphemeral: ephemeral in-memory delivery; loss is safe
	// and callers retry.
	NatsDurabilityClassEphemeral NatsDurabilityClass = 3
)

// NatsOrderingClass mirrors the NatsOrderingClass enum.
type NatsOrderingClass int

const (
	NatsOrderingClassUnspecified NatsOrderingClass = 0
	// NatsOrderingClassPerSubjectFifo: JetStream per-subject FIFO.
	NatsOrderingClassPerSubjectFifo NatsOrderingClass = 1
	// NatsOrderingClassPerAggregateEpoch: total order enforced by one fenced
	// writer epoch per aggregate.
	NatsOrderingClassPerAggregateEpoch NatsOrderingClass = 2
	// NatsOrderingClassUnordered: no ordering guarantee; consumers must
	// tolerate reordering.
	NatsOrderingClassUnordered NatsOrderingClass = 3
)

// NatsCapabilityEntry mirrors the sealed record: one frozen capability
// disposition. Accepted entries carry owner, data class, durability, ordering,
// security boundary, failure mode, observability requirement, and landed
// evidence. Deferred entries carry a revisit trigger; rejected entries carry
// an exclusion rationale.
type NatsCapabilityEntry struct {
	Capability                         NatsCapability
	Disposition                        NatsCapabilityDisposition
	Owner                              NatsCapabilityOwner
	DataClass                          NatsDataClass
	Durability                         NatsDurabilityClass
	Ordering                           NatsOrderingClass
	SecurityBoundary                   string
	FailureMode                        string
	ObservabilityRequirement           string
	RevisitTriggerOrRejectionRationale string
	LandedEvidence                     string
}

// IsWellFormed mirrors the internal rule.
func (e NatsCapabilityEntry) IsWellFormed() bool {
	if e.Capability == NatsCapabilityUnspecified || e.Disposition == NatsCapabilityDispositionUnspecified {
		return false
	}

	if e.Disposition == NatsCapabilityDispositionAccept {
		return e.Owner != NatsCapabilityOwnerUnspecified &&
			e.DataClass != NatsDataClassUnspecified &&
			e.Durability != NatsDurabilityClassUnspecified &&
			e.Ordering != NatsOrderingClassUnspecified &&
			isPresentCapabilityText(e.SecurityBoundary) &&
			isPresentCapabilityText(e.FailureMode) &&
			isPresentCapabilityText(e.ObservabilityRequirement) &&
			isPresentCapabilityText(e.LandedEvidence)
	}

	return isPresentCapabilityText(e.RevisitTriggerOrRejectionRationale)
}

func isPresentCapabilityText(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 512
}

// NatsCapabilityMatrix mirrors the C# static class: the frozen NATS
// feature-adoption matrix. Canonical document:
// docs/contracts/nats-capability-matrix.md. Drift tests bind this table to
// the document and pin every disposition.
var NatsCapabilityMatrix natsCapabilityMatrix

type natsCapabilityMatrix struct{}

var natsCapabilityEntries = createNatsCapabilityEntries()

// Entries mirrors NatsCapabilityMatrix.Entries; treat the slice as read-only.
func (natsCapabilityMatrix) Entries() []NatsCapabilityEntry { return natsCapabilityEntries }

// Find mirrors NatsCapabilityMatrix.Find: the single disposition of one
// capability, or nil when the matrix has none.
func (natsCapabilityMatrix) Find(capability NatsCapability) *NatsCapabilityEntry {
	var found *NatsCapabilityEntry
	for index := range natsCapabilityEntries {
		if natsCapabilityEntries[index].Capability == capability {
			if found != nil {
				// Mirrors SingleOrDefault throwing on more than one match.
				panic("Sequence contains more than one matching element")
			}

			found = &natsCapabilityEntries[index]
		}
	}

	return found
}

// IsComplete mirrors NatsCapabilityMatrix.IsComplete: every capability named
// by the contract has exactly one well-formed disposition.
func (natsCapabilityMatrix) IsComplete() bool {
	return len(NatsCapabilityMatrix.CompletenessViolations()) == 0
}

// CompletenessViolations mirrors NatsCapabilityMatrix.CompletenessViolations.
func (natsCapabilityMatrix) CompletenessViolations() []string {
	violations := []string{}
	seen := map[NatsCapability]struct{}{}
	for _, entry := range natsCapabilityEntries {
		if entry.Capability == NatsCapabilityUnspecified {
			violations = append(violations, "The matrix contains an unspecified capability.")
			continue
		}

		if _, duplicate := seen[entry.Capability]; duplicate {
			violations = append(violations, "The matrix dispositions "+entry.Capability.String()+" more than once.")
		}

		seen[entry.Capability] = struct{}{}
		if !entry.IsWellFormed() {
			violations = append(violations, "The "+entry.Capability.String()+" entry is not well formed.")
		}
	}

	for _, capability := range allNatsCapabilities() {
		if capability == NatsCapabilityUnspecified {
			continue
		}

		if _, present := seen[capability]; !present {
			violations = append(violations, "The matrix does not disposition "+capability.String()+".")
		}
	}

	return violations
}

func allNatsCapabilities() []NatsCapability {
	return []NatsCapability{
		NatsCapabilityCorePubSub,
		NatsCapabilityRequestReply,
		NatsCapabilityServicesAndDiscovery,
		NatsCapabilityQueueGroups,
		NatsCapabilityHeaders,
		NatsCapabilityMessageIds,
		NatsCapabilityJetStreamStreams,
		NatsCapabilityDurableConsumers,
		NatsCapabilityAcknowledgement,
		NatsCapabilityRedeliveryAndBackoff,
		NatsCapabilityFlowControl,
		NatsCapabilityKeyValueCasAndWatch,
		NatsCapabilityObjectStore,
		NatsCapabilityAccounts,
		NatsCapabilityJwts,
		NatsCapabilityNKeys,
		NatsCapabilityMtls,
		NatsCapabilityImportsAndExports,
		NatsCapabilityGateways,
		NatsCapabilityAdvisories,
		NatsCapabilitySystemMonitoring,
		NatsCapabilitySnapshots,
		NatsCapabilityRollingCompatibility,
	}
}

func acceptedNatsCapability(
	capability NatsCapability,
	owner NatsCapabilityOwner,
	dataClass NatsDataClass,
	durability NatsDurabilityClass,
	ordering NatsOrderingClass,
	securityBoundary string,
	failureMode string,
	observability string,
	landedEvidence string,
) NatsCapabilityEntry {
	return NatsCapabilityEntry{
		Capability:               capability,
		Disposition:              NatsCapabilityDispositionAccept,
		Owner:                    owner,
		DataClass:                dataClass,
		Durability:               durability,
		Ordering:                 ordering,
		SecurityBoundary:         securityBoundary,
		FailureMode:              failureMode,
		ObservabilityRequirement: observability,
		LandedEvidence:           landedEvidence,
	}
}

func deferredNatsCapability(
	capability NatsCapability,
	owner NatsCapabilityOwner,
	revisitTrigger string,
) NatsCapabilityEntry {
	return NatsCapabilityEntry{
		Capability:                         capability,
		Disposition:                        NatsCapabilityDispositionDefer,
		Owner:                              owner,
		RevisitTriggerOrRejectionRationale: revisitTrigger,
	}
}

func rejectedNatsCapability(
	capability NatsCapability,
	owner NatsCapabilityOwner,
	rationale string,
) NatsCapabilityEntry {
	return NatsCapabilityEntry{
		Capability:                         capability,
		Disposition:                        NatsCapabilityDispositionReject,
		Owner:                              owner,
		RevisitTriggerOrRejectionRationale: rationale,
	}
}

func createNatsCapabilityEntries() []NatsCapabilityEntry {
	return []NatsCapabilityEntry{
		acceptedNatsCapability(
			NatsCapabilityCorePubSub,
			NatsCapabilityOwnerRegionalControlRuntime,
			NatsDataClassOperationalTelemetry,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Control account subject permissions; publish only taxonomy subjects; no product-plane subjects.",
			"Lost publications are safe: hints, heartbeats, and fanout are advisory and consumers reconcile from durable state.",
			"Drop/latency counters per subject namespace; no alert may depend on a lossy hint.",
			"NatsRuntime service endpoints and request/reply use core pub/sub; RegionalRuntimeMembership heartbeats go through the bounded ORCH_RUNTIME KV bucket."),
		acceptedNatsCapability(
			NatsCapabilityRequestReply,
			NatsCapabilityOwnerRegionalControlRuntime,
			NatsDataClassOperatorQuery,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Typed endpoints only; callers hold scoped subscribe permissions plus _INBOX; no-responder surfaces as an error, never silence.",
			"Timeout/no-responder is caller-visible; callers retry with the same idempotency key.",
			"Request latency and no-responder rate per endpoint; bounded timeouts are pinned by the contract.",
			"NatsRuntime health/status/members endpoints; GlobalCellDirectoryServiceRuntime serves "+
				NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()+"."),
		acceptedNatsCapability(
			NatsCapabilityServicesAndDiscovery,
			NatsCapabilityOwnerRegionalControlRuntime,
			NatsDataClassOperatorQuery,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"$SRV subjects stay account-scoped; only declared endpoints are registered; discovery complements workload DNS/LB discovery.",
			"Missing service or endpoint metadata fails the caller closed (NatsRuntime verifies discovery at startup).",
			"Service/endpoint presence, queue-group membership, and per-endpoint latency/error statistics.",
			"NatsRuntime registers terrascale_orchestrator_<cell> with health/status/members endpoints and verifies $SRV.INFO readback."),
		acceptedNatsCapability(
			NatsCapabilityQueueGroups,
			NatsCapabilityOwnerRegionalControlRuntime,
			NatsDataClassControlCommand,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Queue groups may distribute only equivalent-worker work; the single authoritative writer is always chosen by a KV CAS lease, never by a queue group.",
			"Any group member may answer; answers must be equivalent; authoritative writes are fenced by epoch checks.",
			"Group size, member churn, and duplicate-answer rejections per group.",
			"NatsTopology.ServiceQueueGroup and OperationJournalWriterQueueGroup; DirectDelivery/DirectDeliveryCoordinators fence writes by lease epoch."),
		acceptedNatsCapability(
			NatsCapabilityHeaders,
			NatsCapabilityOwnerMessagingContracts,
			NatsDataClassControlCommand,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Headers carry only contract-defined TS-* metadata; never secrets, credentials, or payload body.",
			"Missing or malformed required headers fail closed at the wire codec before dispatch.",
			"Header validation rejection counts by header name.",
			"TS-* envelope headers in NativeGitOpsCellWireCodec, DirectDeliveryCommandWire, and NatsRuntime startup verification."),
		acceptedNatsCapability(
			NatsCapabilityMessageIds,
			NatsCapabilityOwnerMessagingContracts,
			NatsDataClassControlCommand,
			NatsDurabilityClassDurableBounded,
			NatsOrderingClassUnordered,
			"Transport-level suppression only, bounded by each stream's duplicate window; never an exactly-once claim.",
			"A duplicate outside the window is admitted; operation-level idempotency keys remain the authority.",
			"Duplicate-suppression counters next to idempotency-replay counters so the two layers stay distinguishable.",
			"MsgId on every JetStream publish (ForgejoEventPublisher, NativeGitOps publishers, NatsRuntime startup) with 2m/24h duplicate windows in NatsTopology/GlobalNatsTopology."),
		acceptedNatsCapability(
			NatsCapabilityJetStreamStreams,
			NatsCapabilityOwnerInfrastructureBootstrap,
			NatsDataClassAuthoritativeState,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Streams are infrastructure-provisioned; controllers validate exact configuration and never create/update streams at runtime.",
			"Controller start fails closed on any stream configuration mismatch; limits retention bounds age and bytes.",
			"Stream depth, age, bytes, discarded counts, and replica health per critical stream.",
			"NatsTopology Streams (CELL_SPEC, CELL_OPERATIONS, CELL_EVENTS) and GlobalNatsTopology Streams (GLOBAL_SPEC, GLOBAL_CI) validated by NatsOperationJournalStore."),
		acceptedNatsCapability(
			NatsCapabilityDurableConsumers,
			NatsCapabilityOwnerInfrastructureBootstrap,
			NatsDataClassControlCommand,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Consumers are provisioned with closed profiles; controllers may only create/open/ack their named consumer.",
			"A missing or mismatched consumer fails controller check/run closed rather than being created at runtime.",
			"Consumer lag, pending, redelivery counts, and exact-profile validation failures.",
			"StartupConsumer, CellSpecConsumer, CiConsumer, CiRuntimeProofConsumer, CiJobConsumer profiles with exact-match startup validation (NatsRuntime.OpenExactConsumerAsync)."),
		acceptedNatsCapability(
			NatsCapabilityAcknowledgement,
			NatsCapabilityOwnerDeliveryContracts,
			NatsDataClassControlCommand,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Explicit-ack consumers only; a worker acknowledges only after the durable effect is journaled or an idempotent replay is proven; long work sends progress.",
			"A crash before ack means redelivery; the idempotency key makes the replay safe; authority loss after acceptance withholds the ack.",
			"Ack latency after durable effect, progress-heartbeat age, and authority-lost-after-acceptance counts.",
			"NativeGitOpsCellInbox double-acks after journal acceptance; RepositoryCiJobNatsConsumer sends AckProgressAsync; ForgejoCiEventConsumer terminally acks deterministic conflicts."),
		acceptedNatsCapability(
			NatsCapabilityRedeliveryAndBackoff,
			NatsCapabilityOwnerDeliveryContracts,
			NatsDataClassControlCommand,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Bounded by the consumer profile: at most 5 deliveries with a 1s/5s/15s/30s backoff ladder; ack wait is derived from the first backoff interval.",
			"Exhaustion stops redelivery only with terminal evidence; no message may disappear silently.",
			"Redelivery histograms, exhaustion counts, and final-delivery warnings by subject.",
			"Consumer profiles in NatsTopology/GlobalNatsTopology; final-delivery warning and Nak-with-delay in ForgejoCiEventConsumer."),
		acceptedNatsCapability(
			NatsCapabilityFlowControl,
			NatsCapabilityOwnerInfrastructureBootstrap,
			NatsDataClassOperationalTelemetry,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"$JS.FC grants are granted only to identities that own the consuming stream/bucket; the global authority never receives durable/pull/ack shapes for watch-only buckets.",
			"A stalled consumer that stops answering flow control is marked slow and surfaced, never silently dropped.",
			"Slow-consumer advisories and outstanding flow-control latency per consumer.",
			"Explicit $JS.FC permission grants in GlobalNatsPermissions; the GlobalNatsAccessContract account model grants them only to the owning stream or bucket identity."),
		acceptedNatsCapability(
			NatsCapabilityKeyValueCasAndWatch,
			NatsCapabilityOwnerRegionalControlRuntime,
			NatsDataClassCoordinationRecord,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerAggregateEpoch,
			"KV provides leases, epochs, and small coordination records only; the operation stream stays the durable explanation/history; journal KV stores are denied to controllers.",
			"CAS conflict is a normal outcome: the loser re-observes and retries; ambiguity holds instead of creating a competing writer.",
			"CAS conflict rate, lease age, watch lag, and journal-store denial attempts.",
			"RegionalAuthorityCoordinator CAS leases/epochs; GlobalCellDirectoryRuntime watches cell.>; GlobalNatsPermissions grants inbox-delivered ephemeral watch consumers only."),
		acceptedNatsCapability(
			NatsCapabilityObjectStore,
			NatsCapabilityOwnerStorageAndSnapshots,
			NatsDataClassEvidenceArtifact,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Small signed bundles, protocol packages, and evidence only; never the build registry or backup system; secrets never enter objects.",
			"Missing or byte-unequal protocol package fails startup closed; bundle digests are content-addressed.",
			"Object counts/bytes per bucket and integrity-check failures.",
			"CELL_BUNDLES, GLOBAL_BUNDLES, CI_RUNNER_BUNDLES, ORCH_PROTOCOL_PACKAGE with byte-exact verification in NatsRuntime."),
		acceptedNatsCapability(
			NatsCapabilityAccounts,
			NatsCapabilityOwnerSecurityAndIdentity,
			NatsDataClassCoordinationRecord,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassUnordered,
			"Hard namespaces: system, global authority, global directory, regional control, CI, audit/export, operator, product, test; capability determines the account, never caller-supplied credentials.",
			"An identity in the wrong account simply lacks permissions; cross-plane authorization is structurally impossible.",
			"Account-scoped auth failures and permission denials feed security alerts.",
			"GlobalNatsAccountNames and GlobalNatsAccessContract account split; distinct control/product planes in the NatsSubjectTaxonomy account model."),
		deferredNatsCapability(
			NatsCapabilityJwts,
			NatsCapabilityOwnerSecurityAndIdentity,
			"Operator/account/user JWT issuance and the JWT/NKey administration toolchain are unselected (phase1-nats-l0c-foundation outcome); adopt only after the L0C lane pins the toolchain and rotating account-signing-key procedure."),
		acceptedNatsCapability(
			NatsCapabilityNKeys,
			NatsCapabilityOwnerSecurityAndIdentity,
			NatsDataClassCoordinationRecord,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"NKey authentication for controllers, writer, infrastructure, directory, and operator identities; every command rejects every NATS credential family it does not own before file resolution.",
			"Anonymous connections must be denied (startup verifies); a missing NKey fails closed.",
			"Authentication failure counts by identity family; anonymous-denial verification at startup.",
			"OrchestratorOptions.NatsNKeyFile, NatsRuntime.VerifyAnonymousDeniedAsync, CiRunnerNatsCredentialIssuer, GlobalNatsAccessContract identity separation."),
		acceptedNatsCapability(
			NatsCapabilityMtls,
			NatsCapabilityOwnerSecurityAndIdentity,
			NatsDataClassCoordinationRecord,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"mTLS proves machine/workload transport identity for clients, routes, and gateways; it never replaces NKey/JWT authorization; global endpoints require absolute tls:// URLs.",
			"TLS failure is a startup/connection failure; no plaintext fallback path exists.",
			"Certificate expiry freshness, handshake failures, and per-endpoint TLS mode.",
			"NatsRuntime NatsTlsOpts Require mode; NatsTlsFiles; infrastructure mTLS required by NatsOperationJournalProvisioner."),
		acceptedNatsCapability(
			NatsCapabilityImportsAndExports,
			NatsCapabilityOwnerSecurityAndIdentity,
			NatsDataClassOperatorQuery,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Least-privilege service import/export across accounts within one cluster only (the directory query service); cross-cluster/region stream or service import/export is rejected — the gateway mesh is the only cross-cluster path and no stream may span regions.",
			"A missing import/export makes the cross-account call fail closed with no-responder.",
			"Import/export presence checks per account pair; any undeclared cross-account subject is a security alert.",
			"GlobalNatsServiceImport/Export for "+NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()+
				" in GlobalNatsAccessContract; no cross-region stream exists in either topology."),
		acceptedNatsCapability(
			NatsCapabilityGateways,
			NatsCapabilityOwnerInfrastructureBootstrap,
			NatsDataClassCoordinationRecord,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Launch topology is a full mTLS gateway mesh (not hub-and-spoke) inside one offline control-plane operator domain; local streams and actions stay regional; explicit known clusters with constrained account traffic.",
			"Gateway loss isolates regions; regional control stays autonomous and pre-authorized regional work continues.",
			"Gateway link state, latency, and isolated-region duration; expansion beyond the mesh envelope requires a new owner decision.",
			"Gateway membership validated by MessagingPolicyEngine plane policies (docs/architecture/orchestrator.md launch-control topology); no production gateway adapter is deployed yet."),
		acceptedNatsCapability(
			NatsCapabilityAdvisories,
			NatsCapabilityOwnerObservability,
			NatsDataClassOperationalTelemetry,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"Authenticated $SYS subjects only for remote status; advisories are read, never acted on as authority.",
			"A missed advisory degrades monitoring only; it never changes control decisions.",
			"Slow-consumer, quorum/leader-change, and auth-failure advisories are alert inputs.",
			"docs/architecture/orchestrator.md system-account monitoring contract; observability adapters consume advisories (design-binding; see unresolved measurements)."),
		acceptedNatsCapability(
			NatsCapabilitySystemMonitoring,
			NatsCapabilityOwnerObservability,
			NatsDataClassOperationalTelemetry,
			NatsDurabilityClassEphemeral,
			NatsOrderingClassUnordered,
			"HTTP monitoring binds to loopback or an isolated host-management address only, scraped locally; remote status goes through authenticated $SYS subjects; the monitoring port has no application auth boundary and is never internet- or workload-exposed.",
			"Monitoring loss blinds operators without affecting control correctness.",
			"Server/account/connection/consumer health and quorum state feed Grafana and alerts.",
			"docs/architecture/orchestrator.md NATS monitoring rules; dev-lab and production monitoring adapters tracked as an unresolved measurement."),
		acceptedNatsCapability(
			NatsCapabilitySnapshots,
			NatsCapabilityOwnerStorageAndSnapshots,
			NatsDataClassEvidenceArtifact,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerSubjectFifo,
			"Snapshots carry a signed stream position and schema version; restore replays from that position and refuses an older snapshot over a newer accepted epoch; journal KV stores deny snapshot/restore APIs to controllers.",
			"Restore never regresses accepted epochs; product data never enters control backups and control state never enters product backups.",
			"Snapshot freshness, restore attempts, and refusal counts by reason.",
			"SignedSnapshot/SnapshotRestore pure core; journal stores provisioned by NatsOperationJournalProvisioner with snapshot/restore APIs denied to controllers; stream/KV snapshot-restore exercise is an L0C gate."),
		acceptedNatsCapability(
			NatsCapabilityRollingCompatibility,
			NatsCapabilityOwnerMessagingContracts,
			NatsDataClassControlCommand,
			NatsDurabilityClassReplicatedDurableFile,
			NatsOrderingClassPerAggregateEpoch,
			"N and N-1 interoperate for commands, snapshots, schema reads, and leadership transfer; upgrades proceed one plane and one failure domain at a time and cannot remove the last candidate or drop either plane below its disruption budget.",
			"An upgrade cannot proceed without current and rollback artifacts in the regional survival bundle; N-1 nodes fail closed on N-major documents.",
			"Per-version interop matrix results and rollback outcomes per failure domain.",
			"MessagingPolicyEngine.DecideCompatibility (Commands, Snapshots, SchemaReads, LeadershipTransfer); forward-only schema migration discipline in RepositoryCiJobJournal."),
	}
}
