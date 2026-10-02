package protocol

import "strings"

// Subject roots. Every NATS subject the orchestrator publishes, subscribes to,
// grants, or stores is built from one of these roots in this package, so the
// interregion leafnode export and import lists can be derived from the same
// builders as the regional permissions. A test fails if another package spells
// a "ts." subject literal.
const (
	// ControlRoot prefixes the ordered, durable JetStream control logs. Its
	// scope token is a regional cell or GlobalScope.
	ControlRoot = "ts.control"
	// BrokerRoot prefixes ephemeral regional broker ticket and fence RPCs.
	BrokerRoot = "ts.broker"
	// GlobalStateRoot prefixes records in the home region's global control
	// stream. It is disjoint from ControlRoot so the global stream never
	// overlaps the regional TS_CONTROL_LOG subjects.
	GlobalStateRoot = "ts.global.v1"
	// TemplateSubject is the NATS JWT user-scope template for the
	// authenticated user's public key.
	TemplateSubject = "{{subject()}}"
	// InterRegionRoot prefixes subjects that exist only to carry the global
	// stream mirror across an interregion leafnode.
	InterRegionRoot = "ts.interregion.v1"
	// GlobalControlStream is the home region's global state stream and the
	// name of its read-only mirror in every other region.
	GlobalControlStream = "TS_GLOBAL_CONTROL"
	// JSLocalAPIPrefix is the account-local JetStream API prefix.
	JSLocalAPIPrefix = "$JS.API"
)

// JSConsumerResetSubject is the reset API subject of one named consumer under
// an API prefix. It is the only JetStream API verb a durable-sourced mirror
// sends: it moves that one consumer to its ack floor or to a requested
// sequence (forward too) and cannot change where the consumer delivers. Any
// empty part yields "", which NATS rejects.
func JSConsumerResetSubject(apiPrefix, stream, consumer string) string {
	if apiPrefix == "" || stream == "" || consumer == "" {
		return ""
	}
	return apiPrefix + ".CONSUMER.RESET." + stream + "." + consumer
}

// JSFlowControlSubject matches the flow-control replies of one consumer on
// stream; with the flow-control ack policy these replies are also its acks.
func JSFlowControlSubject(stream, consumer string) string {
	if stream == "" || consumer == "" {
		return ""
	}
	return "$JS.FC." + stream + "." + consumer + ".*"
}

// InterRegionJSAPIPrefix is the external JetStream API prefix under which a
// home region exposes the reset verb of its global mirror consumers to peers
// over a leafnode. Nothing else is reachable beneath it.
func InterRegionJSAPIPrefix(home string) string {
	token, err := RegionToken(home)
	if err != nil || token == GlobalScope {
		return ""
	}
	return InterRegionRoot + "." + token + ".jsapi"
}

// InterRegionGlobalDeliverSubject is the fixed delivery subject of cell's
// durable mirror consumer on the home region's global stream. The home region
// sets it when it creates the consumer; a peer can never choose it.
func InterRegionGlobalDeliverSubject(cell string) string {
	token, err := RegionToken(cell)
	if err != nil || token == GlobalScope {
		return ""
	}
	return InterRegionRoot + "." + token + ".global"
}

// GlobalMirrorConsumer is the durable consumer on the home region's global
// stream that feeds cell's read-only mirror.
func GlobalMirrorConsumer(cell string) string {
	token, err := RegionToken(cell)
	if err != nil || token == GlobalScope {
		return ""
	}
	return "global-mirror-" + token
}

// Well-known regional verbs below the regional root.
const (
	VerbHostRegister          = "host.register"
	VerbBackupOperation       = "backup.operation"
	VerbBrokerClaimApply      = "broker.claim.apply"
	VerbPlacementApply        = "placement.apply"
	VerbManagedUpdatePrepare  = "managed-update.prepare"
	VerbMaterialPrepare       = "material.prepare"
	VerbDeliveryIntent        = "delivery.intent"
	VerbDeliveryArtifactAdmit = "delivery.artifact.admit"
	VerbRegionHealth          = "region.health"
)

// Regional joins a regional root and dot-separated tokens. Each token may be a
// lowercase protocol token, an NKey, a hash, a NATS wildcard ("*", or ">" as
// the final token) or the JWT user template. An invalid cell or token yields
// the empty string, which NATS rejects as a subject and as a permission, so
// a malformed configuration fails closed instead of widening a grant. Callers
// pass cells already validated by their configuration.
func Regional(cell string, tokens ...string) string {
	root, err := RegionalRoot(cell)
	if err != nil {
		return ""
	}
	return joinSubject(root, tokens)
}

// Control joins a control-log scope (a cell or GlobalScope) and tokens.
func Control(scope string, tokens ...string) string {
	token, err := RegionToken(scope)
	if err != nil {
		return ""
	}
	return joinSubject(ControlRoot+"."+token, tokens)
}

// ControlStreamSubject is the single subject filter of TS_CONTROL_LOG.
func ControlStreamSubject() string { return ControlRoot + ".*.>" }

// Broker joins a regional broker RPC root and tokens.
func Broker(cell string, tokens ...string) string {
	token, err := RegionToken(cell)
	if err != nil || token == GlobalScope {
		return ""
	}
	return joinSubject(BrokerRoot+"."+token, tokens)
}

// GlobalState joins the global control stream root and tokens.
func GlobalState(tokens ...string) string { return joinSubject(GlobalStateRoot, tokens) }

// GlobalStateStreamSubject is the single subject filter of TS_GLOBAL_CONTROL.
func GlobalStateStreamSubject() string { return GlobalStateRoot + ".>" }

// GlobalControlRequest is the global-authority mutation request subject.
func GlobalControlRequest(action string) string {
	subject, err := GlobalControlSubject(action)
	if err != nil {
		return ""
	}
	return subject
}

// HostRegisterSubject is the controller host registration request subject.
func HostRegisterSubject(cell string) string { return Regional(cell, VerbHostRegister) }

// BackupOperationSubject is the signed backup operation request subject.
func BackupOperationSubject(cell string) string { return Regional(cell, VerbBackupOperation) }

// BrokerClaimApplySubject is the signed broker account claim request subject.
func BrokerClaimApplySubject(cell string) string { return Regional(cell, VerbBrokerClaimApply) }

// PlacementApplySubject is the managed placement admission request subject.
func PlacementApplySubject(cell string) string { return Regional(cell, VerbPlacementApply) }

// ManagedUpdatePrepareSubject is the managed update preparation subject.
func ManagedUpdatePrepareSubject(cell string) string {
	return Regional(cell, VerbManagedUpdatePrepare)
}

// MaterialPrepareSubject is the operator material preparation subject.
func MaterialPrepareSubject(cell string) string { return Regional(cell, VerbMaterialPrepare) }

// TerminalSubject is a terminal workload request; action may be ">".
func TerminalSubject(cell, action string) string { return Regional(cell, "terminal", action) }

// DeliveryIntentSubject is the regional delivery work-queue subject.
func DeliveryIntentSubject(cell string) string { return Regional(cell, VerbDeliveryIntent) }

// DeliveryArtifactAdmitSubject is the artifact claim admission subject.
func DeliveryArtifactAdmitSubject(cell string) string {
	return Regional(cell, VerbDeliveryArtifactAdmit)
}

// RegionHealthSubject is the signed regional heartbeat exported to peers.
func RegionHealthSubject(cell string) string { return Regional(cell, VerbRegionHealth) }

// ObservabilityGrant is the subscribe grant covering every read-only member
// telemetry leaf (ObservabilitySubject) of one regional cell.
func ObservabilityGrant(cell string) string { return Regional(cell, "obs", ">") }

// InboxPrefix is a user's private reply inbox prefix without the trailing ">".
func InboxPrefix(cell, userKey string) string { return Regional(cell, "inbox", userKey) }

// InboxGrant is the subscription grant for a user's private reply inbox.
func InboxGrant(cell, userKey string) string { return Regional(cell, "inbox", userKey, ">") }

// AgentObservation is a host observation subject. agent is the user NKey, a
// wildcard, or the JWT user template; observation may be a wildcard.
func AgentObservation(cell, agent, observation string) string {
	return Regional(cell, "agent", agent, "observation", observation)
}

func joinSubject(root string, tokens []string) string {
	if len(tokens) == 0 {
		return root
	}
	var builder strings.Builder
	builder.WriteString(root)
	for index, token := range tokens {
		for part := range strings.SplitSeq(token, ".") {
			if !validFamilyToken(part, index == len(tokens)-1) {
				return ""
			}
		}
		builder.WriteByte('.')
		builder.WriteString(token)
	}
	result := builder.String()
	// ">" may only terminate the whole subject.
	if index := strings.Index(result, ">"); index >= 0 && index != len(result)-1 {
		return ""
	}
	return result
}

func validFamilyToken(token string, last bool) bool {
	switch token {
	case "*", TemplateSubject:
		return true
	case ">":
		return last
	}
	if token == "" || len(token) > 128 {
		return false
	}
	for _, character := range token {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', character == '-', character == '_':
		default:
			return false
		}
	}
	return true
}
