// Port of src/TerraScale.Orchestrator/Messaging/NatsMonitoringPermissions.cs.
package control

import (
	"fmt"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsMonitoringSubjects mirrors the C# static class: the exact, minimum $SYS
// read subjects the monitoring contract may consume.
var NatsMonitoringSubjects natsMonitoringSubjects

type natsMonitoringSubjects struct{}

const (
	// NatsMonitoringSubjectsConnections: bounded connection census.
	NatsMonitoringSubjectsConnections = "$SYS.REQ.SERVER.PING.CONNZ"
	// NatsMonitoringSubjectsRoutes: bounded route census.
	NatsMonitoringSubjectsRoutes = "$SYS.REQ.SERVER.PING.ROUTEZ"
	// NatsMonitoringSubjectsGateways: outbound gateway link state — the
	// mesh-partition signal.
	NatsMonitoringSubjectsGateways = "$SYS.REQ.SERVER.PING.GATEWAYZ"
	// NatsMonitoringSubjectsServer: server process and JetStream resource use.
	NatsMonitoringSubjectsServer = "$SYS.REQ.SERVER.PING.VARZ"
	// NatsMonitoringSubjectsJetStream: JetStream domains, streams, consumers,
	// memory, and storage totals.
	NatsMonitoringSubjectsJetStream = "$SYS.REQ.SERVER.PING.JSZ"
	// NatsMonitoringSubjectsAccounts: account census.
	NatsMonitoringSubjectsAccounts = "$SYS.REQ.SERVER.PING.ACCOUNTZ"
	// NatsMonitoringSubjectsAccountAdvisories: account advisories.
	NatsMonitoringSubjectsAccountAdvisories = "$SYS.ACCOUNT.*.ADVISORY.>"
	// NatsMonitoringSubjectsJetStreamAdvisories: JetStream advisories.
	NatsMonitoringSubjectsJetStreamAdvisories = "$SYS.JETSTREAM.ADVISORY.>"
)

// Requests mirrors the C# Requests: every request-reply monitoring subject, in
// stable order.
func (natsMonitoringSubjects) Requests() []string {
	return []string{
		NatsMonitoringSubjectsAccounts,
		NatsMonitoringSubjectsConnections,
		NatsMonitoringSubjectsGateways,
		NatsMonitoringSubjectsJetStream,
		NatsMonitoringSubjectsRoutes,
		NatsMonitoringSubjectsServer,
	}
}

// AdvisorySubscriptions mirrors the C# AdvisorySubscriptions.
func (natsMonitoringSubjects) AdvisorySubscriptions() []string {
	return []string{
		NatsMonitoringSubjectsAccountAdvisories,
		NatsMonitoringSubjectsJetStreamAdvisories,
	}
}

// IsMonitoringSubject mirrors the C# IsMonitoringSubject.
func (natsMonitoringSubjects) IsMonitoringSubject(subject string) bool {
	for _, candidate := range NatsMonitoringSubjects.Requests() {
		if candidate == subject {
			return true
		}
	}

	for _, candidate := range NatsMonitoringSubjects.AdvisorySubscriptions() {
		if candidate == subject {
			return true
		}
	}

	return false
}

// IsAdvisoryDeliverySubject mirrors the C# IsAdvisoryDeliverySubject: true
// when a subject is covered by one of the two advisory subscription
// wildcards.
func (natsMonitoringSubjects) IsAdvisoryDeliverySubject(subject string) bool {
	if strings.HasPrefix(subject, "$SYS.ACCOUNT.") {
		rest := subject[len("$SYS.ACCOUNT."):]
		index := strings.Index(rest, ".ADVISORY.")
		// Exactly one bounded account token between the root and the advisory
		// segment, and at least one subject token after it.
		return index > 0 &&
			!strings.Contains(rest[:index], ".") &&
			!strings.Contains(rest[:index], "*") &&
			!strings.Contains(rest[:index], ">") &&
			len(rest[index+len(".ADVISORY."):]) > 0
	}

	if strings.HasPrefix(subject, "$SYS.JETSTREAM.ADVISORY.") {
		return len(subject[len("$SYS.JETSTREAM.ADVISORY."):]) > 0
	}

	return false
}

// NatsMonitoringPermissionPlan mirrors the C# record: the read-only NATS
// permission plan for the monitoring identity.
type NatsMonitoringPermissionPlan struct {
	Publish   []string
	Subscribe []string
}

// NewNatsMonitoringPermissionPlan mirrors the C# constructor: the plan is the
// single source the account model grants from, so it validates itself.
func NewNatsMonitoringPermissionPlan(publish, subscribe []string) (*NatsMonitoringPermissionPlan, error) {
	orderedPublish := append([]string(nil), publish...)
	sort.Strings(orderedPublish)
	orderedSubscribe := append([]string(nil), subscribe...)
	sort.Strings(orderedSubscribe)

	requests := NatsMonitoringSubjects.Requests()
	advisories := NatsMonitoringSubjects.AdvisorySubscriptions()

	for _, subject := range orderedPublish {
		allowed := false
		for _, candidate := range requests {
			if candidate == subject {
				allowed = true
				break
			}
		}

		if !allowed {
			return nil, fmt.Errorf(
				"The monitoring permission plan may not publish '%s': only the exact read-only $SYS request subjects are grantable. (Parameter 'publish')",
				subject)
		}
	}

	for _, subject := range orderedSubscribe {
		allowed := subject == "_INBOX.>"
		for _, candidate := range advisories {
			if candidate == subject {
				allowed = true
				break
			}
		}

		if !allowed {
			return nil, fmt.Errorf(
				"The monitoring permission plan may not subscribe '%s': only the advisory subscriptions and the inbox are grantable. (Parameter 'subscribe')",
				subject)
		}
	}

	return &NatsMonitoringPermissionPlan{Publish: orderedPublish, Subscribe: orderedSubscribe}, nil
}

// NatsMonitoringPermissions mirrors the C# static class.
var NatsMonitoringPermissions natsMonitoringPermissions

type natsMonitoringPermissions struct{}

// Create mirrors NatsMonitoringPermissions.Create: publish only the read-only
// system-service request subjects, subscribe only to advisories and its own
// inbox.
func (natsMonitoringPermissions) Create() (*NatsMonitoringPermissionPlan, error) {
	subscribe := append(NatsMonitoringSubjects.AdvisorySubscriptions(), "_INBOX.>")
	return NewNatsMonitoringPermissionPlan(NatsMonitoringSubjects.Requests(), subscribe)
}

// NatsMonitoringPermissionsForbidden mirrors the C# nested Forbidden class:
// subject classes the monitoring plan must never be able to touch.
var NatsMonitoringPermissionsForbidden natsMonitoringPermissionsForbidden

type natsMonitoringPermissionsForbidden struct{}

// ControlPublish mirrors Forbidden.ControlPublish: control work — regional
// command and internal journal subjects for every cell.
func (natsMonitoringPermissionsForbidden) ControlPublish(cell string) []string {
	direct, _ := protocol.NatsSubjectTaxonomy.DirectDeliverySubject(cell)
	create, _ := protocol.NatsSubjectTaxonomy.OperationJournalCreateSubject(cell)
	update, _ := protocol.NatsSubjectTaxonomy.OperationJournalUpdateSubject(cell)
	desired, _ := protocol.NatsSubjectTaxonomy.RegionalFamilyPattern(
		cell, protocol.NatsSubjectTaxonomy.DesiredFamilySegment())
	observation, _ := protocol.NatsSubjectTaxonomy.RegionalFamilyPattern(
		cell, protocol.NatsSubjectTaxonomy.ObservationFamilySegment())

	return []string{direct, create, update, desired, observation}
}

// GlobalControlPublish mirrors Forbidden.GlobalControlPublish.
func (natsMonitoringPermissionsForbidden) GlobalControlPublish() []string {
	return []string{
		protocol.NatsSubjectTaxonomy.GlobalCellSpecPrefix() + ".>",
		protocol.NatsSubjectTaxonomy.CiJobSubjectPrefix() + ".>",
		protocol.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(),
	}
}

// JetStreamMutation mirrors Forbidden.JetStreamMutation.
func (natsMonitoringPermissionsForbidden) JetStreamMutation() []string {
	return []string{
		"$JS.API.STREAM.CREATE.>",
		"$JS.API.STREAM.UPDATE.>",
		"$JS.API.STREAM.DELETE.>",
		"$JS.API.STREAM.PURGE.>",
		"$JS.API.CONSUMER.CREATE.>",
		"$JS.API.CONSUMER.DELETE.>",
		"$JS.API.CONSUMER.DURABLE.CREATE.>",
		"$JS.ACK.>",
		"$JS.FC.>",
	}
}

// SecretAndJournalReads mirrors Forbidden.SecretAndJournalReads.
func (natsMonitoringPermissionsForbidden) SecretAndJournalReads() []string {
	return []string{
		"$KV.ORCH_OPERATIONS.>",
		"$KV.ORCH_OPERATION_PROOFS.>",
		"$KV.ORCH_RUNTIME.>",
		"$KV.ORCH_DELIVERY.>",
		"$O.CELL_BUNDLES.>",
		"$O.ORCH_PROTOCOL_PACKAGE.>",
	}
}

// ProductPlane mirrors Forbidden.ProductPlane.
func (natsMonitoringPermissionsForbidden) ProductPlane() []string {
	return []string{
		"product.>",
		protocol.NatsSubjectTaxonomy.Root() + "." +
			protocol.NatsSubjectTaxonomy.RegionalAuditPrefixSegment() + ".>",
		protocol.NatsSubjectTaxonomy.Root() + "." +
			protocol.NatsSubjectTaxonomy.RegionalAgentPrefixSegment() + ".>",
	}
}

// NatsMonitoringPermissionsGrants mirrors the C# Grants: true when a granted
// subject pattern can carry the candidate subject. Patterns support a
// single-token * and a trailing > (which must be the last token).
func NatsMonitoringPermissionsGrants(granted []string, subject string) bool {
	candidate := strings.Split(subject, ".")
	for _, pattern := range granted {
		if pattern == subject {
			return true
		}

		tokens := strings.Split(pattern, ".")
		trailing := len(tokens) > 0 && tokens[len(tokens)-1] == ">"
		bounded := len(tokens)
		if trailing {
			bounded--
		}

		if bounded == 0 {
			continue
		}

		if !trailing && bounded != len(candidate) {
			continue
		}

		if trailing && len(candidate) < bounded {
			continue
		}

		matched := true
		for index := 0; index < bounded; index++ {
			token := tokens[index]
			if token == "*" {
				continue
			}

			if token == ">" {
				matched = false
				break
			}

			if token != candidate[index] {
				matched = false
				break
			}
		}

		if matched {
			return true
		}
	}

	return false
}
