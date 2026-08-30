// Port of src/TerraScale.Orchestrator/Messaging/NatsTopology.cs.
package control

import (
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsTopology mirrors the C# record: the regional controller's JetStream
// topology for one cell.
type NatsTopology struct {
	Cell     string
	Replicas int
	Instance string
}

// NewNatsTopology mirrors the C# record constructor (Instance defaults to
// "local").
func NewNatsTopology(cell string, replicas int, instance string) *NatsTopology {
	if instance == "" {
		instance = "local"
	}

	return &NatsTopology{Cell: cell, Replicas: replicas, Instance: instance}
}

func (t *NatsTopology) HealthSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.ControllerHealthSubject(t.Cell)
}

func (t *NatsTopology) InstanceHealthSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.ControllerInstanceHealthSubject(t.Cell, t.Instance)
}

func (t *NatsTopology) StatusSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.ControllerStatusSubject(t.Cell)
}

func (t *NatsTopology) MembersSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.ControllerMembersSubject(t.Cell)
}

// StatsSubject is the read-only service statistics endpoint subject: version,
// schema, health, request/error/latency aggregates.
func (t *NatsTopology) StatsSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.ControllerStatsSubject(t.Cell)
}

func (t *NatsTopology) DirectDeliverySubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.DirectDeliverySubject(t.Cell)
}

func (t *NatsTopology) OperationJournalCreateSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.OperationJournalCreateSubject(t.Cell)
}

func (t *NatsTopology) OperationJournalUpdateSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.OperationJournalUpdateSubject(t.Cell)
}

func (t *NatsTopology) OperationJournalReplySubject(callerIdentity, nonce string) (string, error) {
	return protocol.NatsSubjectTaxonomy.OperationJournalReplySubject(t.Cell, callerIdentity, nonce)
}

func (t *NatsTopology) OperationJournalWriterQueueGroup() string {
	return "terrascale_orchestrator_journal_writer_" + t.Cell
}

func (t *NatsTopology) CellSpecSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.CellSpecSubject(t.Cell)
}

func (t *NatsTopology) StartupSubject() (string, error) {
	return protocol.NatsSubjectTaxonomy.RuntimeStartupSubject(t.Cell, t.Instance)
}

func (t *NatsTopology) ProtocolObject() string { return "orchestrator-protocol-v2" }

func (t *NatsTopology) ServiceName() string { return "terrascale_orchestrator_" + t.Cell }

func (t *NatsTopology) ServiceQueueGroup() string { return "orchestrator_" + t.Cell }

// Streams mirrors NatsTopology.Streams.
func (t *NatsTopology) Streams() ([]jetstream.StreamConfig, error) {
	cellSpecFamily, err := protocol.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, protocol.NatsSubjectTaxonomy.DesiredFamilySegment())
	if err != nil {
		return nil, err
	}

	cellOperationsFamily, err := protocol.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, protocol.NatsSubjectTaxonomy.OperationFamilySegment())
	if err != nil {
		return nil, err
	}

	cellEventsFamily, err := protocol.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, protocol.NatsSubjectTaxonomy.ObservationFamilySegment())
	if err != nil {
		return nil, err
	}

	return []jetstream.StreamConfig{
		natsTopologyStream(t, "CELL_SPEC", cellSpecFamily, 256*1024*1024),
		natsTopologyStream(t, "CELL_OPERATIONS", cellOperationsFamily, 1024*1024*1024),
		natsTopologyStream(t, "CELL_EVENTS", cellEventsFamily, 256*1024*1024),
	}, nil
}

// Leaders mirrors NatsTopology.Leaders.
func (t *NatsTopology) Leaders() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      "ORCH_LEADERS",
		Description: "Fenced authority leases for " + t.Cell,
		History:     5,
		MaxBytes:    8 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// Runtime mirrors NatsTopology.Runtime.
func (t *NatsTopology) Runtime() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      "ORCH_RUNTIME",
		Description: "Live orchestrator registrations for " + t.Cell,
		History:     2,
		TTL:         5 * time.Minute,
		MaxBytes:    8 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// Delivery mirrors NatsTopology.Delivery.
func (t *NatsTopology) Delivery() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       "ORCH_DELIVERY",
		Description:  "Durable regional delivery and handoff coordination for " + t.Cell,
		History:      2,
		MaxValueSize: 16 * 1024,
		MaxBytes:     256 * 1024 * 1024,
		Replicas:     t.Replicas,
	}
}

// Operations mirrors NatsTopology.Operations. This authoritative journal is
// provisioned only by the infrastructure identity; controller TS_ORCH_REPLICAS
// must never reconfigure it.
func (t *NatsTopology) Operations() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       "ORCH_OPERATIONS",
		Description:  "Authoritative encrypted regional operation journal for " + t.Cell,
		History:      2,
		MaxValueSize: 16 * 1024,
		MaxBytes:     256 * 1024 * 1024,
		Replicas:     3,
	}
}

// OperationProofConsumptions mirrors NatsTopology.OperationProofConsumptions:
// expiry-bounded R3 records that make each private journal authority proof
// single-use.
func (t *NatsTopology) OperationProofConsumptions() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       "ORCH_OPERATION_PROOFS",
		Description:  "Expiry-bounded single-use operation journal authority proofs for " + t.Cell,
		History:      1,
		TTL:          5 * time.Minute,
		MaxValueSize: 256,
		MaxBytes:     8 * 1024 * 1024,
		// As with ORCH_OPERATIONS, this is provisioned only by infrastructure
		// and must never inherit the controller's development replica count.
		Replicas: 3,
	}
}

// Bundles mirrors NatsTopology.Bundles.
func (t *NatsTopology) Bundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "CELL_BUNDLES",
		Description: "Signed regional control bundles for " + t.Cell,
		MaxBytes:    256 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// ProtocolPackage mirrors NatsTopology.ProtocolPackage: the controller may
// read only this immutable canonical protocol package.
func (t *NatsTopology) ProtocolPackage() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "ORCH_PROTOCOL_PACKAGE",
		Description: "Immutable canonical orchestrator protocol package for " + t.Cell,
		MaxBytes:    256 * 1024,
		Replicas:    t.Replicas,
	}
}

// StartupConsumer mirrors NatsTopology.StartupConsumer.
func (t *NatsTopology) StartupConsumer() (jetstream.ConsumerConfig, error) {
	filter, err := protocol.NatsSubjectTaxonomy.RuntimeStartupPattern(t.Cell)
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	return jetstream.ConsumerConfig{
		Name:          "runtime_startup",
		Durable:       "runtime_startup",
		Description:   "Acknowledged runtime startup events for " + t.Cell,
		FilterSubject: filter,
		// JetStream derives the effective acknowledgement wait from the first
		// backoff interval, so declare the value it will return on readback.
		AckWait:       1 * time.Second,
		MaxDeliver:    5,
		MaxAckPending: 32,
		MaxWaiting:    16,
		BackOff: []time.Duration{
			1 * time.Second,
			5 * time.Second,
			15 * time.Second,
			30 * time.Second,
		},
		Replicas: t.Replicas,
	}, nil
}

// CellSpecConsumer mirrors NatsTopology.CellSpecConsumer.
func (t *NatsTopology) CellSpecConsumer() (jetstream.ConsumerConfig, error) {
	subject, err := t.CellSpecSubject()
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	name := "gitops_cell_spec_" + t.Instance
	return jetstream.ConsumerConfig{
		Name:          name,
		Durable:       name,
		Description:   "Durable signed native GitOps CellSpecs for " + t.Cell + "/" + t.Instance,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subject,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		// Keep the declared value aligned with the first backoff interval.
		AckWait:           1 * time.Second,
		MaxDeliver:        5,
		MaxAckPending:     8,
		MaxWaiting:        8,
		MaxRequestBatch:   1,
		MaxRequestExpires: 30 * time.Second,
		BackOff: []time.Duration{
			1 * time.Second,
			5 * time.Second,
			15 * time.Second,
			30 * time.Second,
		},
		Replicas: t.Replicas,
	}, nil
}

func natsTopologyStream(t *NatsTopology, name, subject string, maxBytes int64) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:                   name,
		Description:            "TerraScale Orchestrator " + name + " for " + t.Cell,
		Subjects:               []string{subject},
		MaxConsumers:           -1,
		MaxMsgs:                -1,
		MaxMsgsPerSubject:      -1,
		MaxBytes:               maxBytes,
		MaxAge:                 30 * 24 * time.Hour,
		MaxMsgSize:             -1,
		Duplicates:             2 * time.Minute,
		Replicas:               t.Replicas,
		Retention:              jetstream.LimitsPolicy,
		Storage:                jetstream.FileStorage,
		Compression:            jetstream.NoCompression,
		NoAck:                  false,
		Discard:                jetstream.DiscardOld,
		Sealed:                 false,
		DenyDelete:             false,
		DenyPurge:              false,
		AllowRollup:            false,
		AllowDirect:            false,
		MirrorDirect:           false,
		DiscardNewPerSubject:   false,
		AllowMsgTTL:            false,
		SubjectDeleteMarkerTTL: 0,
		AllowMsgCounter:        false,
		AllowMsgSchedules:      false,
		AllowAtomicPublish:     false,
	}
}
