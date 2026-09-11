package messaging

import (
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// NatsTopology is the regional controller's JetStream topology for one cell.
type NatsTopology struct {
	Cell     string
	Replicas int
	Instance string
}

// NewNatsTopology builds the topology; Instance defaults to "local".
func NewNatsTopology(cell string, replicas int, instance string) *NatsTopology {
	if instance == "" {
		instance = "local"
	}

	return &NatsTopology{Cell: cell, Replicas: replicas, Instance: instance}
}

func (t *NatsTopology) HealthSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.ControllerHealthSubject(t.Cell)
}

func (t *NatsTopology) InstanceHealthSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.ControllerInstanceHealthSubject(t.Cell, t.Instance)
}

func (t *NatsTopology) StatusSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.ControllerStatusSubject(t.Cell)
}

func (t *NatsTopology) MembersSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.ControllerMembersSubject(t.Cell)
}

// StatsSubject is the read-only service statistics endpoint subject: version,
// schema, health, request/error/latency aggregates.
func (t *NatsTopology) StatsSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.ControllerStatsSubject(t.Cell)
}

func (t *NatsTopology) DirectDeliverySubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.DirectDeliverySubject(t.Cell)
}

func (t *NatsTopology) OperationJournalCreateSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.OperationJournalCreateSubject(t.Cell)
}

func (t *NatsTopology) OperationJournalUpdateSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.OperationJournalUpdateSubject(t.Cell)
}

func (t *NatsTopology) OperationJournalReplySubject(callerIdentity, nonce string) (string, error) {
	return natspolicy.NatsSubjectTaxonomy.OperationJournalReplySubject(t.Cell, callerIdentity, nonce)
}

func (t *NatsTopology) OperationJournalWriterQueueGroup() string {
	return "terrascale_orchestrator_journal_writer_" + t.Cell
}

func (t *NatsTopology) CellSpecSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.CellSpecSubject(t.Cell)
}

func (t *NatsTopology) StartupSubject() (string, error) {
	return natspolicy.NatsSubjectTaxonomy.RuntimeStartupSubject(t.Cell, t.Instance)
}

func (t *NatsTopology) ProtocolObject() string { return "orchestrator-protocol-v1" }

func (t *NatsTopology) ServiceName() string { return "terrascale_orchestrator_" + t.Cell }

func (t *NatsTopology) ServiceQueueGroup() string { return "orchestrator_" + t.Cell }

// Streams returns the regional stream configurations.
func (t *NatsTopology) Streams() ([]jetstream.StreamConfig, error) {
	cellSpecFamily, err := natspolicy.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, natspolicy.NatsSubjectTaxonomy.DesiredFamilySegment())
	if err != nil {
		return nil, err
	}

	cellOperationsFamily, err := natspolicy.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, natspolicy.NatsSubjectTaxonomy.OperationFamilySegment())
	if err != nil {
		return nil, err
	}

	cellEventsFamily, err := natspolicy.NatsSubjectTaxonomy.RegionalFamilyPattern(
		t.Cell, natspolicy.NatsSubjectTaxonomy.ObservationFamilySegment())
	if err != nil {
		return nil, err
	}

	return []jetstream.StreamConfig{
		natsTopologyStream(t, "CELL_SPEC", cellSpecFamily, 256*1024*1024),
		natsTopologyStream(t, "CELL_OPERATIONS", cellOperationsFamily, 1024*1024*1024),
		natsTopologyStream(t, "CELL_EVENTS", cellEventsFamily, 256*1024*1024),
	}, nil
}

// Leaders returns the regional authority lease bucket.
func (t *NatsTopology) Leaders() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      "ORCH_LEADERS",
		Description: "Fenced authority leases for " + t.Cell,
		History:     5,
		MaxBytes:    8 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// Runtime returns the live orchestrator registration bucket.
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

// DeliveryOperationMaxDocumentBytes holds a request, receipt and journal metadata.
const DeliveryOperationMaxDocumentBytes = 2*1024*1024 + 16*1024

// DeliveryOperationMaxValueBytes also allows the KV CAS headers counted by
// JetStream in its per-message size limit.
const DeliveryOperationMaxValueBytes = DeliveryOperationMaxDocumentBytes + 4*1024

// DeliveryOperationMaxMessageBytes includes the ordinary leader API's JSON
// base64 encoding of a full operation and its response metadata.
const DeliveryOperationMaxMessageBytes = (DeliveryOperationMaxValueBytes+2)/3*4 + 16*1024

// Delivery returns the delivery and handoff coordination bucket.
func (t *NatsTopology) Delivery() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       "ORCH_DELIVERY",
		Description:  "Durable regional delivery and handoff coordination for " + t.Cell,
		History:      2,
		MaxValueSize: DeliveryOperationMaxValueBytes,
		MaxBytes:     256 * 1024 * 1024,
		Replicas:     t.Replicas,
	}
}

// CommandReplay is the bounded, replicated replay claim store used by the
// signed command ingress. Expired claims are removed by JetStream rather than
// retained forever in the delivery journal.
func (t *NatsTopology) CommandReplay() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       "ORCH_COMMAND_REPLAY",
		Description:  "Expiry-bounded signed command replay claims for " + t.Cell,
		History:      1,
		TTL:          15 * time.Minute,
		MaxValueSize: 256,
		MaxBytes:     16 * 1024 * 1024,
		Replicas:     t.Replicas,
	}
}

// Operations returns the authoritative operation journal bucket. This journal
// is provisioned only by the infrastructure identity; controller
// TS_ORCH_REPLICAS must never reconfigure it.
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

// OperationProofConsumptions returns expiry-bounded R3 records that make each
// private journal authority proof single-use.
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

// Bundles returns the regional bundle object store.
func (t *NatsTopology) Bundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "CELL_BUNDLES",
		Description: "Signed regional control bundles for " + t.Cell,
		MaxBytes:    256 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// ProtocolPackage returns the immutable canonical protocol package store, the
// only package the controller may read.
func (t *NatsTopology) ProtocolPackage() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "ORCH_PROTOCOL_PACKAGE",
		Description: "Immutable canonical orchestrator protocol package for " + t.Cell,
		MaxBytes:    256 * 1024,
		Replicas:    t.Replicas,
	}
}

// StartupConsumer returns the runtime startup consumer configuration. The
// durable proof consumer is per-instance, mirroring CellSpecConsumer: a
// cell-wide cursor lets one replica's proof fetch consume and acknowledge
// another replica's proof from the shared deliver position, failing both.
func (t *NatsTopology) StartupConsumer() (jetstream.ConsumerConfig, error) {
	filter, err := natspolicy.NatsSubjectTaxonomy.RuntimeStartupSubject(t.Cell, t.Instance)
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	name := "runtime_startup_" + t.Instance
	return jetstream.ConsumerConfig{
		Name:          name,
		Durable:       name,
		Description:   "Acknowledged runtime startup events for " + t.Cell + "/" + t.Instance,
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

// CellSpecConsumer returns the regional CellSpec consumer configuration.
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
