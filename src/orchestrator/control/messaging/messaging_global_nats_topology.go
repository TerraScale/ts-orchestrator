package messaging

import (
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// GlobalNatsTopology is the GRU global-authority JetStream topology (streams,
// KV buckets and durable desired-state consumers).
type GlobalNatsTopology struct {
	Replicas int
}

const (
	GlobalNatsTopologyCellSpecStream         = "GLOBAL_SPEC"
	GlobalNatsTopologyMasterDeliveriesBucket = "GLOBAL_DELIVERIES"
	GlobalNatsTopologyCellsBucket            = "GLOBAL_CELLS"
)

func GlobalNatsTopologyCellDirectorySubject() string {
	return natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()
}

func GlobalNatsTopologyCellSpecSubjectPrefix() string {
	return natspolicy.NatsSubjectTaxonomy.GlobalCellSpecPrefix()
}

// NewGlobalNatsTopology validates the replica count (R3 only).
func NewGlobalNatsTopology(replicas int) (*GlobalNatsTopology, error) {
	if replicas != 3 {
		return nil, errors.New("Global control state requires R3. (Parameter 'replicas')")
	}

	return &GlobalNatsTopology{Replicas: replicas}, nil
}

// Streams returns the global stream configurations.
func (t *GlobalNatsTopology) Streams() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{
			Name:        GlobalNatsTopologyCellSpecStream,
			Description: "Accepted global revisions and compiled cell handoffs",
			Subjects: []string{natspolicy.NatsSubjectTaxonomy.GlobalFamilyPattern(
				natspolicy.NatsSubjectTaxonomy.DesiredFamilySegment())},
			MaxConsumers:      -1,
			MaxMsgs:           -1,
			MaxMsgsPerSubject: -1,
			MaxMsgSize:        -1,
			MaxBytes:          256 * 1024 * 1024,
			MaxAge:            30 * 24 * time.Hour,
			Duplicates:        2 * time.Minute,
			Replicas:          t.Replicas,
			Retention:         jetstream.LimitsPolicy,
			Storage:           jetstream.FileStorage,
			Discard:           jetstream.DiscardOld,
		},
	}
}

// Leaders returns the fenced global authority lease bucket.
func (t *GlobalNatsTopology) Leaders() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      "ORCH_LEADERS",
		Description: "Fenced global authority leases",
		History:     5,
		MaxBytes:    8 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// Cells returns the durable cell advertisement bucket.
func (t *GlobalNatsTopology) Cells() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       GlobalNatsTopologyCellsBucket,
		Description:  "Durable read-only regional cell advertisements",
		History:      16,
		TTL:          30 * 24 * time.Hour,
		MaxValueSize: 64 * 1024,
		MaxBytes:     64 * 1024 * 1024,
		Replicas:     t.Replicas,
	}
}

// MasterDeliveries holds immutable original intent and resumable regional fanout.
func (t *GlobalNatsTopology) MasterDeliveries() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{Bucket: GlobalNatsTopologyMasterDeliveriesBucket,
		Description: "Signed global delivery preparation and regional fanout",
		History:     1, TTL: 0, MaxValueSize: DeliveryOperationMaxValueBytes,
		MaxBytes: 1024 * 1024 * 1024, Storage: jetstream.FileStorage, Replicas: t.Replicas}
}

// CellSpecConsumer returns the global CellSpec consumer for a cell.
func (t *GlobalNatsTopology) CellSpecConsumer(cell string) (jetstream.ConsumerConfig, error) {
	subject, err := GlobalNatsTopologyCellSpecSubject(cell)
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	return jetstream.ConsumerConfig{
		Name:              "global_cell_spec_" + cell,
		Description:       "Durable globally signed desired-estate CellSpecs for " + cell,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		AckPolicy:         jetstream.AckExplicitPolicy,
		FilterSubject:     subject,
		ReplayPolicy:      jetstream.ReplayInstantPolicy,
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

func GlobalNatsTopologyCellSpecSubject(cell string) (string, error) {
	if !GlobalNatsTopologyIsCellToken(cell) {
		return "", errors.New(
			"The global CellSpec cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	return GlobalNatsTopologyCellSpecSubjectPrefix() + "." + cell, nil
}

func GlobalNatsTopologyIsCellToken(cell string) bool { return shared.MessagingCellTokenIsValid(cell) }

func GlobalNatsTopologyCellAdvertisementKey(cell string) (string, error) {
	if !GlobalNatsTopologyIsCellToken(cell) {
		return "", errors.New(
			"The advertised cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	return "cell." + cell, nil
}

// GlobalNatsTopologyBucketName returns the KV bucket of a config for callers
// that only need the name.
func GlobalNatsTopologyBucketName(config jetstream.KeyValueConfig) string { return config.Bucket }
