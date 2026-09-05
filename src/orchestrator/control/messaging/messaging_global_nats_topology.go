package messaging

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// GlobalNatsTopology is the GRU global-authority JetStream topology (streams,
// KV buckets, Object Stores, durable consumers) and the CI subject
// derivations.
type GlobalNatsTopology struct {
	Replicas int
}

const (
	GlobalNatsTopologyCellSpecStream           = "GLOBAL_SPEC"
	GlobalNatsTopologyCiStream                 = "GLOBAL_CI"
	GlobalNatsTopologyMasterDeliveriesBucket   = "GLOBAL_DELIVERIES"
	GlobalNatsTopologyCellsBucket              = "GLOBAL_CELLS"
	GlobalNatsTopologyRunnerJobsBucket         = "CI_RUNNER_JOBS"
	GlobalNatsTopologyRunnerBundlesBucket      = "CI_RUNNER_BUNDLES"
	GlobalNatsTopologyCiRunnerJournalKeyPrefix = "ci.runner"
)

func GlobalNatsTopologyCiSubject() string {
	return natspolicy.NatsSubjectTaxonomy.CiForgejoTriggerSubject()
}

func GlobalNatsTopologyCiJobSubjectPrefix() string {
	return natspolicy.NatsSubjectTaxonomy.CiJobSubjectPrefix()
}

func GlobalNatsTopologyCiRuntimeProofSubject() string {
	return natspolicy.NatsSubjectTaxonomy.CiRuntimeProofSubject()
}

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
			MaxBytes:   256 * 1024 * 1024,
			MaxAge:     30 * 24 * time.Hour,
			Duplicates: 2 * time.Minute,
			Replicas:   t.Replicas,
			Retention:  jetstream.LimitsPolicy,
			Storage:    jetstream.FileStorage,
			Discard:    jetstream.DiscardOld,
		},
		{
			Name:        GlobalNatsTopologyCiStream,
			Description: "Durable normalized CI events and fenced runner commands",
			Subjects:    []string{natspolicy.NatsSubjectTaxonomy.GlobalCiFamilyPattern()},
			MaxBytes:    1024 * 1024 * 1024,
			MaxAge:      30 * 24 * time.Hour,
			Duplicates:  24 * time.Hour,
			Replicas:    t.Replicas,
			Retention:   jetstream.LimitsPolicy,
			Storage:     jetstream.FileStorage,
			Discard:     jetstream.DiscardOld,
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

// Releases returns the delivery and CI journal ledger bucket.
func (t *GlobalNatsTopology) Releases() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		// Durable bucket name kept from the retired stage for store continuity; its
		// content is the direct-delivery and CI journal ledger, not a
		// candidate/promotion stage journal.
		Bucket:       "GLOBAL_RELEASES",
		Description:  "Durable delivery and CI journal ledger (triggers, pipelines, direct operations)",
		History:      64,
		TTL:          365 * 24 * time.Hour,
		MaxValueSize: 16 * 1024,
		MaxBytes:     1024 * 1024 * 1024,
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

// RunnerJobs returns the CI runner acceptance pointer bucket.
func (t *GlobalNatsTopology) RunnerJobs() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:       GlobalNatsTopologyRunnerJobsBucket,
		Description:  "Fenced durable CI runner command acceptance pointers",
		History:      8,
		TTL:          30 * 24 * time.Hour,
		MaxValueSize: 16 * 1024,
		MaxBytes:     512 * 1024 * 1024,
		Replicas:     t.Replicas,
	}
}

// Bundles returns the global CI bundle object store.
func (t *GlobalNatsTopology) Bundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "GLOBAL_BUNDLES",
		Description: "Content-addressed global CI pipeline and native GitOps handoff records",
		MaxBytes:    1024 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// RunnerBundles returns the CI runner bundle object store.
func (t *GlobalNatsTopology) RunnerBundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      GlobalNatsTopologyRunnerBundlesBucket,
		Description: "Content-addressed CI runner source, log, evidence, and artifact records",
		TTL:         30 * 24 * time.Hour,
		MaxBytes:    64 * 1024 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// CiConsumer returns the CI trigger consumer configuration.
func (t *GlobalNatsTopology) CiConsumer() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Name:          "global_ci_trigger",
		Description:   "Leader-only normalized Forgejo trigger decisions",
		FilterSubject: GlobalNatsTopologyCiSubject(),
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
	}
}

// CiRuntimeProofConsumer returns the CI runtime-proof consumer configuration.
func (t *GlobalNatsTopology) CiRuntimeProofConsumer() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Name:              "global_ci_runtime_proof",
		Description:       "Leader-verified native CI runtime observations",
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		AckPolicy:         jetstream.AckExplicitPolicy,
		FilterSubject:     GlobalNatsTopologyCiRuntimeProofSubject(),
		ReplayPolicy:      jetstream.ReplayInstantPolicy,
		AckWait:           1 * time.Second,
		MaxDeliver:        5,
		MaxAckPending:     32,
		MaxWaiting:        16,
		MaxRequestBatch:   1,
		MaxRequestExpires: 30 * time.Second,
		BackOff: []time.Duration{
			1 * time.Second,
			5 * time.Second,
			15 * time.Second,
			30 * time.Second,
		},
		Replicas: t.Replicas,
	}
}

// CellSpecConsumer returns the global CellSpec consumer for a cell.
func (t *GlobalNatsTopology) CellSpecConsumer(cell string) (jetstream.ConsumerConfig, error) {
	subject, err := GlobalNatsTopologyCellSpecSubject(cell)
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	return jetstream.ConsumerConfig{
		Name:              "gitops_global_cell_spec_" + cell,
		Description:       "Durable globally signed native GitOps CellSpecs for " + cell,
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

// CiJobConsumer returns the durable fenced command inbox consumer for one
// runner.
func (t *GlobalNatsTopology) CiJobConsumer(zone, runner string) (jetstream.ConsumerConfig, error) {
	subject, err := GlobalNatsTopologyCiJobSubject(zone, runner)
	if err != nil {
		return jetstream.ConsumerConfig{}, err
	}

	runnerHash := subject[strings.LastIndex(subject, ".")+1:]
	return jetstream.ConsumerConfig{
		Name:              "ci_runner_" + strings.ReplaceAll(zone, "-", "_") + "_" + runnerHash,
		Description:       "Durable fenced CI command inbox for " + zone + " runner " + runnerHash,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		AckPolicy:         jetstream.AckExplicitPolicy,
		FilterSubject:     subject,
		ReplayPolicy:      jetstream.ReplayInstantPolicy,
		AckWait:           1 * time.Second,
		MaxDeliver:        5,
		MaxAckPending:     1,
		MaxWaiting:        4,
		MaxRequestBatch:   1,
		MaxRequestExpires: 30 * time.Second,
		InactiveThreshold: 24 * time.Hour,
		BackOff: []time.Duration{
			1 * time.Second,
			5 * time.Second,
			15 * time.Second,
			30 * time.Second,
		},
		Replicas: t.Replicas,
	}, nil
}

func GlobalNatsTopologyCiJobSubject(zone, runner string) (string, error) {
	if zone != "untrusted-product" && zone != "trusted-build" {
		return "", errors.New("The CI runner subject zone is invalid. (Parameter 'zone')")
	}

	hash, err := GlobalNatsTopologyCiRunnerIdentityHash(runner)
	if err != nil {
		return "", err
	}

	return GlobalNatsTopologyCiJobSubjectPrefix() + "." + zone + "." + hash[:24], nil
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

func GlobalNatsTopologyCiRunnerJournalPrefix(runner string) (string, error) {
	hash, err := GlobalNatsTopologyCiRunnerIdentityHash(runner)
	if err != nil {
		return "", err
	}

	return GlobalNatsTopologyCiRunnerJournalKeyPrefix + "." + hash + ".job", nil
}

func GlobalNatsTopologyCiRunnerIdentityHash(runner string) (string, error) {
	if len(runner) < 1 || len(runner) > 512 ||
		strings.IndexFunc(runner, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 {
		return "", errors.New("The CI runner subject identity is invalid. (Parameter 'runner')")
	}

	digest := sha256.Sum256([]byte(runner))
	return hex.EncodeToString(digest[:]), nil
}

// GlobalNatsTopologyBucketName returns the KV bucket of a config for callers
// that only need the name.
func GlobalNatsTopologyBucketName(config jetstream.KeyValueConfig) string { return config.Bucket }
