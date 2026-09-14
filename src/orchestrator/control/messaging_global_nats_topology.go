package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// GlobalNatsTopology mirrors the C# class: the GRU global-authority JetStream
// topology (streams, KV buckets, Object Stores, durable consumers) and the CI
// subject derivations. NATS.Net model types map onto nats.go jetstream config
// types (NatsKVConfig → jetstream.KeyValueConfig, NatsObjConfig →
// jetstream.ObjectStoreConfig, StreamConfig/ConsumerConfig identically named).
type GlobalNatsTopology struct {
	Replicas int
}

const (
	GlobalNatsTopologyCellSpecStream           = "GLOBAL_SPEC"
	GlobalNatsTopologyCiStream                 = "GLOBAL_CI"
	GlobalNatsTopologyCellsBucket              = "GLOBAL_CELLS"
	GlobalNatsTopologyRunnerJobsBucket         = "CI_RUNNER_JOBS"
	GlobalNatsTopologyRunnerBundlesBucket      = "CI_RUNNER_BUNDLES"
	GlobalNatsTopologyCiRunnerJournalKeyPrefix = "ci.runner"
)

func GlobalNatsTopologyCiSubject() string {
	return protocol.NatsSubjectTaxonomy.CiForgejoTriggerSubject()
}

func GlobalNatsTopologyCiJobSubjectPrefix() string {
	return protocol.NatsSubjectTaxonomy.CiJobSubjectPrefix()
}

func GlobalNatsTopologyCiRuntimeProofSubject() string {
	return protocol.NatsSubjectTaxonomy.CiRuntimeProofSubject()
}

func GlobalNatsTopologyCellDirectorySubject() string {
	return protocol.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()
}

func GlobalNatsTopologyCellSpecSubjectPrefix() string {
	return protocol.NatsSubjectTaxonomy.GlobalCellSpecPrefix()
}

// NewGlobalNatsTopology mirrors the C# constructor (R3 only).
func NewGlobalNatsTopology(replicas int) (*GlobalNatsTopology, error) {
	if replicas != 3 {
		return nil, errors.New("Global control state requires R3. (Parameter 'replicas')")
	}

	return &GlobalNatsTopology{Replicas: replicas}, nil
}

// Streams mirrors GlobalNatsTopology.Streams.
func (t *GlobalNatsTopology) Streams() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{
			Name:        GlobalNatsTopologyCellSpecStream,
			Description: "Accepted global revisions and compiled cell handoffs",
			Subjects: []string{protocol.NatsSubjectTaxonomy.GlobalFamilyPattern(
				protocol.NatsSubjectTaxonomy.DesiredFamilySegment())},
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
			Subjects:    []string{protocol.NatsSubjectTaxonomy.GlobalCiFamilyPattern()},
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

// Leaders mirrors GlobalNatsTopology.Leaders.
func (t *GlobalNatsTopology) Leaders() jetstream.KeyValueConfig {
	return jetstream.KeyValueConfig{
		Bucket:      "ORCH_LEADERS",
		Description: "Fenced global authority leases",
		History:     5,
		MaxBytes:    8 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// Cells mirrors GlobalNatsTopology.Cells.
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

// Releases mirrors GlobalNatsTopology.Releases.
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

// RunnerJobs mirrors GlobalNatsTopology.RunnerJobs.
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

// Bundles mirrors GlobalNatsTopology.Bundles.
func (t *GlobalNatsTopology) Bundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      "GLOBAL_BUNDLES",
		Description: "Content-addressed global CI pipeline and native GitOps handoff records",
		MaxBytes:    1024 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// RunnerBundles mirrors GlobalNatsTopology.RunnerBundles.
func (t *GlobalNatsTopology) RunnerBundles() jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{
		Bucket:      GlobalNatsTopologyRunnerBundlesBucket,
		Description: "Content-addressed CI runner source, log, evidence, and artifact records",
		TTL:         30 * 24 * time.Hour,
		MaxBytes:    64 * 1024 * 1024 * 1024,
		Replicas:    t.Replicas,
	}
}

// CiConsumer mirrors GlobalNatsTopology.CiConsumer.
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

// CiRuntimeProofConsumer mirrors GlobalNatsTopology.CiRuntimeProofConsumer.
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

// CellSpecConsumer mirrors GlobalNatsTopology.CellSpecConsumer.
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

// CiJobConsumer mirrors GlobalNatsTopology.CiJobConsumer.
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

// GlobalNatsTopologyCiJobSubject mirrors the static CiJobSubject.
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

// GlobalNatsTopologyCellSpecSubject mirrors the static CellSpecSubject.
func GlobalNatsTopologyCellSpecSubject(cell string) (string, error) {
	if !GlobalNatsTopologyIsCellToken(cell) {
		return "", errors.New(
			"The global CellSpec cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	return GlobalNatsTopologyCellSpecSubjectPrefix() + "." + cell, nil
}

// GlobalNatsTopologyIsCellToken mirrors the internal IsCellToken.
func GlobalNatsTopologyIsCellToken(cell string) bool { return messagingCellTokenIsValid(cell) }

// GlobalNatsTopologyCellAdvertisementKey mirrors the internal CellAdvertisementKey.
func GlobalNatsTopologyCellAdvertisementKey(cell string) (string, error) {
	if !GlobalNatsTopologyIsCellToken(cell) {
		return "", errors.New(
			"The advertised cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	return "cell." + cell, nil
}

// GlobalNatsTopologyCiRunnerJournalPrefix mirrors the static CiRunnerJournalPrefix.
func GlobalNatsTopologyCiRunnerJournalPrefix(runner string) (string, error) {
	hash, err := GlobalNatsTopologyCiRunnerIdentityHash(runner)
	if err != nil {
		return "", err
	}

	return GlobalNatsTopologyCiRunnerJournalKeyPrefix + "." + hash + ".job", nil
}

// GlobalNatsTopologyCiRunnerIdentityHash mirrors the static CiRunnerIdentityHash.
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
// that only need the name (mirrors config.Bucket in C#).
func GlobalNatsTopologyBucketName(config jetstream.KeyValueConfig) string { return config.Bucket }
