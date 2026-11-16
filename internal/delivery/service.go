package delivery

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	AdmissionBucket = "TS_DELIVERY_ADMISSIONS"
	OperationBucket = "TS_DELIVERY_OPERATIONS"
	IntentStream    = "TS_DELIVERY_INTENTS"
	IntentConsumer  = "TS_DELIVERY_WORKER"
)

// VerifiedEnvelope is returned only after a trusted signature was verified
// over the exact payload bytes.
type VerifiedEnvelope struct {
	Payload []byte
	Actor   string
}

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type Verifier interface {
	Verify(context.Context, []byte) (VerifiedEnvelope, error)
}

type ArtifactSigner interface {
	SignArtifact(context.Context, ArtifactRecord) ([]byte, error)
}

type ArtifactVerifier interface {
	VerifyArtifact(context.Context, []byte) (ArtifactRecord, string, error)
	VerifyArchivedArtifact(context.Context, []byte) (ArtifactRecord, string, error)
}

type Fencer interface {
	Current() authority.Snapshot
	Guard(context.Context, uint64) error
}

type Planner interface {
	Plan(context.Context, Intent) ([]host.Desired, error)
}

// ShapedPlanner is an optional Planner extension for roles whose replica count
// and host desired generation are owned by a continuous reconciler. The shape
// is recorded with the operation so a resumed delivery validates the same plan.
type ShapedPlanner interface {
	PlanShaped(context.Context, Intent) (PlanShape, []host.Desired, error)
}

// PlanShape is the desired generation and active replica count of a plan.
type PlanShape struct {
	Generation uint64 `json:"generation"`
	Replicas   int    `json:"replicas"`
}

type DesiredWriter interface {
	ApplyDesired(context.Context, host.Desired) (host.Receipt, error)
}

type Config struct {
	// ContainerApply admits the exact signed OCI release through SwarmKit and
	// returns only after application readiness. Replays must be idempotent.
	ContainerApply          func(context.Context, Intent) error
	CaptureContainerProfile func(context.Context, Intent) (string, error)
	Conn                    *nats.Conn
	JS                      jetstream.JetStream
	Cell                    string
	Replicas                int
	ArtifactStoreMaxBytes   int64
	Signer                  Signer
	Verifier                Verifier
	ArtifactSigner          ArtifactSigner
	ArtifactVerifier        ArtifactVerifier
	AuthorizeArtifact       func(context.Context, string, ArtifactRecord) error
	Authorize               func(context.Context, string, Intent) error
	Fencer                  Fencer
	Planner                 Planner
	Writer                  DesiredWriter
	// MaxPlannerAttempts bounds deliveries of an intent the planner keeps
	// refusing, such as a missing profile or no eligible host, before it is
	// held with a durable receipt. Zero uses DefaultMaxPlannerAttempts.
	// Transport and leadership failures never count toward it.
	MaxPlannerAttempts int
}

// DefaultMaxPlannerAttempts holds a planner-refused intent after roughly
// half an hour of capped redelivery backoff.
const DefaultMaxPlannerAttempts = 30

type Service struct {
	// recovery overrides deliveryConsumerRecovery, for tests.
	recovery   consumerRecovery
	js         jetstream.JetStream
	artifacts  jetstream.ObjectStore
	admissions jetstream.KeyValue
	operations jetstream.KeyValue
	consumer   jetstream.Consumer
	config     Config
	// plannerRefusals bounds an intent the planner keeps refusing.
	plannerRefusals plannerRefusalCounter
}

// Receipt is a durable admission outcome. "accepted" means each planned host
// desired write was accepted; it does not claim the guest is running or ready.
// Host reports provide observed runtime readiness separately.
type Receipt struct {
	OperationID    string `json:"operationId"`
	Fingerprint    string `json:"fingerprint"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	ArtifactDigest string `json:"artifactDigest"`
	ManifestDigest string `json:"manifestDigest"`
	Cell           string `json:"cell"`
	Role           string `json:"role"`
	Environment    string `json:"environment"`
	Generation     uint64 `json:"generation"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
}
