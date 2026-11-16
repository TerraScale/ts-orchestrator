package rolloutexec

import (
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	HealthDomain = "terrascale.orchestrator.rollout-health"
	HealthSchema = "terrascale.orchestrator.rollout-health.v1"
	// HealthLifetime bounds one proof, so only a recent one counts.
	HealthLifetime = 2 * time.Minute
	// DefaultProofInterval is how often a healthy unit publishes a proof.
	DefaultProofInterval = 5 * time.Second
	healthClockSkew      = time.Minute
)

var (
	ErrInvalid = errors.New("rollout executor input is invalid")

	unitRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// HealthProof is signed by a running unit while it is healthy. It names the
// exact binary digest the process executes and its incarnation (process ID
// and a per-start nonce), so the executor detects both a wrong release and
// a restart during soak.
type HealthProof struct {
	Schema       string    `json:"schema"`
	Cell         string    `json:"cell"`
	Unit         string    `json:"unit"`
	BinarySHA256 string    `json:"binary_sha256"`
	ProcessID    int64     `json:"process_id"`
	StartNonce   string    `json:"start_nonce"`
	ObservedAt   time.Time `json:"observed_at"`
	// ReceivedAt is when the collector accepted the proof, on the leader's
	// own clock. It is never signed or sent; it orders a proof against the
	// leader's steps without trusting the unit's clock.
	ReceivedAt time.Time `json:"-"`
}

// KeyResolver returns the keys allowed to sign unit's proofs. Controllers
// resolve to the regional controller response key; an unknown unit returns
// an error, so its proofs are dropped.
type KeyResolver func(unit string) (trust.Keyring, error)

// Collector verifies proofs from protocol.RolloutProofSubject and keeps the
// newest proof per unit. It is safe for concurrent use.
type Collector struct {
	cell string
	keys KeyResolver
	now  func() time.Time
	// Arrived, when set before Subscribe, is signalled after every newly
	// accepted proof, so the executor acts without waiting for its tick.
	Arrived chan<- struct{}

	mu     sync.Mutex
	latest map[string]HealthProof
	// retired lists, per unit, incarnations a newer one superseded and
	// when each may be forgotten; their proofs are refused until then.
	retired map[string][]retiredIncarnation
}

type retiredIncarnation struct {
	processID  int64
	startNonce string
	until      time.Time
}
