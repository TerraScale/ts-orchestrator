package rolloutexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	HealthDomain = "terrascale.orchestrator.rollout-health"
	HealthSchema = "terrascale.orchestrator.rollout-health.v1"
	// HealthLifetime bounds one proof, so only a recent one counts.
	HealthLifetime = 2 * time.Minute
	// DefaultProofInterval is how often a healthy unit publishes a proof.
	DefaultProofInterval = 15 * time.Second
	healthClockSkew      = time.Minute
	// incarnationQuiet is how long a unit's newest incarnation must have
	// been silent before a new incarnation whose clock reads earlier
	// replaces it: a live incarnation keeps proving within it, so a
	// delayed proof of a superseded process never displaces it.
	incarnationQuiet = 2 * DefaultProofInterval
	maxProofUnits    = 4 * rollout.MaxUnits
	// maxRetired bounds the superseded incarnations kept per unit.
	maxRetired = 8
	// retiredFor is how long a superseded incarnation stays refused: no
	// proof it signed can still verify after that.
	retiredFor = HealthLifetime + healthClockSkew
)

var (
	ErrInvalid = errors.New("rollout executor input is invalid")

	unitRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nonceRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
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

func (proof HealthProof) validate() error {
	if proof.Schema != HealthSchema || !unitRE.MatchString(proof.Cell) || !unitRE.MatchString(proof.Unit) ||
		!digestRE.MatchString(proof.BinarySHA256) || proof.ProcessID <= 0 || !nonceRE.MatchString(proof.StartNonce) ||
		proof.ObservedAt.IsZero() {
		return fmt.Errorf("%w: health proof", ErrInvalid)
	}
	return nil
}

// Health converts the proof into the rollout core's health observation.
// Its ObservedAt is the leader's receipt time (seen), so the core orders
// the report against the leader-clock phase and soak times without
// trusting the unit's clock; the signed ObservedAt only bounds replay.
func (proof HealthProof) Health() rollout.Health {
	return rollout.Health{Digest: proof.BinarySHA256, ProcessID: proof.ProcessID, StartNonce: proof.StartNonce,
		ObservedAt: proof.seen()}
}

// seen is when the proof reached the leader, on the leader's clock. A
// source that does not record receipt falls back to the unit's own
// observation time.
func (proof HealthProof) seen() time.Time {
	if !proof.ReceivedAt.IsZero() {
		return proof.ReceivedAt
	}
	return proof.ObservedAt
}

// arrivedAfter reports whether the proof reached the leader after at, a
// leader-clock time.
func (proof HealthProof) arrivedAfter(at time.Time) bool {
	return proof.seen().After(at)
}

func (proof HealthProof) sameIncarnation(other HealthProof) bool {
	return proof.ProcessID == other.ProcessID && proof.StartNonce == other.StartNonce
}

func healthScope(cell, unit string) trust.Scope {
	return trust.Scope{Domain: HealthDomain, DeploymentID: unit, Cell: cell, Environment: "rollout", Role: "health", Slot: "v1"}
}

// SignHealthProof signs proof with the unit's own key.
func SignHealthProof(proof HealthProof, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	proof.ObservedAt = proof.ObservedAt.UTC()
	if err := proof.validate(); err != nil {
		return nil, err
	}
	payload, err := trust.EncodePayload(proof)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.Sign(payload, healthScope(proof.Cell, proof.Unit), now, now.Add(HealthLifetime), key)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

// VerifyHealthProof accepts only a currently valid proof for exactly this
// cell and unit, signed by one of keys.
func VerifyHealthProof(wire []byte, cell, unit string, keys trust.Keyring, now time.Time) (HealthProof, error) {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return HealthProof{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, healthScope(cell, unit), keys, now,
		trust.Policy{MaxLifetime: HealthLifetime, ClockSkew: healthClockSkew})
	if err != nil {
		return HealthProof{}, err
	}
	var proof HealthProof
	if err := protocol.DecodeStrict(payload, &proof, trust.MaxPayloadBytes); err != nil {
		return HealthProof{}, err
	}
	if err := proof.validate(); err != nil {
		return HealthProof{}, err
	}
	if proof.Cell != cell || proof.Unit != unit || proof.ObservedAt.After(now.Add(healthClockSkew)) ||
		proof.ObservedAt.Before(envelope.IssuedAt.Add(-healthClockSkew)) {
		return HealthProof{}, fmt.Errorf("%w: health proof binding", ErrInvalid)
	}
	return proof, nil
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

// NewCollector returns a collector for cell. now defaults to time.Now.
func NewCollector(cell string, keys KeyResolver, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{cell: cell, keys: keys, now: now, latest: map[string]HealthProof{},
		retired: map[string][]retiredIncarnation{}}
}

// Observe verifies one proof received on subject and records it. A proof
// that arrived on another unit's subject, is older than the unit's newest
// proof, or fails verification is dropped with an error.
func (c *Collector) Observe(subject string, wire []byte) error {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return err
	}
	unit := envelope.Scope.DeploymentID
	if !unitRE.MatchString(unit) || subject != protocol.RolloutProofSubject(c.cell, unit) {
		return fmt.Errorf("%w: health proof subject", ErrInvalid)
	}
	if c.keys == nil {
		return fmt.Errorf("%w: no proof keys", ErrInvalid)
	}
	keys, err := c.keys(unit)
	if err != nil {
		return err
	}
	proof, err := VerifyHealthProof(wire, c.cell, unit, keys, c.now())
	if err != nil {
		return err
	}
	now := c.now().UTC()
	proof.ReceivedAt = now
	c.mu.Lock()
	defer c.mu.Unlock()
	// A superseded process never becomes current again: a delayed or
	// replayed proof of it is refused while any proof it signed verifies.
	retired := slices.DeleteFunc(c.retired[unit], func(r retiredIncarnation) bool { return !now.Before(r.until) })
	c.retired[unit] = retired
	if slices.ContainsFunc(retired, func(r retiredIncarnation) bool {
		return r.processID == proof.ProcessID && r.startNonce == proof.StartNonce
	}) {
		return nil
	}
	previous, exists := c.latest[unit]
	// Within one incarnation proofs only move forward. Another
	// incarnation whose clock reads earlier (a clock stepped back across a
	// restart) replaces the newest one only after that one went quiet.
	if exists && !proof.ObservedAt.After(previous.ObservedAt) &&
		(proof.sameIncarnation(previous) || proof.ReceivedAt.Sub(previous.ReceivedAt) <= incarnationQuiet) {
		return nil
	}
	if !exists && len(c.latest) >= maxProofUnits {
		// An expired proof completes nothing: reclaim the units that
		// stopped proving (removed or replaced) before refusing a new one.
		for id, held := range c.latest {
			if now.Sub(held.ReceivedAt) > retiredFor {
				delete(c.latest, id)
				delete(c.retired, id)
			}
		}
		if len(c.latest) >= maxProofUnits {
			return fmt.Errorf("%w: too many proof units", ErrInvalid)
		}
	}
	if exists && !proof.sameIncarnation(previous) {
		if len(retired) >= maxRetired {
			retired = slices.Delete(retired, 0, len(retired)-maxRetired+1)
		}
		c.retired[unit] = append(retired, retiredIncarnation{processID: previous.ProcessID,
			startNonce: previous.StartNonce, until: now.Add(retiredFor)})
	}
	c.latest[unit] = proof
	return nil
}

// Latest returns unit's newest verified proof.
func (c *Collector) Latest(unit string) (HealthProof, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	proof, exists := c.latest[unit]
	return proof, exists
}

// Subscribe feeds every unit's proofs in the cell into the collector.
func (c *Collector) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: proof collector needs a connection", ErrInvalid)
	}
	return conn.Subscribe(protocol.RolloutProofSubject(c.cell, ""), func(msg *nats.Msg) {
		if err := c.Observe(msg.Subject, msg.Data); err != nil {
			slog.Debug("rollout health proof dropped", "component", "rollout", "error", err)
		}
	})
}

// Publisher signs and publishes this process's health proof while Healthy
// reports true. The binary digest is hashed once from the running
// executable, so a replaced file on disk never changes what is reported.
type Publisher struct {
	Conn     *nats.Conn
	Cell     string
	Unit     string
	Key      ed25519.PrivateKey
	Healthy  func() bool
	Interval time.Duration
	// Executable defaults to /proc/self/exe.
	Executable string
	Now        func() time.Time
}

// Run publishes until ctx ends.
func (p Publisher) Run(ctx context.Context) error {
	if p.Conn == nil || !unitRE.MatchString(p.Cell) || !unitRE.MatchString(p.Unit) ||
		len(p.Key) != ed25519.PrivateKeySize || p.Healthy == nil {
		return fmt.Errorf("%w: proof publisher configuration", ErrInvalid)
	}
	now, interval, executable := p.Now, p.Interval, p.Executable
	if now == nil {
		now = time.Now
	}
	if interval <= 0 {
		interval = DefaultProofInterval
	}
	if executable == "" {
		executable = "/proc/self/exe"
	}
	digest, err := hashExecutable(executable)
	if err != nil {
		return fmt.Errorf("hash running executable: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	identity := HealthProof{Schema: HealthSchema, Cell: p.Cell, Unit: p.Unit, BinarySHA256: digest,
		ProcessID: int64(os.Getpid()), StartNonce: hex.EncodeToString(nonce)}
	subject := protocol.RolloutProofSubject(p.Cell, p.Unit)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if p.Healthy() {
			at := now().UTC()
			proof := identity
			proof.ObservedAt = at
			if wire, err := SignHealthProof(proof, p.Key, at); err != nil {
				return err
			} else if err := p.Conn.Publish(subject, wire); err != nil {
				slog.Debug("rollout health proof not published", "component", "rollout", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func hashExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
