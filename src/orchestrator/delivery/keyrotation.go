package delivery

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// This file owns the D-70 key-rotation cadence the delivery runtime drives:
// the 24-hour capability HMAC rotation with one expiry-bucket overlap pushed
// to members and the Cloudflare Secrets Store, and the hooks a Vault
// integration implements to rotate the per-Region KEK and per-database DEKs.
// The staged transition machinery itself lives in security.Coordinator; this
// file only decides when an operation is due, derives its deterministic
// identity, and sequences the data-key hooks. Nothing here generates, holds,
// or logs key material: every fact and error is redacted by construction.

// CapabilityRotator is the staged rotation seam security.Coordinator
// implements. Rotate is idempotent per operation ID and fails closed;
// RetireExpired removes the previous bucket once every consumer reported the
// new generation and the overlap window has passed.
type CapabilityRotator interface {
	Rotate(ctx context.Context, operationID string) (security.RotationResult, error)
	RetireExpired(ctx context.Context) (security.RotationResult, error)
}

// CapabilityRotationPeriod is the mandated capability key lifetime (D-70).
const CapabilityRotationPeriod = security.CapabilityPeriod

// CapabilityRotationConfig configures the 24-hour cadence driver. Every
// field except Rotator has a D-70 default.
type CapabilityRotationConfig struct {
	// Rotator executes one staged rotation. Required.
	Rotator CapabilityRotator
	// Period is the rotation cadence; default 24 hours.
	Period time.Duration
	// Lead starts each rotation this long before the period boundary so
	// distribute, verify, and activate finish while the current generation
	// is still valid. Default security.DefaultExpirySafety.
	Lead time.Duration
	// Now overrides the clock for tests.
	Now func() time.Time
}

// CapabilityRotation drives one capability rotation per 24-hour bucket. Each
// bucket maps to exactly one deterministic operation ID, so retries,
// restarts, and duplicate ticks collapse into a single rotation through the
// coordinator's own idempotency. Durable idempotency lives in the
// coordinator's state store; the in-memory guard only avoids repeating
// provider calls within a tick loop.
type CapabilityRotation struct {
	rotator CapabilityRotator
	period  time.Duration
	lead    time.Duration
	now     func() time.Time

	mu         sync.Mutex
	lastBucket int64
	hasLast    bool
}

// NewCapabilityRotation validates the cadence configuration.
func NewCapabilityRotation(config CapabilityRotationConfig) (*CapabilityRotation, error) {
	if config.Rotator == nil {
		return nil, errors.New("delivery: capability rotation requires a rotator")
	}
	period := config.Period
	if period <= 0 {
		period = CapabilityRotationPeriod
	}
	lead := config.Lead
	if lead <= 0 {
		lead = security.DefaultExpirySafety
	}
	if lead >= period {
		return nil, errors.New("delivery: capability rotation lead must be shorter than the period")
	}
	if now := config.Now; now == nil {
		config.Now = time.Now
	}
	return &CapabilityRotation{rotator: config.Rotator, period: period, lead: lead, now: config.Now}, nil
}

// CapabilityRotationOperationID derives the deterministic operation identity
// of one bucket. The same bucket always yields the same ID.
func CapabilityRotationOperationID(bucket int64) string {
	return "capability-rotation-" + strconv.FormatInt(bucket, 10)
}

// Bucket returns the deterministic capability bucket containing t. With the
// default 24-hour period the buckets align to UTC day boundaries.
func (r *CapabilityRotation) Bucket(t time.Time) int64 {
	if r == nil || r.period <= 0 {
		return 0
	}
	return t.UTC().Unix() / int64(r.period/time.Second)
}

// targetBucket is the bucket the next generation serves. Inside the lead
// window at the end of a bucket the driver already targets the next bucket,
// so the staged transition overlaps the boundary instead of racing it.
func (r *CapabilityRotation) targetBucket(now time.Time) int64 {
	bucket := r.Bucket(now)
	into := now.UTC().Unix() % int64(r.period/time.Second)
	if into >= int64(r.period/time.Second)-int64(r.lead/time.Second) {
		return bucket + 1
	}
	return bucket
}

// Due reports whether the rotation for the bucket now falls in still has to
// run in this process. A restarted process reports due even when the durable
// coordinator already completed the bucket: the duplicate operation is a
// no-op, not a second rotation.
func (r *CapabilityRotation) Due(now time.Time) bool {
	if r == nil {
		return false
	}
	target := r.targetBucket(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.hasLast || target > r.lastBucket
}

// CapabilityRotationFact is the redacted, observable outcome of one tick:
// identifiers, generations, and expiries only, never key material.
type CapabilityRotationFact struct {
	Bucket        int64
	OperationID   string
	Rotated       bool
	Generation    uint64
	Phase         security.Phase
	CurrentKeyID  string
	PreviousKeyID string
	ExpiresAt     time.Time
	// RetireFailed records that overlap retirement did not complete. The
	// rotation itself is committed; the next tick retries retirement.
	RetireFailed bool
}

// Tick executes the rotation due for the current bucket, if any, and then
// retires expired overlap material. A rotation failure fails the tick
// without advancing the bucket, so the same deterministic operation is
// retried; the coordinator's failed-closed journal governs whether that
// retry may proceed. A retirement failure after a committed rotation does
// not fail the tick, because the next tick must keep retrying retirement
// rather than stop the cadence.
func (r *CapabilityRotation) Tick(ctx context.Context) (CapabilityRotationFact, error) {
	if r == nil || r.rotator == nil {
		return CapabilityRotationFact{}, errors.New("delivery: capability rotation is not configured")
	}
	if err := ctx.Err(); err != nil {
		return CapabilityRotationFact{}, err
	}
	now := r.now().UTC()
	if now.IsZero() {
		return CapabilityRotationFact{}, errors.New("delivery: capability rotation clock is invalid")
	}
	bucket := r.targetBucket(now)
	fact := CapabilityRotationFact{Bucket: bucket, OperationID: CapabilityRotationOperationID(bucket)}
	if r.Due(now) {
		result, err := r.rotator.Rotate(ctx, fact.OperationID)
		if err != nil {
			return CapabilityRotationFact{}, err
		}
		r.mu.Lock()
		r.lastBucket, r.hasLast = bucket, true
		r.mu.Unlock()
		fact.Rotated = true
		fact.Generation = result.NewVersion
		fact.Phase = result.Phase
		fact.CurrentKeyID = result.CurrentKeyID
		fact.PreviousKeyID = result.PreviousKeyID
		fact.ExpiresAt = result.NewExpiry
	}
	if _, err := r.rotator.RetireExpired(ctx); err != nil {
		fact.RetireFailed = true
	}
	return fact, nil
}

// DEKRotationReceipt is the secret-free proof of one database DEK rotation.
// The wrapped DEK itself stays beside the placement record; only identifiers
// and bookkeeping cross this seam.
type DEKRotationReceipt struct {
	DatabaseID   string
	Generation   uint64
	WrappedUnder string
	PreviousKept bool
	At           time.Time
}

// KEKRotationReceipt is the secret-free proof of one Region KEK rotation.
// RewrappedDEKs counts the DEKs rewrapped under the new KEK version inside
// the Vault boundary.
type KEKRotationReceipt struct {
	Region        string
	Generation    uint64
	RewrappedDEKs int
	At            time.Time
}

// DEKRotator is the D-70 hook a Vault integration implements for one
// database: generate the next DEK generation wrapped under the Region KEK,
// keep the previous wrapped DEK for overlap, and record the new version
// beside the placement record. It must be idempotent per idempotency key.
type DEKRotator interface {
	RotateDEK(ctx context.Context, databaseID, idempotencyKey string) (DEKRotationReceipt, error)
}

// KEKRotator is the D-70 hook a Vault integration implements for one Region:
// create the next KEK version and rewrap every DEK the Region holds without
// unwrapping any key outside the Vault boundary. It must be idempotent per
// idempotency key.
type KEKRotator interface {
	RotateKEK(ctx context.Context, region, idempotencyKey string) (KEKRotationReceipt, error)
}

// DEKRotationItem names one database whose DEK rotation is due. Generation
// is the DEK generation currently recorded beside the placement record.
type DEKRotationItem struct {
	DatabaseID string
	Generation uint64
}

// KEKRotationItem names one Region KEK whose rotation is due. Generation is
// the current KEK version.
type KEKRotationItem struct {
	Region     string
	Generation uint64
}

// DataKeySource reports which KEKs and DEKs are due. The placement records
// own the schedule; this seam keeps the driver free of storage and keeps
// provider identifiers out of rotation decisions.
type DataKeySource interface {
	DEKsDue(ctx context.Context) ([]DEKRotationItem, error)
	KEKsDue(ctx context.Context) ([]KEKRotationItem, error)
}

// DataKeyRotationConfig configures the data-key hook driver. All three
// seams are required: a missing authority must stop startup rather than
// silently skip a due rotation.
type DataKeyRotationConfig struct {
	DEKs   DEKRotator
	KEKs   KEKRotator
	Source DataKeySource
	Now    func() time.Time
}

// DataKeyRotation sequences due KEK and DEK rotations one item at a time
// with deterministic idempotency keys. It never touches key material.
type DataKeyRotation struct {
	deks   DEKRotator
	keks   KEKRotator
	source DataKeySource
	now    func() time.Time
}

// NewDataKeyRotation validates the hook configuration.
func NewDataKeyRotation(config DataKeyRotationConfig) (*DataKeyRotation, error) {
	if config.DEKs == nil || config.KEKs == nil || config.Source == nil {
		return nil, errors.New("delivery: data-key rotation requires a DEK hook, a KEK hook, and a due-key source")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &DataKeyRotation{deks: config.DEKs, keks: config.KEKs, source: config.Source, now: config.Now}, nil
}

// DataKeyRotationFact is the redacted record of one rotated key. Exactly one
// of Region (KEK) and DatabaseID (DEK) is set.
type DataKeyRotationFact struct {
	Kind       string // "kek" or "dek"
	Region     string
	DatabaseID string
	Generation uint64
	At         time.Time
}

// Tick rotates every due Region KEK first, then every due database DEK.
// KEKs go first so later DEK rotations wrap under the new KEK version.
// Items run in deterministic order, each with an idempotency key derived
// from its identity and target generation. The first failure stops the pass
// and fails closed: completed facts are returned alongside the error, and a
// retry re-runs the remaining items through hook idempotency.
func (d *DataKeyRotation) Tick(ctx context.Context) ([]DataKeyRotationFact, error) {
	if d == nil || d.deks == nil || d.keks == nil || d.source == nil {
		return nil, errors.New("delivery: data-key rotation is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := d.now().UTC()
	if now.IsZero() {
		return nil, errors.New("delivery: data-key rotation clock is invalid")
	}
	facts := make([]DataKeyRotationFact, 0)

	keks, err := d.source.KEKsDue(ctx)
	if err != nil {
		return facts, &DataKeyRotationError{Kind: "kek", Stage: "source", Code: "due_keys_unavailable"}
	}
	sort.Slice(keks, func(i, j int) bool { return keks[i].Region < keks[j].Region })
	for _, item := range keks {
		if strings.TrimSpace(item.Region) == "" || item.Generation == 0 || item.Generation == ^uint64(0) {
			return facts, &DataKeyRotationError{Kind: "kek", Region: item.Region, Stage: "source", Code: "item_invalid"}
		}
		receipt, err := d.keks.RotateKEK(ctx, item.Region, kekIdempotencyKey(item.Region, item.Generation+1))
		if err != nil {
			return facts, &DataKeyRotationError{Kind: "kek", Region: item.Region, Stage: "rotate", Code: "rotation_failed"}
		}
		if receipt.Region != item.Region || receipt.Generation != item.Generation+1 {
			return facts, &DataKeyRotationError{Kind: "kek", Region: item.Region, Stage: "verify", Code: "receipt_mismatch"}
		}
		at := receipt.At
		if at.IsZero() {
			at = now
		}
		facts = append(facts, DataKeyRotationFact{Kind: "kek", Region: receipt.Region, Generation: receipt.Generation, At: at})
	}

	deks, err := d.source.DEKsDue(ctx)
	if err != nil {
		return facts, &DataKeyRotationError{Kind: "dek", Stage: "source", Code: "due_keys_unavailable"}
	}
	sort.Slice(deks, func(i, j int) bool { return deks[i].DatabaseID < deks[j].DatabaseID })
	for _, item := range deks {
		if strings.TrimSpace(item.DatabaseID) == "" || item.Generation == 0 || item.Generation == ^uint64(0) {
			return facts, &DataKeyRotationError{Kind: "dek", DatabaseID: item.DatabaseID, Stage: "source", Code: "item_invalid"}
		}
		receipt, err := d.deks.RotateDEK(ctx, item.DatabaseID, dekIdempotencyKey(item.DatabaseID, item.Generation+1))
		if err != nil {
			return facts, &DataKeyRotationError{Kind: "dek", DatabaseID: item.DatabaseID, Stage: "rotate", Code: "rotation_failed"}
		}
		if receipt.DatabaseID != item.DatabaseID || receipt.Generation != item.Generation+1 || strings.TrimSpace(receipt.WrappedUnder) == "" {
			return facts, &DataKeyRotationError{Kind: "dek", DatabaseID: item.DatabaseID, Stage: "verify", Code: "receipt_mismatch"}
		}
		at := receipt.At
		if at.IsZero() {
			at = now
		}
		facts = append(facts, DataKeyRotationFact{Kind: "dek", DatabaseID: receipt.DatabaseID, Generation: receipt.Generation, At: at})
	}
	return facts, nil
}

// kekIdempotencyKey and dekIdempotencyKey derive stable operation keys so a
// crashed pass retries the exact same provider operation.
func kekIdempotencyKey(region string, generation uint64) string {
	return "kek-rotation/" + region + "/" + strconv.FormatUint(generation, 10)
}

func dekIdempotencyKey(databaseID string, generation uint64) string {
	return "dek-rotation/" + databaseID + "/" + strconv.FormatUint(generation, 10)
}

// DataKeyRotationError reports a bounded, redacted failure. Provider errors
// are deliberately dropped: a Vault response can echo ciphertext, key
// versions, or request details that must not reach logs or audit trails.
type DataKeyRotationError struct {
	Kind       string // "kek" or "dek"
	Region     string
	DatabaseID string
	Stage      string // "source", "rotate", or "verify"
	Code       string
}

func (e *DataKeyRotationError) Error() string {
	var builder strings.Builder
	builder.WriteString("delivery: data-key rotation failed: ")
	builder.WriteString(e.Kind)
	if e.Region != "" {
		builder.WriteString(" region=")
		builder.WriteString(e.Region)
	}
	if e.DatabaseID != "" {
		builder.WriteString(" database=")
		builder.WriteString(e.DatabaseID)
	}
	builder.WriteString(" stage=")
	builder.WriteString(e.Stage)
	builder.WriteString(" code=")
	builder.WriteString(e.Code)
	return builder.String()
}
