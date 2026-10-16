package kvsnapshot

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	planBucket     = "TS_KV_RESTORE"
	restorePlanKey = "plan"
	stateRunning   = "running"
	stateComplete  = "complete"
	maxPlanBytes   = 64 << 10
)

// restorePlan is the cell's one restore decision, kept in its own JetStream
// store, so it is lost exactly when the buckets are. The first controller to
// boot without a plan decides which buckets to restore: in a cell whose
// authority log was never written, those with a snapshot whose stream is
// missing or was never written. Every controller
// that boots while the plan runs finishes it before opening any store, and a
// complete plan is never acted on again, so a later boot never restores over
// live values.
type restorePlan struct {
	Version   int       `json:"version"`
	State     string    `json:"state"`
	Buckets   []string  `json:"buckets"`
	DecidedAt time.Time `json:"decided_at"`
}

// RestoreReport describes one restore pass.
type RestoreReport struct {
	// Buckets are the buckets in the cell's plan.
	Buckets []string
	// Written counts values this pass wrote; Kept counts values left alone
	// because their key already had history.
	Written, Kept int
}

func openPlans(ctx context.Context, js jetstream.JetStream, replicas int) (jetstream.KeyValue, error) {
	plans, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: planBucket,
		Description: "Regional KV snapshot restore decision", History: 1, MaxValueSize: maxPlanBytes,
		Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return nil, fmt.Errorf("open kv restore plan: %w", err)
	}
	return plans, nil
}

func readPlan(ctx context.Context, plans jetstream.KeyValue) (restorePlan, uint64, bool, error) {
	entry, err := plans.Get(ctx, restorePlanKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return restorePlan{}, 0, false, nil
	}
	if err != nil {
		return restorePlan{}, 0, false, fmt.Errorf("read kv restore plan: %w", err)
	}
	var plan restorePlan
	if err := protocol.DecodeStrict(entry.Value(), &plan, maxPlanBytes); err != nil {
		return restorePlan{}, 0, false, fmt.Errorf("decode kv restore plan: %w", err)
	}
	if plan.Version != documentVersion || plan.State != stateRunning && plan.State != stateComplete ||
		plan.DecidedAt.IsZero() || validBuckets(plan.Buckets) != nil {
		return restorePlan{}, 0, false, errors.New("kv restore plan is invalid")
	}
	return plan, entry.Revision(), true, nil
}

// RestoreComplete reports whether this cell already completed its restore.
// It needs no Object Storage, so an ordinary controller restart stays
// independent of OCI.
func RestoreComplete(ctx context.Context, js jetstream.JetStream, replicas int) (bool, error) {
	plans, err := openPlans(ctx, js, replicas)
	if err != nil {
		return false, err
	}
	plan, _, found, err := readPlan(ctx, plans)
	return found && plan.State == stateComplete, err
}

// Restore runs the cell's restore plan, deciding it first when no
// controller has. It must finish before any owner opens a bucket. A value is
// written only if its key never had any revision in this cell, so a
// concurrent restorer or a live update or delete always wins.
func Restore(ctx context.Context, js jetstream.JetStream, objects *Objects, buckets []string, replicas int,
	now time.Time,
) (RestoreReport, error) {
	if err := validBuckets(buckets); err != nil {
		return RestoreReport{}, err
	}
	plans, err := openPlans(ctx, js, replicas)
	if err != nil {
		return RestoreReport{}, err
	}
	plan, revision, found, err := readPlan(ctx, plans)
	if err != nil || found && plan.State == stateComplete {
		return RestoreReport{}, err
	}
	documents := map[string]Document{}
	if !found {
		plan = restorePlan{Version: documentVersion, State: stateRunning, DecidedAt: now.UTC()}
		// A cell whose authority log already holds records kept its
		// JetStream state, so it is live and restores nothing; it reads no
		// OCI, and enabling snapshots on a live cell cannot stop its boot.
		fresh, err := neverWritten(ctx, js, authority.ControlStreamName)
		if err != nil {
			return RestoreReport{}, err
		}
		if !fresh {
			buckets = nil
		}
		for _, bucket := range buckets {
			empty, err := neverWritten(ctx, js, "KV_"+bucket)
			if err != nil {
				return RestoreReport{}, err
			}
			if !empty {
				continue
			}
			document, _, ok, err := objects.Get(ctx, bucket)
			if err != nil {
				return RestoreReport{}, err
			}
			if ok {
				plan.Buckets = append(plan.Buckets, bucket)
				documents[bucket] = document
			}
		}
		data, err := protocol.EncodeJSON(plan)
		if err != nil {
			return RestoreReport{}, err
		}
		revision, err = plans.Create(ctx, restorePlanKey, data)
		if errors.Is(err, jetstream.ErrKeyExists) {
			// Another controller decided first; follow its plan.
			plan, revision, found, err = readPlan(ctx, plans)
			if err == nil && !found {
				err = errors.New("kv restore plan vanished after a conflicting create")
			}
			if err != nil || plan.State == stateComplete {
				return RestoreReport{}, err
			}
			documents = map[string]Document{}
		} else if err != nil {
			return RestoreReport{}, fmt.Errorf("record kv restore plan: %w", err)
		}
	}
	report := RestoreReport{Buckets: plan.Buckets}
	for _, bucket := range plan.Buckets {
		document, ok := documents[bucket]
		if !ok {
			if document, _, ok, err = objects.Get(ctx, bucket); err != nil {
				return report, err
			}
			if !ok {
				return report, fmt.Errorf("planned kv snapshot of %s is missing", bucket)
			}
		}
		written, kept, err := restoreBucket(ctx, js, document, replicas)
		report.Written += written
		report.Kept += kept
		if err != nil {
			return report, err
		}
	}
	plan.State = stateComplete
	data, err := protocol.EncodeJSON(plan)
	if err != nil {
		return report, err
	}
	if _, err := plans.Update(ctx, restorePlanKey, data, revision); err != nil {
		// A plan only moves from running to complete, so a lost race is fine
		// once the plan reads complete.
		current, _, found, readErr := readPlan(ctx, plans)
		if readErr != nil || !found || current.State != stateComplete {
			return report, fmt.Errorf("complete kv restore plan: %w", errors.Join(err, readErr))
		}
	}
	return report, nil
}

// neverWritten asks the stream leader, through a fresh STREAM.INFO request
// (CachedInfo returns that reply), whether the stream ever stored a message.
func neverWritten(ctx context.Context, js jetstream.JetStream, name string) (bool, error) {
	stream, err := js.Stream(ctx, name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", name, err)
	}
	return stream.CachedInfo().State.LastSeq == 0, nil
}

func restoreBucket(ctx context.Context, js jetstream.JetStream, document Document, replicas int) (int, int, error) {
	kv, err := js.KeyValue(ctx, document.Bucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		kv, err = js.CreateKeyValue(ctx, document.Config.keyValueConfig(document.Bucket, replicas))
		if errors.Is(err, jetstream.ErrBucketExists) {
			kv, err = js.KeyValue(ctx, document.Bucket)
		}
	}
	if err != nil {
		return 0, 0, fmt.Errorf("open %s for restore: %w", document.Bucket, err)
	}
	written, kept := 0, 0
	for _, entry := range document.Entries {
		// Revision 0 requires a key with no revision at all, not even a
		// delete marker, so a deleted key is never brought back.
		_, err := kv.Update(ctx, entry.Key, entry.Value, 0)
		switch {
		case err == nil:
			written++
		case errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch):
			kept++
		default:
			return written, kept, fmt.Errorf("restore %s: %w", document.Bucket, err)
		}
	}
	return written, kept, nil
}
