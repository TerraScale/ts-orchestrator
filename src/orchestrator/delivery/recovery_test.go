package delivery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type recoveryObserverControl struct {
	mu          sync.Mutex
	state       HostReleaseState
	converges   []string
	fail        bool
	requireAuth bool
}

func (c *recoveryObserverControl) Cordon(context.Context, string, bool) error { return nil }

func (c *recoveryObserverControl) DrainStatus(context.Context, string) (DrainReport, error) {
	return DrainReport{Cordoned: true, Drained: true}, nil
}

func (c *recoveryObserverControl) Converge(_ context.Context, host string, plan []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("recovery converge failed")
	}
	c.converges = append(c.converges, host+":"+string(plan))
	return nil
}

func (c *recoveryObserverControl) ObserveRelease(ctx context.Context, host string) (HostReleaseState, error) {
	if host == "" {
		return HostReleaseState{}, errors.New("host is required")
	}
	if c.requireAuth {
		if authenticated, _ := ctx.Value(recoveryAuthContextKey{}).(bool); !authenticated {
			return HostReleaseState{}, errors.New("release observation is unauthenticated")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, nil
}

func (c *recoveryObserverControl) convergeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.converges)
}

type recoveryAuthContextKey struct{}

func recoveryRollout(t *testing.T, control *recoveryObserverControl) *Rollout {
	t.Helper()
	r, err := NewRollout(RolloutConfig{
		Spec: estate.Default(),
		Hosts: fakeInventory{hosts: map[string][]string{
			"gru": {"member-1"}, "sfo": {"member-2"}, "fra": {"member-3"},
		}},
		Control: control,
	})
	if err != nil {
		t.Fatalf("build rollout: %v", err)
	}
	return r
}

func recoveryOperation(t *testing.T, request *Request, signature []byte, progress RolloutHostProgress) *Operation {
	t.Helper()
	now := time.Unix(1_000, 0).UTC()
	j := NewJournal()
	j.clock = func() time.Time { return now }
	lease := OperationLease{OwnerID: "crashed-owner", TTL: time.Minute, Generation: 1}
	operation, exists, err := j.Begin(request, lease)
	if err != nil || exists {
		t.Fatalf("begin operation: exists=%v err=%v", exists, err)
	}
	if err := j.RecordReleaseSignature(request.OperationID, operation.RequestDigest, lease, signature); err != nil {
		t.Fatalf("record release signature: %v", err)
	}
	if err := j.RecordRollout(request.OperationID, operation.RequestDigest, lease, progress.Host, progress.PriorDigest, progress.PriorManifestDigest, progress.CandidateDigest, progress.Mutated, progress.Completed); err != nil {
		t.Fatalf("record host ledger: %v", err)
	}
	j.clock = func() time.Time { return now.Add(time.Hour) }
	recovered, _, err := j.GetWithError(request.OperationID)
	if err != nil {
		t.Fatalf("read operation: %v", err)
	}
	if string(recovered.ReleaseSignature) != string(signature) {
		t.Fatalf("persisted release signature changed")
	}
	return recovered
}

func TestRolloutRecoverUsesSignedHostLedgerAndRetriesUnresolvedState(t *testing.T) {
	request, fetcher, trust, body := testRelease(t, nil)
	artifact, err := verifyArtifact(context.Background(), fetcher, trust, request)
	if err != nil {
		t.Fatalf("verify exact release: %v", err)
	}
	if string(artifact.Body) != string(body) || len(artifact.Signature) == 0 {
		t.Fatalf("verified artifact lost exact signed release")
	}

	prior := HostReleaseState{ArtifactDigest: request.Rollback.ArtifactDigest, ManifestDigest: request.Rollback.ManifestDigest}
	candidate := HostReleaseState{ArtifactDigest: request.Artifact.Digest, ManifestDigest: request.Artifact.ManifestDigest}
	progress := RolloutHostProgress{Host: "member-1", PriorDigest: prior.ArtifactDigest, PriorManifestDigest: prior.ManifestDigest, CandidateDigest: candidate.ArtifactDigest, Mutated: true, Completed: false}

	t.Run("pre-effect", func(t *testing.T) {
		control := &recoveryObserverControl{state: prior}
		rollout := recoveryRollout(t, control)
		p := progress
		p.Mutated = false
		op := recoveryOperation(t, request, artifact.Signature, p)
		rollback, err := rollout.Recover(context.WithValue(context.Background(), recoveryAuthContextKey{}, true), op.Request, artifact, op.Rollout)
		if err != nil || rollback.Status != RollbackSucceeded || control.convergeCount() != 0 {
			t.Fatalf("pre-effect recovery: rollback=%+v err=%v converges=%d", rollback, err, control.convergeCount())
		}
	})

	t.Run("after-effect-before-ack", func(t *testing.T) {
		control := &recoveryObserverControl{state: candidate}
		rollout := recoveryRollout(t, control)
		op := recoveryOperation(t, request, artifact.Signature, progress)
		rollback, err := rollout.Recover(context.WithValue(context.Background(), recoveryAuthContextKey{}, true), op.Request, artifact, op.Rollout)
		if err != nil || rollback.Status != RollbackSucceeded || control.convergeCount() != 1 {
			t.Fatalf("post-effect recovery: rollback=%+v err=%v converges=%d", rollback, err, control.convergeCount())
		}
	})

	t.Run("unrecognized-remains-retryable", func(t *testing.T) {
		control := &recoveryObserverControl{state: HostReleaseState{ArtifactDigest: "sha256:unknown", ManifestDigest: "sha256:unknown"}, fail: true}
		rollout := recoveryRollout(t, control)
		op := recoveryOperation(t, request, artifact.Signature, progress)
		ctx := context.WithValue(context.Background(), recoveryAuthContextKey{}, true)
		if _, err := rollout.Recover(ctx, op.Request, artifact, op.Rollout); err == nil {
			t.Fatal("unrecognized release was accepted")
		}
		if control.convergeCount() != 0 {
			t.Fatal("unrecognized release triggered rollback")
		}
		control.state = candidate
		control.fail = true
		if _, err := rollout.Recover(ctx, op.Request, artifact, op.Rollout); err == nil {
			t.Fatal("failed rollback was reported successful")
		}
		control.fail = false
		rollback, err := rollout.Recover(ctx, op.Request, artifact, op.Rollout)
		if err != nil || rollback.Status != RollbackSucceeded || control.convergeCount() != 1 {
			t.Fatalf("retry recovery: rollback=%+v err=%v converges=%d", rollback, err, control.convergeCount())
		}
	})
}
