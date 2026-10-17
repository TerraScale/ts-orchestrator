package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestNodeComputeMirrorRequiresOriginalAuthorityAndImmutableOutcome(t *testing.T) {
	now := time.Now().UTC()
	original := nodeOp{ID: entityid.New(), Op: nodeOpReboot, RequestSHA256: strings.Repeat("a", 64)}
	receipt := rootoci.NodeOperationReceipt{OperationID: original.ID, RequestSHA256: original.RequestSHA256,
		InstanceID: "ocid1.instance.original", Phase: "complete", Session: "original-session",
		ActedAt: now.Add(-time.Second), ObservedAt: now, ExpiresAt: now.Add(time.Second)}
	deadline := now.Add(2 * time.Second)
	op := original
	if err := mirrorNodeComputeReceipt(&op, receipt, deadline, now); err != nil || op.Instance != receipt.InstanceID || !op.ActedAt.Equal(receipt.ActedAt) || op.Session != receipt.Session {
		t.Fatalf("original outcome not mirrored: %+v %v", op, err)
	}
	for _, change := range []func(*rootoci.NodeOperationReceipt){
		func(r *rootoci.NodeOperationReceipt) { r.OperationID = entityid.New() },
		func(r *rootoci.NodeOperationReceipt) { r.RequestSHA256 = strings.Repeat("b", 64) },
		func(r *rootoci.NodeOperationReceipt) { r.InstanceID = "ocid1.instance.successor" },
		func(r *rootoci.NodeOperationReceipt) { r.Session = "successor-session" },
		func(r *rootoci.NodeOperationReceipt) { r.ActedAt = now },
		func(r *rootoci.NodeOperationReceipt) { r.ExpiresAt = deadline.Add(time.Second) },
	} {
		changed := receipt
		change(&changed)
		before := op
		if err := mirrorNodeComputeReceipt(&op, changed, deadline, now); err == nil || op != before {
			t.Fatalf("successor receipt changed original progress: %+v %v", op, err)
		}
	}
}

func TestNodeComputePartialOutcomeCannotAdvanceReadiness(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		phase string
		err   error
	}{{"pending", rootoci.ErrPending}, {"ambiguous", rootoci.ErrOutcomeUnknown}} {
		op := nodeOp{ID: entityid.New(), Op: nodeOpRetire, RequestSHA256: strings.Repeat("a", 64)}
		receipt := rootoci.NodeOperationReceipt{OperationID: op.ID, RequestSHA256: op.RequestSHA256,
			InstanceID: "ocid1.instance.original", BackupID: "ocid1.bootvolumebackup.original", Phase: test.phase,
			ActedAt: now.Add(-time.Second), ObservedAt: now, ExpiresAt: now.Add(time.Second)}
		if err := mirrorNodeComputeReceipt(&op, receipt, receipt.ExpiresAt, now); !errors.Is(err, test.err) ||
			!op.ActedAt.IsZero() || op.Backup != receipt.BackupID || op.Instance != receipt.InstanceID {
			t.Fatalf("%s advanced readiness or discarded protected partial outcome: %+v %v", test.phase, op, err)
		}
		receipt.Phase = "complete"
		if err := mirrorNodeComputeReceipt(&op, receipt, receipt.ExpiresAt, now); err != nil || op.ActedAt.IsZero() {
			t.Fatalf("protected completion not mirrored: %+v %v", op, err)
		}
	}
}

func TestNodeRetireCompletionRequiresProtectedBackup(t *testing.T) {
	now := time.Now().UTC()
	op := nodeOp{ID: entityid.New(), Op: nodeOpRetire, RequestSHA256: strings.Repeat("a", 64)}
	receipt := rootoci.NodeOperationReceipt{OperationID: op.ID, RequestSHA256: op.RequestSHA256,
		InstanceID: "ocid1.instance.original", Phase: "complete", ActedAt: now, ObservedAt: now, ExpiresAt: now.Add(time.Second)}
	if err := mirrorNodeComputeReceipt(&op, receipt, receipt.ExpiresAt, now); err == nil || !op.ActedAt.IsZero() {
		t.Fatalf("retirement completed without backup: %+v %v", op, err)
	}
}
