package vmqualsuite

import (
	"context"
	"net/http"
	"testing"
)

func TestRunReconcileContractUsesLoopAndProviderReadback(t *testing.T) {
	endpoints, err := NewLocalProviderEndpoints(LocalProviderConfig{StateRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("start local providers: %v", err)
	}
	t.Cleanup(func() {
		if err := endpoints.Close(); err != nil {
			t.Errorf("close local providers: %v", err)
		}
	})

	result, err := RunReconcileContract(t.Context(), endpoints, &http.Client{})
	if err != nil {
		t.Fatalf("run reconcile contract: %v", err)
	}
	if result.DesiredRecord.Name != reconcileContractDesiredName || result.DesiredRecord.Content != "192.0.2.44" || !result.DesiredRecord.Proxied {
		t.Fatalf("desired provider record = %+v", result.DesiredRecord)
	}
	if result.UnownedRecord.Name != reconcileContractForeignName || result.UnownedRecord.Content != "198.51.100.77" || result.UnownedRecord.Proxied {
		t.Fatalf("unowned provider record = %+v", result.UnownedRecord)
	}
	if result.InitialPlan.Creates != 1 || result.InitialPlan.Updates != 0 || result.InitialPlan.Deletes != 1 {
		t.Fatalf("initial plan = %+v", result.InitialPlan)
	}
	if result.EventualPlan.Creates != 0 || result.EventualPlan.Updates != 0 || result.EventualPlan.Deletes != 1 {
		t.Fatalf("eventual plan = %+v", result.EventualPlan)
	}
	if result.MutableDriftPlan.Creates != 0 || result.MutableDriftPlan.Updates != 1 || result.MutableDriftPlan.Deletes != 1 {
		t.Fatalf("mutable-drift plan = %+v", result.MutableDriftPlan)
	}
	if result.FinalPlan.Creates != 0 || result.FinalPlan.Updates != 0 || result.FinalPlan.Deletes != 1 {
		t.Fatalf("final plan = %+v", result.FinalPlan)
	}

	wantProviderCalls := ReconcileContractCalls{
		Observes:          6,
		ApplyAttempts:     3,
		RetryableFailures: 1,
		Creates:           1,
		Updates:           1,
	}
	if result.ProviderCalls != wantProviderCalls {
		t.Fatalf("provider calls = %+v, want %+v", result.ProviderCalls, wantProviderCalls)
	}
	if result.HTTPCalls.Creates != 2 || result.HTTPCalls.Updates != 2 || result.HTTPCalls.Deletes != 0 || result.HTTPCalls.Lists == 0 {
		t.Fatalf("HTTP calls = %+v", result.HTTPCalls)
	}
	if result.SkippedUnownedDelete != 6 {
		t.Fatalf("skipped unowned deletes = %d, want 6", result.SkippedUnownedDelete)
	}
}

func TestRunReconcileContractRejectsMissingInputs(t *testing.T) {
	if _, err := RunReconcileContract(nil, nil, nil); err == nil {
		t.Fatal("nil context was accepted")
	}
	if _, err := RunReconcileContract(context.Background(), nil, nil); err == nil {
		t.Fatal("nil provider endpoint was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunReconcileContract(canceled, &LocalProviderEndpoints{}, nil); err == nil {
		t.Fatal("canceled context was accepted")
	}
}
