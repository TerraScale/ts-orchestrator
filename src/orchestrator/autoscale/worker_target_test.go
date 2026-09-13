package autoscale

import "testing"

func TestFixedWorkerTargetRequiresTwoHostFloor(t *testing.T) {
	target, err := FixedWorkerTarget("gru", 2)
	if err != nil {
		t.Fatal(err)
	}
	if target.Workers != 2 || target.MinWorkers != 2 || target.MaxWorkers != 2 || target.OperationID != "" {
		t.Fatalf("target = %+v", target)
	}
}

func TestWorkerTargetRejectsMemberLikeScaleDown(t *testing.T) {
	if _, err := FixedWorkerTarget("gru", 1); err == nil {
		t.Fatal("one worker target accepted")
	}
	if err := (WorkerTarget{Region: "gru", Workers: 2, MinWorkers: 2, MaxWorkers: 3}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (WorkerTarget{Region: "GRU", Workers: 2, MinWorkers: 2, MaxWorkers: 2}).Validate(); err == nil {
		t.Fatal("non-canonical region accepted")
	}
}
