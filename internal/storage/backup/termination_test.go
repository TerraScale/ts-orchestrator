package backup

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunnerRecognizesTerminatedPlacedVolumesWithoutCreatingBackups(t *testing.T) {
	for _, age := range []time.Duration{time.Hour, 31 * 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			provider := newFakeProvider(owned("backup", "AVAILABLE", TypeFull, age))
			provider.gone = map[string]bool{volume: true}
			report, err := runner(provider, &fakeFencer{snapshot: leader()}).RunOnce(t.Context())
			wantDeleted := 0
			if age >= orphanRetention {
				wantDeleted = 1
			}
			if err != nil || provider.creates != 0 || len(provider.deletes) != wantDeleted || len(report.Deleted) != wantDeleted {
				t.Fatalf("terminated placed volume: creates=%d deletes=%v report=%+v err=%v", provider.creates, provider.deletes, report, err)
			}
		})
	}
}

func TestRunnerProtectsPlacedVolumeAfterSourceObservationFailure(t *testing.T) {
	provider := newFakeProvider(owned("backup", "AVAILABLE", TypeFull, 31*24*time.Hour))
	provider.goneErr = map[string]error{volume: errors.New("OCI source unreadable")}
	runner := runner(provider, &fakeFencer{snapshot: leader()})
	runner.Volumes = func(context.Context) ([]string, error) { return []string{volume, "ocid1.volume.readable"}, nil }
	report, err := runner.RunOnce(t.Context())
	if err == nil || len(provider.deletes) != 0 || provider.goneReads[volume] != 1 || provider.creates != 1 || len(report.Created) != 1 {
		t.Fatalf("unreadable placed source: creates=%d deletes=%v reads=%v report=%+v err=%v", provider.creates, provider.deletes, provider.goneReads, report, err)
	}
}

func TestRunnerChecksYoungOrphanSourcesOnceIncludingFailures(t *testing.T) {
	for _, readErr := range []error{nil, errors.New("OCI source unreadable")} {
		provider := newFakeProvider(orphan("young-a", "removed", time.Hour), orphan("young-b", "removed", 2*time.Hour))
		provider.goneErr = map[string]error{"removed": readErr}
		runner := runner(provider, &fakeFencer{snapshot: leader()})
		runner.Volumes = func(context.Context) ([]string, error) { return nil, nil }
		report, err := runner.RunOnce(t.Context())
		if (err != nil) != (readErr != nil) || provider.goneReads["removed"] != 1 || len(provider.deletes) != 0 || len(report.Deleted) != 0 {
			t.Fatalf("young orphan observation: reads=%v deletes=%v report=%+v err=%v", provider.goneReads, provider.deletes, report, err)
		}
	}
}
