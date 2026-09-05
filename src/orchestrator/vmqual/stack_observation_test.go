package vmqual

import (
	"path/filepath"
	"testing"
)

func TestStackSnapshotsDoNotExposeMutableTopology(t *testing.T) {
	stack, err := NewStack(StackConfig{VMFactory: &smokeFakeFactory{}, Network: &smokeFakeNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	original := stack.Guests()[0]
	view := stack.Snapshot()
	view.Guests[0].ID = "caller-replacement"
	view.VMs[original.ID] = &smokeFakeVM{}
	config := stack.Config()
	config.Guests[0].ID = "caller-config-replacement"
	again := stack.Snapshot()
	if again.Guests[0] != original || len(again.VMs) != 0 || stack.Config().Guests[0] != original {
		t.Fatal("observation exposed mutable stack topology")
	}
	if err := stack.ReleaseCleanupProbeJournal(); err == nil {
		t.Fatal("normal stack abandoned its journal through fault API")
	}
}

func TestCleanupProbeKeepsBaselineTopologyAndOwnershipValidation(t *testing.T) {
	root := t.TempDir()
	config := StackConfig{Guests: LaunchGuests(DefaultMemoryMiB)[:1], VMFactory: &smokeFakeFactory{}, Network: &smokeFakeNetwork{}, ResourceRoot: root, StateRoot: filepath.Join(root, "state"), JournalPath: filepath.Join(root, "journal.json")}
	if _, err := NewStack(config); err == nil {
		t.Fatal("baseline accepted a one-guest topology")
	}
	if _, err := NewCleanupProbeStack(config); err != nil {
		t.Fatal(err)
	}
	config.Guests[0].VCPU = 2
	if _, err := NewCleanupProbeStack(config); err == nil {
		t.Fatal("probe bypassed guest resource validation")
	}
	config.Guests[0].VCPU = 1
	config.ResourceRoot = ""
	if _, err := NewCleanupProbeStack(config); err == nil {
		t.Fatal("probe accepted missing ownership root")
	}
}
