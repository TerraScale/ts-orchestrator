package attempt

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func smallAttempt(t *testing.T) *Attempt {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	wire := []byte(`{"workdir":"` + filepath.Join(dir, "work") + `","deployment_id":"0000000000F9PR1WNVDTEXS31Z","prefix":"bootstrap/a","tools":{}}`)
	if err := os.WriteFile(config, wire, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(t.Context(), config, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestResumePreservesHistoricalJSONBytes(t *testing.T) {
	a := smallAttempt(t)
	path := a.Path("retained.json")
	retained := []byte("{\n \"identity\": \"signed-before-migration\",\n \"generation\": 1\n}\n")
	if err := os.WriteFile(path, retained, 0600); err != nil {
		t.Fatal(err)
	}
	a.writeJSON(path, Object{"identity": "signed-before-migration", "generation": 1})
	got, err := os.ReadFile(path)
	if err != nil || a.Err() != nil || !bytes.Equal(got, retained) {
		t.Fatal(string(got), err, a.Err())
	}
	a.writeJSON(path, Object{"identity": "changed", "generation": 1})
	if a.Err() == nil {
		t.Fatal("accepted immutable record identity change")
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, retained) {
		t.Fatal("changed retained signed bytes")
	}
	{
		a := &Attempt{}
		dir, err := filepath.Abs(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		planPath := filepath.Join(dir, "founder-plan.json")
		selectionPath := filepath.Join(dir, "founder-selection.json")
		rejectedPath := filepath.Join(dir, "rejected-plan.json")
		plan := typed(a, Object{"seedSlot": "controller-a", "cell": "GRU", "schemaVersion": 1, "deploymentId": "d", "environment": "canary"}, &bootstrap.FounderPlan{})
		if a.err != nil {
			t.Fatal(a.err)
		}
		written, err := json.Marshal(plan, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := protocol.EncodeJSON(*plan)
		if err != nil || !bytes.Equal(written, canonical) || !bytes.HasPrefix(written, []byte(`{"schemaVersion":1,"deploymentId":"d","cell":"GRU"`)) {
			t.Fatalf("written %s, canonical %s, %v", written, canonical, err)
		}
		a.writeJSON(planPath, plan)
		planBytes, err := os.ReadFile(planPath)
		if a.err != nil || err != nil || !bytes.Equal(planBytes, written) || !bytes.Equal(planBytes, canonical) || !bytes.HasPrefix(planBytes, []byte(`{"schemaVersion":1,"deploymentId":"d","cell":"GRU"`)) {
			t.Fatalf("stored plan %s, written %s, canonical %s, %v %v", planBytes, written, canonical, a.err, err)
		}
		selection := typed(a, Object{"manifests": []any{Object{"sha256": "s", "slot": "controller-a"}}, "generation": 1, "schemaVersion": 1}, &bootstrapstart.FounderSelection{})
		written, _ = json.Marshal(selection, json.Deterministic(true))
		canonical, err = protocol.EncodeJSON(*selection)
		if a.err != nil || err != nil || !bytes.Equal(written, canonical) {
			t.Fatalf("selection %s, canonical %s, %v %v", written, canonical, a.err, err)
		}
		a.writeJSON(selectionPath, selection)
		selectionBytes, err := os.ReadFile(selectionPath)
		if a.err != nil || err != nil || !bytes.Equal(selectionBytes, written) || !bytes.Equal(selectionBytes, canonical) {
			t.Fatalf("stored selection %s, written %s, canonical %s, %v %v", selectionBytes, written, canonical, a.err, err)
		}
		resumed := &Attempt{}
		resumed.writeJSON(planPath, typed(resumed, resumed.read(planPath), &bootstrap.FounderPlan{}))
		resumed.writeJSON(selectionPath, typed(resumed, resumed.read(selectionPath), &bootstrapstart.FounderSelection{}))
		if resumed.Err() != nil {
			t.Fatal(resumed.Err())
		}
		planBefore, err := os.ReadFile(planPath)
		if err != nil || !bytes.Equal(planBefore, planBytes) {
			t.Fatalf("plan before rejection %s, want %s, %v", planBefore, planBytes, err)
		}
		selectionBefore, err := os.ReadFile(selectionPath)
		if err != nil || !bytes.Equal(selectionBefore, selectionBytes) {
			t.Fatalf("selection before rejection %s, want %s, %v", selectionBefore, selectionBytes, err)
		}
		if _, err := os.Stat(rejectedPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected path already exists or cannot be checked: %v", err)
		}
		rejected := typed(a, Object{"unknown": 1}, &bootstrap.FounderPlan{})
		if a.err == nil {
			t.Fatal("an unknown member was dropped instead of refused")
		}
		a.writeJSON(rejectedPath, rejected)
		if _, err := os.Stat(rejectedPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected candidate created a file or cannot be checked: %v", err)
		}
		planAfter, err := os.ReadFile(planPath)
		if err != nil || !bytes.Equal(planAfter, planBefore) {
			t.Fatalf("plan after rejection %s, want %s, %v", planAfter, planBefore, err)
		}
		selectionAfter, err := os.ReadFile(selectionPath)
		if err != nil || !bytes.Equal(selectionAfter, selectionBefore) {
			t.Fatalf("selection after rejection %s, want %s, %v", selectionAfter, selectionBefore, err)
		}
	}

}
func TestRootMaterialCleanupRunsAfterCancellationAndFailure(t *testing.T) {
	a := smallAttempt(t)
	ctx, cancel := context.WithCancel(t.Context())
	a.ctx = ctx
	sentinel := errors.New("copy failed")
	cleaned := false
	a.Runner = func(ctx context.Context, c Command) (string, error) {
		switch {
		case slices.Contains(c.Args, "mktemp"):
			return "/run/material-copy\n", nil
		case slices.Contains(c.Args, "cp"):
			cancel()
			return "", sentinel
		case slices.Contains(c.Args, "rm"):
			if ctx.Err() != nil {
				t.Fatal("cleanup reused canceled attempt context")
			}
			if !slices.Contains(c.Args, "/run/material-copy") {
				t.Fatal(c.Args)
			}
			cleaned = true
			return "", nil
		}
		t.Fatal(c.Args)
		return "", nil
	}
	a.rootMaterial(func(string) { t.Fatal("used material after failed copy") })
	if !cleaned || !errors.Is(a.Err(), sentinel) {
		t.Fatal(cleaned, a.Err())
	}
}
