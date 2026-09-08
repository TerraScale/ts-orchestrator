package vmcontrolseed

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPersistentGRUReusesExactCredentialsAndRefusesDifferentInventory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "admission")
	guests := []Guest{{ID: "gru-member-1", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}}
	calls := 0
	create := func() (map[string]Material, error) { calls++; return GenerateGRU("durable-run", guests) }
	first, err := LoadOrCreateGRU(dir, "durable-run", guests, create)
	if err != nil {
		t.Fatal(err)
	}
	defer first[guests[0].ID].Clear()
	path := filepath.Join(dir, "initial-control.json")
	if err := os.Rename(path, path+".pending"); err != nil {
		t.Fatal(err)
	}
	next, err := LoadOrCreateGRU(dir, "durable-run", guests, create)
	if err != nil {
		t.Fatal(err)
	}
	defer next[guests[0].ID].Clear()
	if calls != 1 || first[guests[0].ID].Settings != next[guests[0].ID].Settings {
		t.Fatal("durable configuration reissued")
	}
	for path, want := range first[guests[0].ID].Files {
		if !bytes.Equal(want, next[guests[0].ID].Files[path]) {
			t.Fatal("durable credential changed")
		}
	}
	changed := slices.Clone(guests)
	changed[0].MembershipPublicKey = membershipPublic(t)
	if _, err := LoadOrCreateGRU(dir, "durable-run", changed, create); err == nil || calls != 1 {
		t.Fatal("different inventory regenerated initial material")
	}
	if _, err := LoadOrCreateGRU(dir, "foreign-run", guests, create); err == nil || calls != 1 {
		t.Fatal("different run reused initial material")
	}
}
