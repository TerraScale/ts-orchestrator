package candidatesync

import (
	"context"
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"testing"
)

func TestPrivateBrokerAccountIsolation(t *testing.T) {
	path := t.TempDir()
	b, err := startBroker(context.Background(), path, 16<<20, []preliminarytransfer.ObjectMapping{{Account: "GLOBAL", Stream: "SPEC"}, {Account: "REGIONAL", Stream: "EVENTS"}})
	if err != nil {
		t.Fatal(err)
	}
	b.close()
	if err := inspectTree(path, false); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error { t.Log(p); return e })
}
