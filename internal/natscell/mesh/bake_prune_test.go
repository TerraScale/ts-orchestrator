package mesh

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// gru kept 1044 bake records (2026-10-28). Pruning keeps each service's
// newest five, a desired generation and a running bake, and nothing else.
func TestPruneBakesKeepsNewestDesiredAndRunning(t *testing.T) {
	dir := t.TempDir()
	n := &Node{cfg: config{dir: dir}, desired: map[string]desiredState{"ts-auth": {Operator: &Entry{Generation: 2}}}}
	for generation := int64(1); generation <= 20; generation++ {
		for _, name := range []string{"ts-auth", "whoami"} {
			if err := os.WriteFile(n.bakePath(name, generation), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "desired.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.baking = map[string]chan struct{}{n.bakePath("whoami", 3): make(chan struct{})}
	n.pruneBakes()
	left, _ := filepath.Glob(filepath.Join(dir, "bake-*.json"))
	var names []string
	for _, path := range left {
		names = append(names, filepath.Base(path))
	}
	var want []string
	for _, kept := range []struct {
		name        string
		generations []int64
	}{{"ts-auth", []int64{2, 16, 17, 18, 19, 20}}, {"whoami", []int64{3, 16, 17, 18, 19, 20}}} {
		for _, generation := range kept.generations {
			want = append(want, fmt.Sprintf("bake-%s-%d.json", kept.name, generation))
		}
	}
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("kept %v, want %v", names, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "desired.json")); err != nil {
		t.Fatal("pruning touched another file")
	}
}
