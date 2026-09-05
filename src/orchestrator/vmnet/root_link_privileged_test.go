package vmnet

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRootLinkCleanupWithRetainedNamespace(t *testing.T) {
	if os.Getenv("TS_VMNET_ROOT_LINK_TEST") != "1" {
		t.Skip("set TS_VMNET_ROOT_LINK_TEST=1 with qualification privileges")
	}
	tools, err := DiscoverHostTools()
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	digest := sha256.Sum256([]byte(t.TempDir()))
	config.RunID = fmt.Sprintf("%x", digest[:16])
	config.Tools = tools
	config.Regions = config.Regions[:1]
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := plan.Cleanup.Run(cleanupCtx, runner); err != nil {
			t.Errorf("fixture cleanup: %v", err)
		}
	}()
	if err := plan.ApplyWithJournal(ctx, runner, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	observed, err := runner.observeRootLink(ctx, plan.Uplinks[0].RootDevice)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("root link identity: %+v expected address=%s", observed, plan.Cleanup.RootLinks[0].Address)
	// Holding this fd retains the kernel namespace even after its name is
	// unmounted. Root peer deletion must work without waiting for the fd.
	namespace, err := os.Open(plan.Regions[0].NamespacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if err := runner.Run(ctx, tools.IP, []string{"netns", "del", plan.Regions[0].Namespace}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/sys/class/net", plan.Uplinks[0].RootDevice)
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture did not retain the root peer: %v", err)
	}
	if err := plan.Cleanup.Run(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("root peer survived explicit cleanup: %v", err)
	}
	if _, err := namespace.Stat(); err != nil {
		t.Fatalf("retained namespace was prematurely released: %v", err)
	}
}
