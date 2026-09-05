package vmnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootLinkCleanupRequiresExactIdentityAndObservedRemoval(t *testing.T) {
	for _, test := range []struct {
		name     string
		edit     func(*observedRootLink)
		succeeds bool
	}{
		{"owned", func(*observedRootLink) {}, true},
		{"foreign address", func(link *observedRootLink) { link.Address = "unrelated" }, false},
		{"foreign type", func(link *observedRootLink) { link.Info.Kind = "dummy" }, false},
		{"foreign name", func(link *observedRootLink) { link.Name = "eth0" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Plan(qualifiedConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			cleanup := plan.Cleanup.RootLinks[0]
			link := observedRootLink{Name: cleanup.Command.Args[3], Address: cleanup.Address, Index: 10}
			link.Info.Kind = "veth"
			test.edit(&link)
			body, err := json.Marshal([]observedRootLink{link})
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "deleted")
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
			script := fmt.Sprintf("if [ \"$1\" = '-j' ]; then\n if [ -f %s ]; then echo %s >&2; exit 1; fi\n printf '%%s\\n' %s\nelse\n : > %s\nfi", quote(marker), quote(fmt.Sprintf("Device %q does not exist.", cleanup.Command.Args[3])), quote(string(body)), quote(marker))
			writeIPTablesScript(t, plan.Tools.IP, script)
			runner, err := NewHostRunner(plan.Tools)
			if err != nil {
				t.Fatal(err)
			}
			err = runner.cleanupRootLink(context.Background(), cleanup)
			if (err == nil) != test.succeeds {
				t.Fatalf("succeeds=%v err=%v", test.succeeds, err)
			}
			_, markerErr := os.Stat(marker)
			if (markerErr == nil) != test.succeeds {
				t.Fatal("identity refusal mutated the observed link")
			}
			if test.succeeds {
				if err := runner.cleanupRootLink(context.Background(), cleanup); err != nil {
					t.Fatal(err)
				}
			} else if test.name != "foreign name" {
				if err := runner.checkRootLinkCollisions(context.Background(), []RootLinkCleanup{cleanup}); err == nil {
					t.Fatal("preexisting root device escaped collision refusal")
				}
			}
		})
	}
}

type refusingRootLinkRunner struct {
	fakeRunner
	refuse bool
}

func (r *refusingRootLinkRunner) cleanupRootLink(context.Context, RootLinkCleanup) error {
	if r.refuse {
		return errors.New("root link ownership mismatch")
	}
	return nil
}

func TestRootLinkCleanupRefusalRetainsAllocationLease(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &refusingRootLinkRunner{fakeRunner: fakeRunner{failAt: -1}, refuse: true}
	if err := plan.ApplyWithJournal(context.Background(), runner, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	if err := plan.Cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("root link failure reported cleanup success")
	}
	coordinator, unlock := lockRunCoordinator(plan.RunID)
	retained := coordinator.hostLease != nil && coordinator.cleanupRequired
	unlock()
	if !retained {
		t.Fatal("failed root cleanup released the allocation lease")
	}
	runner.refuse = false
	if err := plan.Cleanup.Run(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
}

func TestRootLinkJournalRejectsForeignOrMissingObligations(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*CleanupPlan){
		func(p *CleanupPlan) { p.RootLinks = p.RootLinks[1:] },
		func(p *CleanupPlan) { p.RootLinks[0].Address = "foreign" },
		func(p *CleanupPlan) { p.RootLinks[0].Command.Args[3] = "eth0" },
	} {
		cleanup := plan.Cleanup.copy()
		edit(&cleanup)
		runner := &fakeRunner{failAt: -1}
		if err := cleanup.Run(context.Background(), runner); err == nil {
			t.Fatal("foreign cleanup journal accepted")
		}
		if len(runner.commands) != 0 {
			t.Fatal("invalid journal changed host resources")
		}
	}
}
