package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQualificationCleanupPreservesResourcesUntilPendingCommandStops(t *testing.T) {
	for _, profile := range []string{"generic", "production"} {
		t.Run(profile, func(t *testing.T) {
			process := fixtureProcess()
			live := true
			process.hooks.quiescent = func(int, time.Duration) error {
				if live {
					return errors.New("still has live members")
				}
				return nil
			}
			calls := 0
			command := func(context.Context, []string, CommandOptions) (CommandResult, error) {
				calls++
				if calls == 1 {
					return CommandResult{}, &PendingCommandError{Process: process, Err: context.Canceled}
				}
				return CommandResult{}, nil
			}
			var cleanup func() []string
			var pending func() []*Process
			var retained func()
			if profile == "generic" {
				l := nativeLab(t)
				l.Command = command
				l.Mounted = []string{filepath.Join(l.Root, "mount")}
				l.CreatedLinks, l.CreatedNFTTables = []string{"owned-bridge"}, []string{"owned-table"}
				_, e := l.cmd([]string{"mount"}, CommandOptions{})
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				cleanup = func() []string { return l.Cleanup(false) }
				pending = func() []*Process { return l.PendingCommands }
				retained = func() {
					requireEqual(t, len(l.Mounted), 1)
					requireEqual(t, len(l.CreatedLinks), 1)
					requireEqual(t, len(l.CreatedNFTTables), 1)
					for _, path := range []string{l.Images, l.Stage, l.Secrets} {
						if _, e := os.Stat(path); e != nil {
							t.Fatal("pending command lost resources", e)
						}
					}
				}
			} else {
				q := nativeProduction(t)
				q.Command = command
				q.Mounted, q.CreatedLinks = []string{filepath.Join(q.Root, "mount")}, []string{"owned-bridge"}
				q.CreatedTables = [][2]string{{"bridge", "owned-table"}}
				_, e := q.command([]string{"mount"}, CommandOptions{})
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				cleanup, pending = q.Cleanup, func() []*Process { return q.PendingCommands }
				retained = func() {
					requireEqual(t, len(q.Mounted), 1)
					requireEqual(t, len(q.CreatedLinks), 1)
					requireEqual(t, len(q.CreatedTables), 1)
				}
			}
			errs := cleanup()
			if len(errs) != 1 || !strings.Contains(errs[0], "not confirmed stopped") {
				t.Fatal(errs)
			}
			requireEqual(t, calls, 1)
			requireEqual(t, len(pending()), 1)
			if process.Reaped {
				t.Fatal("lost uncertain helper ownership")
			}
			retained()
			live = false
			if errs := cleanup(); len(errs) > 0 {
				t.Fatal(errs)
			}
			requireEqual(t, len(pending()), 0)
			requireEqual(t, process.Reaped, true)
			if calls <= 1 {
				t.Fatal("cleanup did not resume after helper stopped")
			}
		})
	}
}

func TestQualificationNetworkRetainsAmbiguousCreationOwnership(t *testing.T) {
	for _, profile := range []string{"generic", "production"} {
		t.Run(profile, func(t *testing.T) {
			command := func(_ context.Context, argv []string, _ CommandOptions) (CommandResult, error) {
				if strings.Join(argv, " ") == "ip link set lo up" {
					return CommandResult{}, nil
				}
				return CommandResult{}, context.Canceled
			}
			if profile == "generic" {
				l := nativeLab(t)
				l.Command = command
				requireError(t, l.Network(), "context canceled")
				requireEqual(t, l.CreatedLinks, []string{l.Bridge})
			} else {
				q := nativeProduction(t)
				q.Command = command
				q.sameNamespace = func() (bool, error) { return false, nil }
				requireError(t, q.Network(), "context canceled")
				requireEqual(t, q.CreatedLinks, []string{q.Bridge})
			}
		})
	}
}
