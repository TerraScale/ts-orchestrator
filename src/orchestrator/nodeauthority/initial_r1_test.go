package nodeauthority

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"
)

type initialR1Fixture struct {
	store     *EpochStore
	directory string
	identity  InitialR1Identity
	uid       uint32
	guard     *InitialR1Guard
}

func initialR1Replacement() string {
	digest, err := hostmanifest.HostManifestSha256(hostmanifest.HostManifest{})
	if err != nil {
		panic(err)
	}
	return digest
}
func newInitialR1Fixture(t *testing.T) *initialR1Fixture {
	t.Helper()
	root := t.TempDir()
	private := filepath.Join(root, "private")
	public := filepath.Join(root, "public")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	s, err := NewEpochStore(private, "gru-one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	i := InitialR1Identity{Role: "seed", NodeID: "gru-one", GrantSHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), LaunchSHA256: strings.Repeat("c", 64), CandidateID: "global-controller-gru-one", StoreScopeSHA256: strings.Repeat("d", 64), IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err = s.AdmitBootstrap(i.GrantSHA256, i.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	g, err := newInitialR1Guard(public, i, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return &initialR1Fixture{s, public, i, uint32(os.Geteuid()), g}
}
func (f *initialR1Fixture) admit(ctx context.Context, fault func() error) error {
	return f.store.admitInitialR1(ctx, f.directory, f.identity, f.uid, fault)
}
func (f *initialR1Fixture) command(t *testing.T) CommandAuthorization {
	t.Helper()
	c := CommandAuthorization{NodeID: f.identity.NodeID, AuthorityID: "gru-regional", Epoch: 1, CandidateID: "gru-controller-one", LeaseID: "lease-one", ExpiresAt: time.Now().Add(time.Minute)}
	handoff, err := hostmanifest.NewApplyManifestCommand("retire-one", f.identity.ManifestSHA256, hostmanifest.HostManifest{})
	if err != nil {
		t.Fatal(err)
	}
	c.Command, err = json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Admit(c); err != nil {
		t.Fatal(err)
	}
	return c
}
func (f *initialR1Fixture) retire(ctx context.Context, c CommandAuthorization, fault func() error) error {
	return f.store.retireInitialR1(ctx, f.directory, f.identity, c, "retire-one", f.identity.ManifestSHA256, initialR1Replacement(), f.uid, fault)
}

func TestInitialR1BindingDurabilityAndRetirement(t *testing.T) {
	f := newInitialR1Fixture(t)
	ctx := t.Context()
	if err := f.guard.Check(ctx); err == nil {
		t.Fatal("missing state authorized")
	}
	fault := errors.New("directory sync interrupted")
	if err := f.admit(ctx, func() error { return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if err := f.admit(ctx, nil); err != nil {
		t.Fatalf("initial rename retry: %v", err)
	}
	if err := f.guard.Check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*InitialR1Identity){
		func(i *InitialR1Identity) { i.GrantSHA256 = strings.Repeat("f", 64) },
		func(i *InitialR1Identity) { i.ManifestSHA256 = strings.Repeat("f", 64) },
		func(i *InitialR1Identity) { i.LaunchSHA256 = strings.Repeat("f", 64) },
		func(i *InitialR1Identity) { i.StoreScopeSHA256 = strings.Repeat("f", 64) },
		func(i *InitialR1Identity) { i.NodeID = "gru-other" },
		func(i *InitialR1Identity) { i.CandidateID = "global-controller-gru-other" },
		func(i *InitialR1Identity) { i.ExpiresAt = i.ExpiresAt.Add(time.Minute) },
	} {
		i := f.identity
		alter(&i)
		g, err := newInitialR1Guard(f.directory, i, f.uid)
		if err == nil && g.Check(ctx) == nil {
			t.Fatal("changed identity authorized")
		}
	}
	c := f.command(t)
	if err := f.retire(ctx, c, func() error { return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if err := f.guard.Check(ctx); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatalf("retirement disappeared after interrupted sync: %v", err)
	}
	if err := f.retire(ctx, c, nil); err != nil {
		t.Fatalf("retirement retry: %v", err)
	}
	if err := f.store.AdmitRuntimeManifest(initialR1Replacement(), f.identity.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitRuntimeManifest(initialR1Replacement()); err != nil {
		t.Fatal(err)
	}
	if err := f.retire(ctx, c, nil); err != nil {
		t.Fatalf("retry after manifest predecessor committed: %v", err)
	}
	if err := f.admit(ctx, nil); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatalf("reinitialized retired grant: %v", err)
	}
	f.store.Close()
	reopened, err := NewEpochStore(filepath.Dir(f.store.path), f.identity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.store = reopened
	if err := f.retire(ctx, c, nil); err != nil {
		t.Fatalf("restart retry: %v", err)
	}
	if err := f.guard.Check(ctx); !errors.Is(err, ErrInitialR1Retired) {
		t.Fatal(err)
	}
}

func TestInitialR1InterruptedInitialPublicationRecoversOnlyPending(t *testing.T) {
	for _, stage := range []string{"intent", "lock", "public-pending", "private-committed"} {
		t.Run(stage, func(t *testing.T) {
			f := newInitialR1Fixture(t)
			progress := initialR1Publication{Version: 1, Identity: f.identity, Directory: f.directory}
			if err := f.store.writeInitialR1Publication(progress); err != nil {
				t.Fatal(err)
			}
			if stage != "intent" {
				dir, lock, _, err := f.guard.lock(t.Context(), true, true)
				if err != nil {
					t.Fatal(err)
				}
				if stage != "lock" {
					if err = writeInitialR1(dir, initialR1Record{Version: 1, Identity: f.identity}, nil); err != nil {
						t.Fatal(err)
					}
				}
				lock.Close()
				dir.Close()
			}
			if stage == "private-committed" {
				progress.Committed = true
				if err := f.store.writeInitialR1Publication(progress); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.guard.Check(t.Context()); err == nil {
				t.Fatal("partial publication authorized effect")
			}
			f.store.Close()
			store, err := NewEpochStore(filepath.Dir(f.store.path), f.identity.NodeID)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			f.store = store
			if err = f.admit(t.Context(), nil); err != nil {
				t.Fatalf("exact initialization recovery %s: %v", stage, err)
			}
			if err = f.guard.Check(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(filepath.Join(f.directory, "initial-r1.json")); err != nil {
				t.Fatal(err)
			}
			if err = f.admit(t.Context(), nil); err == nil {
				t.Fatal("committed missing record recreated")
			}
		})
	}
}

func TestInitialR1RetirementRequiresActualAdmittedAuthority(t *testing.T) {
	f := newInitialR1Fixture(t)
	ctx := t.Context()
	if err := f.admit(ctx, nil); err != nil {
		t.Fatal(err)
	}
	claimed := CommandAuthorization{NodeID: f.identity.NodeID, AuthorityID: "gru-regional", Epoch: 9, CandidateID: "gru-controller-one", LeaseID: "lease-one", ExpiresAt: time.Now().Add(time.Minute)}
	if err := f.retire(ctx, claimed, nil); err == nil {
		t.Fatal("desired epoch authorized retirement")
	}
	c := f.command(t)
	for _, alter := range []func(*CommandAuthorization){func(c *CommandAuthorization) { c.Epoch++ }, func(c *CommandAuthorization) { c.CandidateID = "gru-controller-other" }, func(c *CommandAuthorization) { c.LeaseID = "another" }, func(c *CommandAuthorization) { c.AuthorityID = "global" }, func(c *CommandAuthorization) { c.BootstrapGrantSHA256 = f.identity.GrantSHA256 }, func(c *CommandAuthorization) { c.ExpiresAt = time.Now().Add(-time.Second) }} {
		bad := c
		alter(&bad)
		if err := f.retire(ctx, bad, nil); err == nil {
			t.Fatal("unadmitted authority accepted")
		}
	}
	if err := f.store.retireInitialR1(ctx, f.directory, f.identity, c, "retire-one", strings.Repeat("f", 64), initialR1Replacement(), f.uid, nil); err == nil {
		t.Fatal("unadmitted predecessor accepted")
	}
	if err := f.guard.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestInitialR1RetirementReauthorizationPreservesOriginalEvidence(t *testing.T) {
	f := newInitialR1Fixture(t)
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	first := f.command(t)
	if err := f.retire(t.Context(), first, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.directory, "initial-r1.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	next := first
	next.Epoch++
	next.CandidateID = "gru-controller-two"
	next.LeaseID = "lease-two"
	if err = f.store.Admit(next); err != nil {
		t.Fatal(err)
	}
	if err = f.retire(t.Context(), first, nil); err == nil {
		t.Fatal("old authority retried after takeover")
	}
	if err = f.retire(t.Context(), next, nil); err != nil {
		t.Fatalf("same logical retirement stranded on takeover: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("successor rewrote original retirement evidence")
	}
	if err = f.store.retireInitialR1(t.Context(), f.directory, f.identity, next, "another-command", f.identity.ManifestSHA256, initialR1Replacement(), f.uid, nil); err == nil {
		t.Fatal("successor replaced retirement command")
	}
}

func TestInitialR1RetirementBindsExactManifestCommand(t *testing.T) {
	f := newInitialR1Fixture(t)
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	c := f.command(t)
	for _, wire := range [][]byte{nil, []byte(`{"commandId":"retire-one","drain":true}`), []byte(`{"commandId":"retire-one","component":"orchestrator","version":"1"}`), []byte(strings.Replace(string(c.Command), "retire-one", "different", 1)), []byte(strings.Replace(string(c.Command), f.identity.ManifestSHA256, strings.Repeat("f", 64), 1)), []byte(strings.Replace(string(c.Command), `"commandId":`, `"commandId":"duplicate","commandId":`, 1))} {
		bad := c
		bad.Command = wire
		if err := f.retire(t.Context(), bad, nil); err == nil {
			t.Fatalf("unrelated command retired: %s", wire)
		}
	}
	if err := f.store.retireInitialR1(t.Context(), f.directory, f.identity, c, "retire-one", f.identity.ManifestSHA256, strings.Repeat("f", 64), f.uid, nil); err == nil {
		t.Fatal("independent replacement digest accepted")
	}
	if err := f.guard.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.retire(t.Context(), c, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInitialR1MutationAndRetirementOrdering(t *testing.T) {
	f := newInitialR1Fixture(t)
	ctx := t.Context()
	if err := f.admit(ctx, nil); err != nil {
		t.Fatal(err)
	}
	c := f.command(t)
	entered, release, mutated := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		mutated <- f.guard.WithinMutation(ctx, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	short, cancel := context.WithTimeout(ctx, 35*time.Millisecond)
	defer cancel()
	if err := f.retire(short, c, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retirement falsely completed during mutation: %v", err)
	}
	retired := make(chan error, 1)
	go func() { retired <- f.retire(ctx, c, nil) }()
	select {
	case err := <-retired:
		t.Fatalf("retired before mutation joined: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-mutated; err != nil {
		t.Fatal(err)
	}
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
	called := false
	if err := f.guard.WithinMutation(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrInitialR1Retired) || called {
		t.Fatalf("post-retirement mutation err=%v called=%v", err, called)
	}
}

func TestInitialR1MissingCorruptAndUnsafeStateRefuses(t *testing.T) {
	for _, kind := range []string{"missing", "duplicate", "mode", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newInitialR1Fixture(t)
			if err := f.admit(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.directory, "initial-r1.json")
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte(`{"version":1,`), raw[1:]...)
				if err = os.WriteFile(path, raw, 0644); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(f.directory, "copy")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(f.directory, "target")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.guard.Check(t.Context()); err == nil {
				t.Fatal("unsafe state authorized")
			}
			if err := f.admit(t.Context(), nil); err == nil {
				t.Fatal("unsafe state was recreated")
			}
		})
	}
	if os.Geteuid() != 0 {
		f := newInitialR1Fixture(t)
		if _, err := NewInitialR1Guard(f.directory, f.identity); err == nil {
			t.Fatal("service-owned state accepted as root-owned")
		}
		if err := f.store.AdmitInitialR1(t.Context(), f.directory, f.identity); err == nil {
			t.Fatal("nonroot writer admitted")
		}
	}
}

func TestInitialR1LifetimeAndCanceledLock(t *testing.T) {
	f := newInitialR1Fixture(t)
	f.identity.ExpiresAt = time.Now().UTC().Add(100 * time.Millisecond)
	g, err := newInitialR1Guard(f.directory, f.identity, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	f.guard = g
	if err := f.admit(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	err = f.guard.WithinMutation(t.Context(), func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err = f.guard.Check(t.Context()); err == nil {
		t.Fatal("expired grant authorized")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err = f.guard.Check(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
