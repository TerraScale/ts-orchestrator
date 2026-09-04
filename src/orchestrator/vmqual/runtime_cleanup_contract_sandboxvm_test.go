//go:build sandboxvm

package vmqual

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type cleanupObserverStub struct {
	processes map[int]bool
	paths     map[string]bool
	devices   map[string]bool
	tables    map[string]bool
	listeners map[string]bool
	err       error
	calls     []string
}

func (o *cleanupObserverStub) ProcessExists(process VMProcessIdentity) (bool, error) {
	o.calls = append(o.calls, "process")
	if o.err != nil {
		return false, o.err
	}
	return o.processes[process.PID], nil
}

func (o *cleanupObserverStub) PathExists(path string) (bool, error) {
	o.calls = append(o.calls, "path:"+path)
	if o.err != nil {
		return false, o.err
	}
	return o.paths[path], nil
}

func (o *cleanupObserverStub) DeviceExists(_ context.Context, _ string, namespace, device string) (bool, error) {
	o.calls = append(o.calls, "device:"+namespace+"/"+device)
	if o.err != nil {
		return false, o.err
	}
	return o.devices[namespace+"/"+device], nil
}

func (o *cleanupObserverStub) TableExists(_ context.Context, _, _ string, namespace, table string) (bool, error) {
	o.calls = append(o.calls, "table:"+namespace+"/"+table)
	if o.err != nil {
		return false, o.err
	}
	return o.tables[namespace+"/"+table], nil
}

func (o *cleanupObserverStub) ListenerExists(_ context.Context, address string) (bool, error) {
	o.calls = append(o.calls, "listener:"+address)
	if o.err != nil {
		return false, o.err
	}
	return o.listeners[address], nil
}

func TestObserveCleanupTargetsReportsOnlyFreshHostObservations(t *testing.T) {
	targets := cleanupProbeTargets{
		cause: CleanupCauseAssertionFailure,
		vms: []cleanupVMTarget{{
			id: "cleanup-a", ownershipPath: "/owned/state/ownership.json",
			process: VMProcessIdentity{PID: 41, StartTimeTicks: 42, Executable: "/owned/state/root/firecracker"},
		}},
		networks: []cleanupNetworkTarget{{
			name: "tsc-run-n-gru", path: "/run/netns/tsc-run-n-gru", bridge: "tscbgru",
			taps: []string{"tsctgru01"}, rootDevice: "tschgru", table: "tsc_run_vmnet",
		}},
		cgroups:    []string{"/sys/fs/cgroup/terrascale-sandboxvm/cleanup-a"},
		sockets:    []string{"/owned/state/root/api.sock"},
		statePaths: []string{"/owned/state", "/owned/drives"},
		ownedPaths: []string{"/owned/state/runtime.json"},
		listeners:  []string{"198.18.0.1:4222"},
		ipPath:     "/usr/sbin/ip", nftPath: "/usr/sbin/nft",
	}
	host := &cleanupObserverStub{
		processes: map[int]bool{41: true},
		paths: map[string]bool{
			"/owned/state/ownership.json": true, "/run/netns/tsc-run-n-gru": true,
			"/sys/fs/cgroup/terrascale-sandboxvm/cleanup-a": true,
			"/owned/state/root/api.sock":                    true, "/owned/state": true,
			"/owned/drives": true, "/owned/state/runtime.json": true,
		},
		devices:   map[string]bool{"tsc-run-n-gru/tsctgru01": true, "tsc-run-n-gru/tscbgru": true, "/tschgru": true},
		tables:    map[string]bool{"tsc-run-n-gru/tsc_run_vmnet": true},
		listeners: map[string]bool{"198.18.0.1:4222": true},
	}

	got, err := observeCleanupTargets(context.Background(), targets, host)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cause != CleanupCauseAssertionFailure || !reflect.DeepEqual(got.RunningVMIDs, []string{"cleanup-a"}) || !reflect.DeepEqual(got.OwnedVMIDs, []string{"cleanup-a"}) || !reflect.DeepEqual(got.ProcessIDs, []int{41}) {
		t.Fatalf("VM observation = %+v", got)
	}
	if !reflect.DeepEqual(got.NetworkNamespaces, []string{"tsc-run-n-gru"}) || !reflect.DeepEqual(got.TAPDevices, []string{"tsc-run-n-gru/tsctgru01"}) {
		t.Fatalf("network observation = %+v", got)
	}
	if len(got.Cgroups) != 1 || len(got.APISockets) != 1 || len(got.StatePaths) != 2 || len(got.OwnedResources) != 5 {
		t.Fatalf("owned observation = %+v", got)
	}

	// The same immutable targets are observed again after changing the host
	// state. No prior non-empty or manufactured empty result is reused.
	host.processes = map[int]bool{}
	host.paths = map[string]bool{}
	host.devices = map[string]bool{}
	host.tables = map[string]bool{}
	host.listeners = map[string]bool{}
	host.calls = nil
	got, err = observeCleanupTargets(context.Background(), targets, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RunningVMIDs)+len(got.OwnedVMIDs)+len(got.ProcessIDs)+len(got.NetworkNamespaces)+len(got.TAPDevices)+len(got.Cgroups)+len(got.APISockets)+len(got.StatePaths)+len(got.OwnedResources) != 0 {
		t.Fatalf("absent resources were reported: %+v", got)
	}
	for _, wanted := range []string{"process", "device:tsc-run-n-gru/tsctgru01", "device:tsc-run-n-gru/tscbgru", "device:/tschgru", "table:tsc-run-n-gru/tsc_run_vmnet", "listener:198.18.0.1:4222"} {
		if !containsCleanupCall(host.calls, wanted) {
			t.Fatalf("fresh observation did not call %q: %v", wanted, host.calls)
		}
	}
}

func TestObserveCleanupTargetsPropagatesObservationFailureAndCancellation(t *testing.T) {
	targets := cleanupProbeTargets{cause: CleanupCauseCancellation, vms: []cleanupVMTarget{{id: "cleanup-c", process: VMProcessIdentity{PID: 1}, ownershipPath: "/owned/marker"}}}
	sentinel := errors.New("observation failed")
	if _, err := observeCleanupTargets(context.Background(), targets, &cleanupObserverStub{err: sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want observation failure", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observeCleanupTargets(cancelled, targets, &cleanupObserverStub{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestRealCleanupHostObserverUsesExactProcessIncarnation(t *testing.T) {
	pid := os.Getpid()
	start, err := procStartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	host := realCleanupHostObserver{}
	exists, err := host.ProcessExists(VMProcessIdentity{PID: pid, StartTimeTicks: start, Executable: executable})
	if err != nil || !exists {
		t.Fatalf("exact process exists=%v error=%v", exists, err)
	}
	exists, err = host.ProcessExists(VMProcessIdentity{PID: pid, StartTimeTicks: start + 1, Executable: executable})
	if err != nil || exists {
		t.Fatalf("reused process exists=%v error=%v", exists, err)
	}
}

func TestCleanupFaultTargetRegistryRequiresCompletedExerciseAndConsumesTargets(t *testing.T) {
	factory := &firecrackerFactory{}
	if _, err := factory.InspectOwnedResources(context.Background(), CleanupCauseCancellation); err == nil {
		t.Fatal("inspection without an exercise passed")
	}
	if err := beginCleanupFaultRun(factory, CleanupCauseCancellation); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "leftover")
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	finishCleanupFaultRun(factory, CleanupCauseCancellation, cleanupProbeTargets{cause: CleanupCauseCancellation, statePaths: []string{path}}, true)
	observation, err := factory.InspectOwnedResources(context.Background(), CleanupCauseCancellation)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observation.StatePaths, []string{path}) {
		t.Fatalf("state paths = %v", observation.StatePaths)
	}
	if _, err := factory.InspectOwnedResources(context.Background(), CleanupCauseCancellation); err == nil {
		t.Fatal("consumed cleanup targets were reused")
	}
}

func TestCleanupFaultContractRejectsNonProductionRunner(t *testing.T) {
	factory := &firecrackerFactory{network: &networkController{runner: vmnet.FuncRunner(func(context.Context, string, []string) error { return nil })}}
	result, err := factory.ExerciseCleanup(context.Background(), CleanupCauseCancellation)
	if err == nil || !strings.Contains(err.Error(), "real host network runner") {
		t.Fatalf("ExerciseCleanup() result=%+v error=%v", result, err)
	}
	if result.CauseObserved || result.CleanupCompleted {
		t.Fatalf("fake runner manufactured cleanup evidence: %+v", result)
	}
}

func TestReleaseDiskHandleAllowsTrustedCrashReplay(t *testing.T) {
	root := filepath.Join(t.TempDir(), "drives")
	store, err := vmdisk.New(vmdisk.Config{Root: root, RunID: "cleanup-crash-run"})
	if err != nil {
		t.Fatal(err)
	}
	identity := store.Identity()
	factory := &firecrackerFactory{disks: store, diskRunID: identity.RunID}
	probe := &cleanupProbe{factory: factory}
	if err := probe.releaseDiskHandleForCrash(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factory.disks != nil || factory.diskRunID != "" {
		t.Fatal("factory retained the released crash-replay store handle")
	}
	if _, err := store.Usage(context.Background()); !errors.Is(err, vmdisk.ErrClosed) {
		t.Fatalf("released store error = %v, want ErrClosed", err)
	}
	if err := vmdisk.RemoveStore(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replayed store root remains: %v", err)
	}
}

func TestRemoveCleanupProbeScaffoldingRejectsUnknownResidualAndRemovesEmptyTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cleanup-probes", "run")
	if err := os.MkdirAll(filepath.Join(root, "state", ".vmqual-runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, "cleanup-journal.json.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "state", "leftover")
	if err := os.WriteFile(unknown, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeCleanupProbeScaffolding(root, lock); err == nil || !strings.Contains(err.Error(), "retained owned resource") {
		t.Fatalf("unknown residual error = %v", err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	if err := removeCleanupProbeScaffolding(root, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("probe root remains: %v", err)
	}
}

func TestCleanupNetworkTableComesFromExactPlanCommand(t *testing.T) {
	plan := vmnet.NetworkPlan{
		Tools: vmnet.ToolPaths{IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft"},
		Commands: []vmnet.Command{{
			Executable: "/usr/sbin/ip",
			Args:       []string{"netns", "exec", "owned-ns", "/usr/sbin/nft", "add", "table", "inet", "owned_table"},
		}},
	}
	if got := cleanupNetworkTable(plan, "owned-ns"); got != "owned_table" {
		t.Fatalf("table = %q", got)
	}
	if got := cleanupNetworkTable(plan, "another-ns"); got != "" {
		t.Fatalf("unowned table = %q", got)
	}
}

func containsCleanupCall(calls []string, wanted string) bool {
	for _, call := range calls {
		if call == wanted {
			return true
		}
	}
	return false
}
