//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

var errCleanupProbeAssertion = errors.New("vmqual: injected cleanup qualification assertion failure")

// cleanupFaultRuns holds only the immutable targets needed for a second,
// post-cleanup observation. It never stores a claimed cleanup result: every
// field returned by InspectOwnedResources is populated by observing the host.
var cleanupFaultRuns = struct {
	sync.Mutex
	byFactory map[*firecrackerFactory]*cleanupFaultRunState
}{byFactory: make(map[*firecrackerFactory]*cleanupFaultRunState)}

type cleanupFaultRunState struct {
	running bool
	targets map[vmqual.CleanupCause]cleanupProbeTargets
}

type cleanupProbe struct {
	cause          vmqual.CleanupCause
	root           string
	journalPath    string
	networkJournal string
	guest          vmqual.Guest
	stack          *vmqual.Stack
	factory        *firecrackerFactory
	network        *networkController
	vm             vmqual.VM
	diskIdentity   vmdisk.StoreIdentity
	plan           vmnet.NetworkPlan
}

type cleanupVMTarget struct {
	id            string
	ownershipPath string
	process       vmqual.VMProcessIdentity
}

type cleanupNetworkTarget struct {
	name       string
	path       string
	bridge     string
	taps       []string
	rootDevice string
	table      string
}

type cleanupProbeTargets struct {
	cause      vmqual.CleanupCause
	vms        []cleanupVMTarget
	networks   []cleanupNetworkTarget
	cgroups    []string
	sockets    []string
	statePaths []string
	ownedPaths []string
	listeners  []string
	ipPath     string
	nftPath    string
}

// cleanupHostObserver is the read-only host boundary used after cleanup. The
// production implementation reads procfs and the filesystem and executes the
// pinned ip/nft binaries only for exact run-owned identifiers.
type cleanupHostObserver interface {
	ProcessExists(vmqual.VMProcessIdentity) (bool, error)
	PathExists(string) (bool, error)
	DeviceExists(context.Context, string, string, string) (bool, error)
	TableExists(context.Context, string, string, string, string) (bool, error)
	ListenerExists(context.Context, string) (bool, error)
}

type realCleanupHostObserver struct{}

var _ vmqual.CleanupFaultContract = (*firecrackerFactory)(nil)

// ExerciseCleanup creates an isolated, real Firecracker qualification probe.
// The live six-VM estate is never reused as cleanup evidence.
func (f *firecrackerFactory) ExerciseCleanup(ctx context.Context, cause vmqual.CleanupCause) (result vmqual.CleanupExerciseObservation, resultErr error) {
	result.Cause = cause
	if ctx == nil {
		return result, errors.New("vmqual: cleanup exercise context is nil")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if cause != vmqual.CleanupCauseCancellation && cause != vmqual.CleanupCauseAssertionFailure {
		return result, fmt.Errorf("vmqual: unsupported cleanup cause %q", cause)
	}
	if f == nil || f.network == nil {
		return result, errors.New("vmqual: cleanup qualification requires bound production components")
	}
	if _, ok := f.network.runner.(*vmnet.HostRunner); !ok {
		return result, errors.New("vmqual: cleanup qualification requires the real host network runner")
	}
	if err := beginCleanupFaultRun(f, cause); err != nil {
		return result, err
	}
	stored := false
	defer func() {
		if !stored {
			finishCleanupFaultRun(f, cause, cleanupProbeTargets{}, false)
		}
	}()

	probe, err := newCleanupProbe(ctx, f, cause)
	if err != nil {
		return result, err
	}
	cleaned := false
	defer func() {
		if cleaned {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupExerciseTimeout(f.config))
		defer cancel()
		resultErr = errors.Join(resultErr, probe.emergencyCleanup(cleanupCtx))
	}()

	if err := probe.start(ctx); err != nil {
		return result, err
	}
	observation, err := probe.vm.Inspect(ctx)
	if err != nil {
		return result, fmt.Errorf("vmqual: inspect cleanup probe: %w", err)
	}
	if !observation.Running || !observation.Ready || observation.ID != probe.guest.ID || vmqual.ZeroProcessIdentity(observation.Process) {
		return result, errors.New("vmqual: cleanup probe did not reach an observed running and ready state")
	}
	targets, err := probe.targets(observation)
	if err != nil {
		return result, err
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupExerciseTimeout(f.config))
	defer cleanupCancel()
	switch cause {
	case vmqual.CleanupCauseCancellation:
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		result.CauseObserved = errors.Is(cancelled.Err(), context.Canceled)
		if !result.CauseObserved {
			return result, errors.New("vmqual: cleanup cancellation was not observed")
		}
		err = probe.stack.Cleanup(cancelled)
		if err == nil {
			err = probe.network.VerifyNoOwnedResources(cleanupCtx)
		}
	case vmqual.CleanupCauseAssertionFailure:
		assertionErr := cleanupProbeAssertion(observation)
		result.CauseObserved = errors.Is(assertionErr, errCleanupProbeAssertion)
		if !result.CauseObserved {
			return result, errors.Join(errors.New("vmqual: cleanup assertion failure was not observed"), assertionErr)
		}
		if err = crashCleanupProbe(targets.vms[0]); err == nil {
			err = probe.recoverAfterControllerCrash(cleanupCtx)
		}
	}
	if err != nil {
		return result, fmt.Errorf("vmqual: production cleanup after %s: %w", cause, err)
	}
	if err := removeCleanupProbeScaffolding(probe.root, probe.journalPath+".lock"); err != nil {
		return result, err
	}
	cleaned = true
	result.CleanupCompleted = true
	finishCleanupFaultRun(f, cause, targets, true)
	stored = true
	return result, nil
}

// InspectOwnedResources performs a fresh host observation after the exercise
// has completed. Empty result slices therefore mean every exact target was
// checked and found absent; they are not predeclared success values.
func (f *firecrackerFactory) InspectOwnedResources(ctx context.Context, cause vmqual.CleanupCause) (vmqual.CleanupObservation, error) {
	if ctx == nil {
		return vmqual.CleanupObservation{Cause: cause}, errors.New("vmqual: cleanup inspection context is nil")
	}
	if err := ctx.Err(); err != nil {
		return vmqual.CleanupObservation{Cause: cause}, err
	}
	targets, err := takeCleanupFaultTargets(f, cause)
	if err != nil {
		return vmqual.CleanupObservation{Cause: cause}, err
	}
	return observeCleanupTargets(ctx, targets, realCleanupHostObserver{})
}

func beginCleanupFaultRun(factory *firecrackerFactory, cause vmqual.CleanupCause) error {
	cleanupFaultRuns.Lock()
	defer cleanupFaultRuns.Unlock()
	state := cleanupFaultRuns.byFactory[factory]
	if state == nil {
		state = &cleanupFaultRunState{targets: make(map[vmqual.CleanupCause]cleanupProbeTargets)}
		cleanupFaultRuns.byFactory[factory] = state
	}
	if state.running {
		return errors.New("vmqual: cleanup qualification is already running")
	}
	if _, exists := state.targets[cause]; exists {
		return fmt.Errorf("vmqual: cleanup cause %s has not been inspected", cause)
	}
	state.running = true
	return nil
}

func finishCleanupFaultRun(factory *firecrackerFactory, cause vmqual.CleanupCause, targets cleanupProbeTargets, keep bool) {
	cleanupFaultRuns.Lock()
	defer cleanupFaultRuns.Unlock()
	state := cleanupFaultRuns.byFactory[factory]
	if state == nil {
		return
	}
	state.running = false
	if keep {
		state.targets[cause] = targets
	}
	if !state.running && len(state.targets) == 0 {
		delete(cleanupFaultRuns.byFactory, factory)
	}
}

func takeCleanupFaultTargets(factory *firecrackerFactory, cause vmqual.CleanupCause) (cleanupProbeTargets, error) {
	cleanupFaultRuns.Lock()
	defer cleanupFaultRuns.Unlock()
	state := cleanupFaultRuns.byFactory[factory]
	if state == nil || state.running {
		return cleanupProbeTargets{}, fmt.Errorf("vmqual: cleanup cause %s has no completed exercise", cause)
	}
	targets, ok := state.targets[cause]
	if !ok {
		return cleanupProbeTargets{}, fmt.Errorf("vmqual: cleanup cause %s has no post-cleanup targets", cause)
	}
	delete(state.targets, cause)
	if len(state.targets) == 0 {
		delete(cleanupFaultRuns.byFactory, factory)
	}
	return targets, nil
}

func cleanupExerciseTimeout(config vmqual.Config) time.Duration {
	timeout := 2 * time.Minute
	if candidate := config.ReadinessTimeout + 4*config.StopTimeout; candidate > timeout {
		timeout = candidate
	}
	return timeout
}

func newCleanupProbe(ctx context.Context, source *firecrackerFactory, cause vmqual.CleanupCause) (*cleanupProbe, error) {
	networkRunID, err := newCleanupNetworkRunID()
	if err != nil {
		return nil, err
	}
	stackRunID, err := vmqual.NewRunID()
	if err != nil {
		return nil, err
	}
	marker := "c"
	if cause == vmqual.CleanupCauseAssertionFailure {
		marker = "a"
	}
	guest := vmqual.Guest{ID: "cleanup-" + marker + "-" + networkRunID[:12], Region: vmnet.GRU, VCPU: 1, MemoryMiB: vmqual.DefaultMemoryMiB, Control: true, Service: true}
	root := filepath.Join(source.config.Root, "cleanup-probes", networkRunID)
	if _, err := os.Lstat(root); err == nil {
		return nil, fmt.Errorf("vmqual: cleanup probe root already exists: %s", root)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	thirdOctet := 32 + int(networkRunID[0])%192
	networkConfig := vmnet.Config{
		Prefix: "tsc", RunID: networkRunID, Tools: source.network.plan.Tools,
		TAPUID: uint32(source.config.JailerUID), TAPGID: uint32(source.config.JailerGID),
		CoordinationRoot: source.network.plan.CoordinationRoot,
		Regions:          []vmnet.RegionSpec{{Code: vmnet.GRU, CIDR: fmt.Sprintf("10.88.%d.0/24", thirdOctet), Guests: []vmnet.GuestSpec{{ID: guest.ID}}}},
	}
	networkJournal := filepath.Join(root, "network-cleanup-journal.json")
	controllerValue, err := NewNetworkController(networkConfig, source.network.runner, networkJournal)
	if err != nil {
		return nil, err
	}
	controller := controllerValue.(*networkController)
	config := source.config
	config.Root = root
	config.StateRoot = filepath.Join(root, "state")
	config.JournalPath = filepath.Join(root, "cleanup-journal.json")
	config.ReadinessRoot = filepath.Join(root, "readiness")
	config.NetworkPlan = controller.Plan()
	services, err := newQualificationServices(config, config.NetworkPlan, source.image.Manifest.Architecture)
	if err != nil {
		return nil, err
	}
	factoryValue, err := newFirecrackerFactory(config, source.image, services)
	if err != nil {
		_ = services.Close(context.Background())
		return nil, err
	}
	factory := factoryValue.(*firecrackerFactory)
	factory.network = controller
	controller.services = services
	stack, err := vmqual.NewCleanupProbeStack(vmqual.StackConfig{
		Guests: []vmqual.Guest{guest}, VMFactory: factory, Network: controller,
		JournalPath: config.JournalPath, StateRoot: config.StateRoot, ResourceRoot: root,
		RunID: stackRunID, MaxRSSBytes: vmqual.MaxIdleRSSBytes, MaxIdleCPU: vmqual.MaxIdleCPU,
		MaxDiskBytes: config.MaxDiskBytes,
	})
	if err != nil {
		_ = services.Close(context.Background())
		return nil, err
	}
	return &cleanupProbe{
		cause: cause, root: root, journalPath: config.JournalPath, networkJournal: networkJournal,
		guest: guest, stack: stack, factory: factory, network: controller, plan: config.NetworkPlan,
	}, nil
}

func newCleanupNetworkRunID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("vmqual: generate cleanup network run ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func (p *cleanupProbe) start(ctx context.Context) error {
	if err := p.stack.StartCleanupProbe(ctx); err != nil {
		return err
	}
	p.vm = p.stack.Snapshot().VMs[p.guest.ID]
	if p.vm == nil {
		return errors.New("vmqual: cleanup probe VM handle is missing")
	}
	p.factory.diskMu.Lock()
	if p.factory.disks != nil {
		p.diskIdentity = p.factory.disks.Identity()
	}
	p.factory.diskMu.Unlock()
	if p.diskIdentity.Root == "" {
		return errors.New("vmqual: cleanup probe disk ownership is missing")
	}
	return nil
}

func cleanupProbeAssertion(observation vmqual.VMObservation) error {
	if !observation.Running || !observation.Ready || vmqual.ZeroProcessIdentity(observation.Process) {
		return errors.New("vmqual: cannot inject assertion failure before observing a live VM")
	}
	return errCleanupProbeAssertion
}

func crashCleanupProbe(target cleanupVMTarget) error {
	if target.id == "" || vmqual.ZeroProcessIdentity(target.process) || target.ownershipPath == "" {
		return errors.New("vmqual: cleanup crash target is incomplete")
	}
	stateDir := filepath.Dir(target.ownershipPath)
	record, err := sandboxvm.ReadRuntimeRecord(stateDir, target.id)
	if err != nil {
		return fmt.Errorf("vmqual: read crash target runtime record: %w", err)
	}
	if record.PID != target.process.PID || record.ProcessStartTime != target.process.StartTimeTicks || record.SocketPath == "" {
		return errors.New("vmqual: crash target runtime identity differs from its observation")
	}
	if err := record.VerifyRunningProcess(target.process.Executable); err != nil {
		return fmt.Errorf("vmqual: verify crash target identity: %w", err)
	}
	if err := syscall.Kill(target.process.PID, syscall.SIGKILL); err != nil {
		return fmt.Errorf("vmqual: crash exact Firecracker process: %w", err)
	}
	if !vmqual.WaitForProcessExit(target.process, 10*time.Second) {
		return errors.New("vmqual: crashed Firecracker process did not exit")
	}
	return nil
}

func (p *cleanupProbe) recoverAfterControllerCrash(ctx context.Context) error {
	// The provider still owns its SDK handle in this process, so let the exact
	// production Stop/Delete path reap the deliberately crashed VMM and remove
	// its jailer state. A real controller crash would close those descriptors
	// when the controller process exited.
	providerErr := errors.Join(p.vm.Stop(ctx), p.vm.Delete(ctx), vmqual.VerifyGuestCleanup(ctx, p.vm))
	diskHandleErr := p.releaseDiskHandleForCrash(ctx)
	// Dropping the in-memory Stack lock models a dead controller. Recovery is
	// driven only by its durable journal and exact store/network identities.
	lockErr := p.stack.ReleaseCleanupProbeJournal()
	journalErr := vmqual.CleanJournal(ctx, p.journalPath, p.network.runner)
	networkErr := p.network.Cleanup(ctx)
	verifyNetworkErr := p.network.VerifyNoOwnedResources(ctx)
	diskErr := vmdisk.RemoveStore(ctx, p.diskIdentity)
	transportErr := releaseGuestTransport(p.factory.config.StateRoot)
	return errors.Join(providerErr, diskHandleErr, lockErr, journalErr, networkErr, verifyNetworkErr, diskErr, transportErr)
}

func (p *cleanupProbe) releaseDiskHandleForCrash(ctx context.Context) error {
	p.factory.diskMu.Lock()
	defer p.factory.diskMu.Unlock()
	store := p.factory.disks
	if store == nil {
		return errors.New("vmqual: cleanup probe disk store handle is missing")
	}
	if err := store.Close(ctx); err != nil {
		return fmt.Errorf("vmqual: release disk store before crash replay: %w", err)
	}
	p.factory.disks = nil
	p.factory.diskRunID = ""
	return nil
}

func (p *cleanupProbe) emergencyCleanup(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.vm != nil {
		errs = append(errs, p.vm.Stop(ctx), p.vm.Delete(ctx))
	}
	if p.stack != nil {
		errs = append(errs, p.stack.Cleanup(ctx))
	}
	if p.network != nil {
		errs = append(errs, p.network.Cleanup(ctx), p.network.VerifyNoOwnedResources(ctx))
	}
	if p.diskIdentity.Root != "" {
		errs = append(errs, vmdisk.RemoveStore(ctx, p.diskIdentity))
	}
	if p.factory != nil {
		errs = append(errs, releaseGuestTransport(p.factory.config.StateRoot))
	}
	errs = append(errs, removeCleanupProbeScaffolding(p.root, p.journalPath+".lock"))
	return errors.Join(errs...)
}

func (p *cleanupProbe) targets(observation vmqual.VMObservation) (cleanupProbeTargets, error) {
	resources := observation.Resources
	if resources.StateDir == "" || resources.SandboxOwnershipPath == "" || resources.SocketPath == "" || resources.CgroupPath == "" || resources.JailerCgroupPath == "" {
		return cleanupProbeTargets{}, errors.New("vmqual: cleanup probe did not report complete owned resources")
	}
	expectedExecutable := filepath.Join(resources.JailRoot, filepath.Base(p.factory.config.FirecrackerPath))
	if observation.Process.Executable != expectedExecutable {
		return cleanupProbeTargets{}, fmt.Errorf("vmqual: cleanup probe executable %s differs from jail copy %s", observation.Process.Executable, expectedExecutable)
	}
	targets := cleanupProbeTargets{
		cause:   p.cause,
		vms:     []cleanupVMTarget{{id: observation.ID, ownershipPath: resources.SandboxOwnershipPath, process: observation.Process}},
		cgroups: []string{resources.CgroupPath, resources.JailerCgroupPath},
		sockets: []string{resources.SocketPath}, ipPath: p.plan.Tools.IP, nftPath: p.plan.Tools.NFT,
		statePaths: []string{
			p.root, p.factory.config.StateRoot, p.factory.diskRoot, p.journalPath, p.networkJournal,
			resources.StateDir, resources.DriveDir, resources.SeedDir,
		},
		ownedPaths: []string{
			resources.SandboxOwnershipPath, resources.RunMarkerPath, resources.RuntimePath,
			resources.JailRoot, resources.LogPath, resources.MetricsPath,
			resources.DrivePath, resources.DriveMetadataPath, resources.DriveOwnershipPath,
		},
	}
	for _, listener := range p.plan.Listeners {
		targets.listeners = append(targets.listeners, net.JoinHostPort(listener.Address, fmt.Sprint(listener.Port)))
	}
	for _, region := range p.plan.Regions {
		network := cleanupNetworkTarget{
			name: region.Namespace, path: region.NamespacePath, bridge: region.Bridge,
			rootDevice: region.Uplink.RootDevice, table: cleanupNetworkTable(p.plan, region.Namespace),
		}
		for _, guest := range region.Guests {
			network.taps = append(network.taps, guest.TAP)
		}
		targets.networks = append(targets.networks, network)
	}
	targets.cgroups = compactCleanupTargets(targets.cgroups)
	targets.sockets = compactCleanupTargets(targets.sockets)
	targets.statePaths = compactCleanupTargets(targets.statePaths)
	targets.ownedPaths = compactCleanupTargets(targets.ownedPaths)
	targets.listeners = compactCleanupTargets(targets.listeners)
	return targets, nil
}

func cleanupNetworkTable(plan vmnet.NetworkPlan, namespace string) string {
	for _, command := range plan.Commands {
		args := command.Args
		if command.Executable == plan.Tools.IP && len(args) == 8 && args[0] == "netns" && args[1] == "exec" && args[2] == namespace && args[3] == plan.Tools.NFT && args[4] == "add" && args[5] == "table" && args[6] == "inet" {
			return args[7]
		}
	}
	return ""
}

func compactCleanupTargets(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func observeCleanupTargets(ctx context.Context, targets cleanupProbeTargets, host cleanupHostObserver) (vmqual.CleanupObservation, error) {
	observation := vmqual.CleanupObservation{Cause: targets.cause}
	if ctx == nil || host == nil {
		return observation, errors.New("vmqual: cleanup host observation is not configured")
	}
	if err := ctx.Err(); err != nil {
		return observation, err
	}
	for _, vm := range targets.vms {
		exists, err := host.ProcessExists(vm.process)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup process %s: %w", vm.id, err)
		}
		if exists {
			observation.RunningVMIDs = append(observation.RunningVMIDs, vm.id)
			observation.ProcessIDs = append(observation.ProcessIDs, vm.process.PID)
		}
		exists, err = host.PathExists(vm.ownershipPath)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup VM ownership %s: %w", vm.id, err)
		}
		if exists {
			observation.OwnedVMIDs = append(observation.OwnedVMIDs, vm.id)
		}
	}
	for _, network := range targets.networks {
		exists, err := host.PathExists(network.path)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup namespace %s: %w", network.name, err)
		}
		if exists {
			observation.NetworkNamespaces = append(observation.NetworkNamespaces, network.name)
		}
		for _, tap := range network.taps {
			tapExists, tapErr := host.DeviceExists(ctx, targets.ipPath, network.name, tap)
			if tapErr != nil {
				return observation, fmt.Errorf("vmqual: inspect cleanup TAP %s/%s: %w", network.name, tap, tapErr)
			}
			if tapExists {
				observation.TAPDevices = append(observation.TAPDevices, network.name+"/"+tap)
			}
		}
		for _, device := range []struct{ namespace, name string }{{network.name, network.bridge}, {"", network.rootDevice}} {
			deviceExists, deviceErr := host.DeviceExists(ctx, targets.ipPath, device.namespace, device.name)
			if deviceErr != nil {
				return observation, fmt.Errorf("vmqual: inspect cleanup link %s: %w", device.name, deviceErr)
			}
			if deviceExists {
				observation.OwnedResources = append(observation.OwnedResources, "link:"+device.namespace+"/"+device.name)
			}
		}
		if network.table != "" {
			tableExists, tableErr := host.TableExists(ctx, targets.ipPath, targets.nftPath, network.name, network.table)
			if tableErr != nil {
				return observation, fmt.Errorf("vmqual: inspect cleanup nft table %s/%s: %w", network.name, network.table, tableErr)
			}
			if tableExists {
				observation.OwnedResources = append(observation.OwnedResources, "nft:"+network.name+"/inet/"+network.table)
			}
		}
	}
	for _, cgroup := range targets.cgroups {
		exists, err := host.PathExists(cgroup)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup cgroup %s: %w", cgroup, err)
		}
		if exists {
			observation.Cgroups = append(observation.Cgroups, cgroup)
		}
	}
	for _, socket := range targets.sockets {
		exists, err := host.PathExists(socket)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup socket %s: %w", socket, err)
		}
		if exists {
			observation.APISockets = append(observation.APISockets, socket)
		}
	}
	for _, path := range targets.statePaths {
		exists, err := host.PathExists(path)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup state path %s: %w", path, err)
		}
		if exists {
			observation.StatePaths = append(observation.StatePaths, path)
		}
	}
	for _, path := range targets.ownedPaths {
		exists, err := host.PathExists(path)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup owned path %s: %w", path, err)
		}
		if exists {
			observation.OwnedResources = append(observation.OwnedResources, path)
		}
	}
	for _, address := range targets.listeners {
		exists, err := host.ListenerExists(ctx, address)
		if err != nil {
			return observation, fmt.Errorf("vmqual: inspect cleanup listener %s: %w", address, err)
		}
		if exists {
			observation.OwnedResources = append(observation.OwnedResources, "tcp:"+address)
		}
	}
	sort.Strings(observation.RunningVMIDs)
	sort.Strings(observation.OwnedVMIDs)
	sort.Ints(observation.ProcessIDs)
	sort.Strings(observation.NetworkNamespaces)
	sort.Strings(observation.TAPDevices)
	sort.Strings(observation.Cgroups)
	sort.Strings(observation.APISockets)
	sort.Strings(observation.StatePaths)
	sort.Strings(observation.OwnedResources)
	return observation, nil
}

func (realCleanupHostObserver) ProcessExists(identity vmqual.VMProcessIdentity) (bool, error) {
	if vmqual.ZeroProcessIdentity(identity) {
		return false, nil
	}
	matched, err := vmqual.ProcessIdentityMatches(identity)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return matched, err
}

func (realCleanupHostObserver) PathExists(path string) (bool, error) {
	if path == "" || !filepath.IsAbs(path) {
		return false, errors.New("cleanup observation path is not absolute")
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (realCleanupHostObserver) DeviceExists(ctx context.Context, ipPath, namespace, device string) (bool, error) {
	if device == "" {
		return false, nil
	}
	args := []string{"link", "show", "dev", device}
	if namespace != "" {
		if _, err := os.Lstat(filepath.Join("/run/netns", namespace)); errors.Is(err, os.ErrNotExist) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		args = append([]string{"-n", namespace}, args...)
	}
	return cleanupCommandExists(ctx, ipPath, args, "does not exist", "cannot open network namespace")
}

func (realCleanupHostObserver) TableExists(ctx context.Context, ipPath, nftPath, namespace, table string) (bool, error) {
	if namespace == "" || table == "" {
		return false, nil
	}
	if _, err := os.Lstat(filepath.Join("/run/netns", namespace)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if nftPath == "" || !filepath.IsAbs(nftPath) {
		return false, errors.New("cleanup observation nft executable is not absolute")
	}
	return cleanupCommandExists(ctx, ipPath, []string{"netns", "exec", namespace, nftPath, "list", "table", "inet", table}, "no such file or directory", "cannot open network namespace")
}

func (realCleanupHostObserver) ListenerExists(ctx context.Context, address string) (bool, error) {
	return kernelListenerExists(ctx, address)
}

func cleanupCommandExists(ctx context.Context, executable string, args []string, absentMessages ...string) (bool, error) {
	if executable == "" || !filepath.IsAbs(executable) {
		return false, errors.New("cleanup observation executable is not absolute")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = hostToolEnvironment()
	var output limitedBuffer
	output.limit = 64 << 10
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false, err
	}
	lower := strings.ToLower(output.String())
	for _, message := range absentMessages {
		if strings.Contains(lower, message) {
			return false, nil
		}
	}
	return false, fmt.Errorf("cleanup observation command failed: %w: %s", err, output.String())
}

// removeCleanupProbeScaffolding removes only an exact probe root after
// production cleanup. The journal lock is the sole regular-file scaffold the
// Stack intentionally retains; any other residual entry fails qualification.
func removeCleanupProbeScaffolding(root, journalLock string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return errors.New("vmqual: cleanup probe root is invalid")
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(journalLock); err == nil {
		if err := vmqual.RemoveFileAndSync(journalLock); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("vmqual: cleanup probe retained symlink %s", path)
		}
		if !entry.IsDir() {
			return fmt.Errorf("vmqual: cleanup probe retained owned resource %s", path)
		}
		directories = append(directories, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vmqual: remove empty cleanup probe directory %s: %w", directory, err)
		}
	}
	if parent := filepath.Dir(root); parent != filepath.Dir(parent) {
		_ = os.Remove(parent)
	}
	return nil
}
