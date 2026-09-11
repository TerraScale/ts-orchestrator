package vmqual

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

type smokeFakeFactory struct {
	mu        sync.Mutex
	created   []*smokeFakeVM
	support   map[string]bool
	createErr error
	verifyErr error
	configure func(*smokeFakeVM)
}

func (factory *smokeFakeFactory) Create(ctx context.Context, guest Guest) (VM, error) {
	if factory.createErr != nil {
		return nil, factory.createErr
	}
	vm := &smokeFakeVM{guest: guest, rssBytes: 16 << 20, idleCPU: 0.01, diskBytes: 64 << 20}
	if factory.configure != nil {
		factory.configure(vm)
	}
	factory.mu.Lock()
	factory.created = append(factory.created, vm)
	factory.mu.Unlock()
	return vm, nil
}

func (factory *smokeFakeFactory) SupportsSmokeProfile(_ context.Context, profile SmokeProfile) (bool, error) {
	if supported, configured := factory.support[profile.Name]; configured {
		return supported, nil
	}
	return true, nil
}

func (factory *smokeFakeFactory) VerifyNoOwnedResources(context.Context) error {
	if factory.verifyErr != nil {
		return factory.verifyErr
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	for _, vm := range factory.created {
		vm.mu.Lock()
		deleted := vm.deleted
		vm.mu.Unlock()
		if !deleted {
			return fmt.Errorf("guest %s remains", vm.guest.ID)
		}
	}
	return nil
}

type smokeFakeNetwork struct {
	mu         sync.Mutex
	applied    bool
	cleaned    bool
	applyErr   error
	cleanupErr error
	verifyErr  error
	cleanDelay time.Duration
}

func (network *smokeFakeNetwork) Apply(context.Context) error {
	network.mu.Lock()
	network.applied = true
	network.mu.Unlock()
	return network.applyErr
}

func (network *smokeFakeNetwork) Cleanup(ctx context.Context) error {
	if network.cleanDelay > 0 {
		timer := time.NewTimer(network.cleanDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	network.mu.Lock()
	network.cleaned = true
	network.mu.Unlock()
	return network.cleanupErr
}

func (network *smokeFakeNetwork) VerifyNoOwnedResources(context.Context) error {
	if network.verifyErr != nil {
		return network.verifyErr
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.applied && !network.cleaned {
		return errors.New("network remains")
	}
	return nil
}

func (network *smokeFakeNetwork) ProveGuestExchange(ctx context.Context, _ VM) error {
	return ctx.Err()
}

type smokeCommandCall struct {
	path string
	args []string
}

type smokeFakeVM struct {
	mu sync.Mutex

	guest      Guest
	running    bool
	ready      bool
	deleted    bool
	startCalls int
	stopCalls  int
	deleteCall int
	commands   []smokeCommandCall
	persistent []byte

	startErr       error
	stopErr        error
	stopErrAt      int
	deleteErr      error
	inspectErr     error
	executeErr     error
	writeErr       error
	readErr        error
	diskErr        error
	verifyErr      error
	wrongPID1      bool
	wrongState     bool
	wrongCgroup    bool
	wrongMount     bool
	wrongNetwork   bool
	unroutable     bool
	noIPv4         bool
	corruptRead    bool
	oversizeOutput bool
	splitOversize  bool
	rssBytes       uint64
	idleCPU        float64
	diskBytes      uint64
	cleanupDelay   time.Duration
	cleanupCtxErr  error
}

func (vm *smokeFakeVM) StartReady(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.startCalls++
	if vm.startErr != nil {
		return vm.startErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	vm.running, vm.ready = true, true
	return nil
}

func (vm *smokeFakeVM) Stop(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.stopCalls++
	vm.cleanupCtxErr = errors.Join(vm.cleanupCtxErr, ctx.Err())
	if vm.cleanupDelay > 0 {
		time.Sleep(vm.cleanupDelay)
	}
	vm.running, vm.ready = false, false
	if vm.stopErrAt != 0 {
		if vm.stopErrAt == vm.stopCalls {
			return vm.stopErr
		}
		return nil
	}
	return vm.stopErr
}

func (vm *smokeFakeVM) Delete(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.deleteCall++
	vm.cleanupCtxErr = errors.Join(vm.cleanupCtxErr, ctx.Err())
	if vm.cleanupDelay > 0 {
		time.Sleep(vm.cleanupDelay)
	}
	vm.deleted = true
	return vm.deleteErr
}

func (vm *smokeFakeVM) Inspect(context.Context) (VMObservation, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.inspectErr != nil {
		return VMObservation{}, vm.inspectErr
	}
	return VMObservation{ID: vm.guest.ID, Region: vm.guest.Region, Running: vm.running, Ready: vm.ready, MemoryMiB: vm.guest.MemoryMiB, RSSBytes: vm.rssBytes, IdleCPU: vm.idleCPU, CPUSampled: true}, nil
}

func (vm *smokeFakeVM) Execute(_ context.Context, command sandboxvm.Command) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.commands = append(vm.commands, smokeCommandCall{path: command.Path, args: append([]string(nil), command.Args...)})
	if vm.executeErr != nil {
		return vm.executeErr
	}
	var output string
	switch command.Path {
	case "/usr/bin/readlink":
		output = "/usr/lib/systemd/systemd\n"
		if vm.wrongPID1 {
			output = "/usr/bin/tini\n"
		}
	case "/usr/bin/systemctl":
		output = "running\n"
		if vm.wrongState {
			output = "stopping\n"
		}
	case "/usr/bin/stat":
		output = "cgroup2fs\n"
		if vm.wrongCgroup {
			output = "tmpfs\n"
		}
	case "/usr/bin/findmnt":
		output = "/dev/vdb ext4 /var/lib/terrascale\n"
		if vm.wrongMount {
			output = "/dev/vdb1 ext4 /var/lib/terrascale\n"
		}
	case "/usr/bin/networkctl":
		output = "State: routable (configured)\nAddress: 10.77.0.10\n"
		if vm.wrongNetwork {
			output = "State: off\nAddress: 127.0.0.1\n"
		}
		if vm.unroutable {
			output = "State: unroutable\nAddress: 169.254.10.2\n"
		}
		if vm.noIPv4 {
			output = "State: routable (configured)\nAddress: fe80::1\n"
		}
	default:
		return fmt.Errorf("unexpected command %s", command.Path)
	}
	if vm.oversizeOutput {
		output = string(bytes.Repeat([]byte("x"), smokeOutputLimit+1))
	}
	if vm.splitOversize {
		output = string(bytes.Repeat([]byte("x"), smokeOutputLimit/2+1))
		if command.Stderr != nil {
			_, _ = io.WriteString(command.Stderr, output)
		}
	}
	if command.Stdout != nil {
		_, _ = io.WriteString(command.Stdout, output)
	}
	return nil
}

func (vm *smokeFakeVM) DataWrite(_ context.Context, path string, data []byte) error {
	if path != "smoke/persistence.bin" {
		return fmt.Errorf("unexpected persistent path %q", path)
	}
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.writeErr != nil {
		return vm.writeErr
	}
	vm.persistent = append([]byte(nil), data...)
	return nil
}

func (vm *smokeFakeVM) DataRead(_ context.Context, path string) ([]byte, error) {
	if path != "smoke/persistence.bin" {
		return nil, fmt.Errorf("unexpected persistent path %q", path)
	}
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.readErr != nil {
		return nil, vm.readErr
	}
	result := append([]byte(nil), vm.persistent...)
	if vm.corruptRead && len(result) > 0 {
		result[0] ^= 0xff
	}
	return result, nil
}

func (vm *smokeFakeVM) HostDiskUsageBytes(context.Context) (uint64, error) {
	return vm.diskBytes, vm.diskErr
}

func (vm *smokeFakeVM) VerifyNoOwnedResources(context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.verifyErr != nil {
		return vm.verifyErr
	}
	if !vm.deleted {
		return errors.New("VM remains")
	}
	return nil
}

func TestRunSmokeProvesBothProfilesAndPersistentData(t *testing.T) {
	factory := &smokeFakeFactory{}
	network := &smokeFakeNetwork{}
	report, err := RunSmoke(context.Background(), factory, network, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Profiles) != 2 || !report.Profiles[0].Supported || !report.Profiles[1].Supported {
		t.Fatalf("profiles = %+v", report.Profiles)
	}
	if report.Profiles[0].Name != "control-only" || report.Profiles[0].MemoryMiB != 512 || report.Profiles[1].Name != "service" || report.Profiles[1].MemoryMiB != 512 {
		t.Fatalf("profile limits = %+v", report.Profiles)
	}
	if report.Boot <= 0 || report.Ready <= 0 || report.Cleanup <= 0 || report.PeakRSSBytes == 0 || report.PeakIdleCPU <= 0 || report.HostDiskBytes == 0 {
		t.Fatalf("report lacks measured evidence: %+v", report)
	}
	for _, profile := range report.Profiles {
		if profile.BootToReady <= 0 || profile.RestartToReady <= 0 || profile.RSSBytes == 0 || profile.IdleCPU <= 0 || profile.HostDiskBytes == 0 {
			t.Fatalf("profile lacks measured evidence: %+v", profile)
		}
	}
	factory.mu.Lock()
	created := append([]*smokeFakeVM(nil), factory.created...)
	factory.mu.Unlock()
	if len(created) != 2 {
		t.Fatalf("created guests = %d", len(created))
	}
	for _, vm := range created {
		vm.mu.Lock()
		if vm.startCalls != 2 || vm.stopCalls != 2 || vm.deleteCall != 1 || !vm.deleted || len(vm.persistent) != 4096 {
			t.Fatalf("guest lifecycle = starts %d stops %d deletes %d deleted %v data %d", vm.startCalls, vm.stopCalls, vm.deleteCall, vm.deleted, len(vm.persistent))
		}
		calls := append([]smokeCommandCall(nil), vm.commands...)
		vm.mu.Unlock()
		if len(calls) != 10 {
			t.Fatalf("diagnostic calls = %d, want 10", len(calls))
		}
		for _, call := range calls {
			request := vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationExecute, Path: call.path, Args: call.args}
			if err := request.Validate(); err != nil {
				t.Fatalf("smoke used unadmitted diagnostic %+v: %v", call, err)
			}
		}
	}
	network.mu.Lock()
	cleaned := network.cleaned
	network.mu.Unlock()
	if !cleaned {
		t.Fatal("network was not cleaned")
	}
}

func TestRunSmokeRecordsUnsupportedControlProfile(t *testing.T) {
	factory := &smokeFakeFactory{support: map[string]bool{"control-only": false}}
	report, err := RunSmoke(context.Background(), factory, &smokeFakeNetwork{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Profiles) != 2 || report.Profiles[0].Supported || !report.Profiles[1].Supported {
		t.Fatalf("profiles = %+v", report.Profiles)
	}
	factory.mu.Lock()
	created := len(factory.created)
	factory.mu.Unlock()
	if created != 1 {
		t.Fatalf("created guests = %d, want 1", created)
	}
}

func TestRunSmokeRejectsFalseGuestEvidenceAndStillCleans(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*smokeFakeVM)
		contains  string
	}{
		{name: "pid1", configure: func(vm *smokeFakeVM) { vm.wrongPID1 = true }, contains: "not systemd"},
		{name: "system state", configure: func(vm *smokeFakeVM) { vm.wrongState = true }, contains: "not running"},
		{name: "cgroup", configure: func(vm *smokeFakeVM) { vm.wrongCgroup = true }, contains: "not cgroup v2"},
		{name: "mount", configure: func(vm *smokeFakeVM) { vm.wrongMount = true }, contains: "mount is invalid"},
		{name: "network", configure: func(vm *smokeFakeVM) { vm.wrongNetwork = true }, contains: "not routable"},
		{name: "unroutable network", configure: func(vm *smokeFakeVM) { vm.unroutable = true }, contains: "not routable"},
		{name: "network without IPv4", configure: func(vm *smokeFakeVM) { vm.noIPv4 = true }, contains: "no usable IPv4"},
		{name: "persistent bytes", configure: func(vm *smokeFakeVM) { vm.corruptRead = true }, contains: "did not preserve"},
		{name: "disk observation", configure: func(vm *smokeFakeVM) { vm.diskBytes = 0 }, contains: "disk usage observation is zero"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			factory := &smokeFakeFactory{configure: testCase.configure}
			network := &smokeFakeNetwork{}
			_, err := RunSmoke(context.Background(), factory, network, time.Second)
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(testCase.contains)) {
				t.Fatalf("error = %v", err)
			}
			if cleanupErr := errors.Join(factory.VerifyNoOwnedResources(context.Background()), network.VerifyNoOwnedResources(context.Background())); cleanupErr != nil {
				t.Fatalf("resources remain after failed assertion: %v", cleanupErr)
			}
		})
	}
}

func TestExecuteGuestBoundsOutput(t *testing.T) {
	vm := &smokeFakeVM{oversizeOutput: true}
	stdout, _, err := executeGuest(context.Background(), vm, "/usr/bin/readlink", "/proc/1/exe")
	if err == nil || len(stdout) != smokeOutputLimit || !bytes.Contains([]byte(err.Error()), []byte("output limit")) {
		t.Fatalf("stdout=%d err=%v", len(stdout), err)
	}
}

func TestExecuteGuestBoundsCombinedOutput(t *testing.T) {
	vm := &smokeFakeVM{splitOversize: true}
	stdout, stderr, err := executeGuest(context.Background(), vm, "/usr/bin/readlink", "/proc/1/exe")
	if err == nil || len(stdout)+len(stderr) != smokeOutputLimit || !bytes.Contains([]byte(err.Error()), []byte("output limit")) {
		t.Fatalf("stdout=%d stderr=%d err=%v", len(stdout), len(stderr), err)
	}
}

func TestRunSmokeRetriesFailedProfileCleanup(t *testing.T) {
	want := errors.New("transient stop failure")
	factory := &smokeFakeFactory{configure: func(vm *smokeFakeVM) {
		vm.stopErr = want
		vm.stopErrAt = 2
	}}
	_, err := RunSmoke(context.Background(), factory, &smokeFakeNetwork{}, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
	factory.mu.Lock()
	vm := factory.created[0]
	factory.mu.Unlock()
	vm.mu.Lock()
	stopCalls, deleteCalls := vm.stopCalls, vm.deleteCall
	vm.mu.Unlock()
	if stopCalls != 3 || deleteCalls != 2 {
		t.Fatalf("cleanup calls = stop %d delete %d, want stop 3 delete 2", stopCalls, deleteCalls)
	}
}

func TestRunSmokeUsesFreshCleanupContextAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	factory := &smokeFakeFactory{}
	network := &smokeFakeNetwork{}
	_, err := RunSmoke(ctx, factory, network, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	factory.mu.Lock()
	created := append([]*smokeFakeVM(nil), factory.created...)
	factory.mu.Unlock()
	for _, vm := range created {
		vm.mu.Lock()
		cleanupCtxErr := vm.cleanupCtxErr
		deleted := vm.deleted
		vm.mu.Unlock()
		if cleanupCtxErr != nil || !deleted {
			t.Fatalf("cleanup context=%v deleted=%v", cleanupCtxErr, deleted)
		}
	}
	if cleanupErr := errors.Join(factory.VerifyNoOwnedResources(context.Background()), network.VerifyNoOwnedResources(context.Background())); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
}

func TestRunSmokePropagatesCleanupVerificationFailure(t *testing.T) {
	want := errors.New("owned TAP remains")
	factory := &smokeFakeFactory{}
	network := &smokeFakeNetwork{verifyErr: want}
	report, err := RunSmoke(context.Background(), factory, network, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
	if report.Cleanup <= 0 {
		t.Fatalf("cleanup duration = %s", report.Cleanup)
	}
}

func TestRunSmokeRejectsMissingFocusedCapabilities(t *testing.T) {
	factory := &smokeIncompleteFactory{}
	_, err := RunSmoke(context.Background(), factory, &smokeFakeNetwork{}, time.Second)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("persistent-data channel")) {
		t.Fatalf("error = %v", err)
	}
}

type smokeIncompleteFactory struct{ vm *smokeIncompleteVM }

func (factory *smokeIncompleteFactory) Create(_ context.Context, guest Guest) (VM, error) {
	factory.vm = &smokeIncompleteVM{guest: guest}
	return factory.vm, nil
}

func (factory *smokeIncompleteFactory) VerifyNoOwnedResources(context.Context) error {
	if factory.vm != nil && !factory.vm.deleted {
		return errors.New("incomplete VM remains")
	}
	return nil
}

type smokeIncompleteVM struct {
	guest   Guest
	deleted bool
}

func (vm *smokeIncompleteVM) StartReady(context.Context) error { return nil }
func (vm *smokeIncompleteVM) Stop(context.Context) error       { return nil }
func (vm *smokeIncompleteVM) Delete(context.Context) error {
	vm.deleted = true
	return nil
}
func (vm *smokeIncompleteVM) Inspect(context.Context) (VMObservation, error) {
	return VMObservation{ID: vm.guest.ID, Region: vm.guest.Region, Running: true, Ready: true, MemoryMiB: vm.guest.MemoryMiB, RSSBytes: 1, IdleCPU: 0.01, CPUSampled: true}, nil
}
func (vm *smokeIncompleteVM) Execute(context.Context, sandboxvm.Command) error { return nil }
func (vm *smokeIncompleteVM) VerifyNoOwnedResources(context.Context) error {
	if !vm.deleted {
		return errors.New("incomplete VM remains")
	}
	return nil
}
