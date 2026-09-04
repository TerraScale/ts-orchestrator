package vmqual

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const (
	smokeControlMemoryMiB = int64(256)
	smokeOutputLimit      = 64 << 10
	smokeUsagePoll        = 25 * time.Millisecond
	maxSmokeUsageWait     = 2 * time.Second
)

type guestExecutor interface {
	Execute(context.Context, sandboxvm.Command) error
}

// smokePersistentGuest is the typed data-disk part of the test-only guest
// channel. It cannot install or activate a service.
type smokePersistentGuest interface {
	DataWrite(context.Context, string, []byte) error
	DataRead(context.Context, string) ([]byte, error)
}

// smokeHostDiskObserver reports allocated host bytes for all file-backed
// drives owned by one VM. Guest filesystem output is not host resource proof.
type smokeHostDiskObserver interface {
	HostDiskUsageBytes(context.Context) (uint64, error)
}

// smokeOwnedResourceVerifier checks an owner's exact journalled resources. It
// must not discover resources by process name or a broad filesystem search.
type smokeOwnedResourceVerifier interface {
	VerifyNoOwnedResources(context.Context) error
}

// smokeProfileSupport lets an image explicitly decline the optional 256 MiB
// profile. The service profile is mandatory and cannot be declined.
type smokeProfileSupport interface {
	SupportsSmokeProfile(context.Context, SmokeProfile) (bool, error)
}

type smokeNetworkExchange interface {
	ProveGuestExchange(context.Context, VM) error
}

type SmokeProfile struct {
	Name  string
	Guest Guest
}

type SmokeProfileReport struct {
	Name           string
	MemoryMiB      int64
	Supported      bool
	BootToReady    time.Duration
	RestartToReady time.Duration
	RSSBytes       uint64
	IdleCPU        float64
	HostDiskBytes  uint64
}

type SmokeReport struct {
	// Boot is the sum of initial boot-to-ready intervals for supported profiles.
	// Ready covers the full guest proof, excluding cleanup.
	Boot    time.Duration
	Ready   time.Duration
	Cleanup time.Duration

	Profiles      []SmokeProfileReport
	PeakRSSBytes  uint64
	PeakIdleCPU   float64
	HostDiskBytes uint64
}

// RunSmoke proves the minimum real guest path. The command supplies a
// Firecracker factory. Unit tests may inject a narrow VM fake, but vm-smoke has
// no fallback backend.
func RunSmoke(ctx context.Context, factory VMFactory, network NetworkController, timeout time.Duration) (report SmokeReport, resultErr error) {
	if ctx == nil {
		return report, errors.New("vmqual: smoke context is nil")
	}
	if factory == nil || network == nil {
		return report, errors.New("vmqual: smoke factory and network are required")
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	factoryVerifier, ok := factory.(smokeOwnedResourceVerifier)
	if !ok {
		return report, errors.New("vm-smoke: factory cannot verify owned-resource cleanup")
	}
	networkVerifier, ok := network.(smokeOwnedResourceVerifier)
	if !ok {
		return report, errors.New("vm-smoke: network cannot verify owned-resource cleanup")
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	networkAttempted := false
	var active VM
	cleanup := func() error {
		started := time.Now()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cleanupCancel()
		var cleanupErr error
		if active != nil {
			cleanupErr = errors.Join(cleanupErr, active.Stop(cleanupCtx), active.Delete(cleanupCtx), verifyGuestCleanup(cleanupCtx, active))
			active = nil
		}
		if networkAttempted {
			cleanupErr = errors.Join(cleanupErr, network.Cleanup(cleanupCtx))
			networkAttempted = false
		}
		cleanupErr = errors.Join(cleanupErr, factoryVerifier.VerifyNoOwnedResources(cleanupCtx), networkVerifier.VerifyNoOwnedResources(cleanupCtx))
		report.Cleanup += time.Since(started)
		return cleanupErr
	}
	defer func() {
		resultErr = errors.Join(resultErr, cleanup())
	}()

	// Apply may fail after creating only part of the network. Mark the attempt
	// first so the cleanup plan always gets a chance to remove that partial set.
	networkAttempted = true
	if err := network.Apply(runCtx); err != nil {
		return report, fmt.Errorf("vm-smoke: apply network: %w", err)
	}

	for _, profile := range smokeProfiles() {
		supported, err := supportsSmokeProfile(runCtx, factory, profile)
		if err != nil {
			return report, err
		}
		profileReport := SmokeProfileReport{Name: profile.Name, MemoryMiB: profile.Guest.MemoryMiB, Supported: supported}
		if !supported {
			if profile.Name == "service" {
				return report, errors.New("vm-smoke: the mandatory service profile is unsupported")
			}
			report.Profiles = append(report.Profiles, profileReport)
			continue
		}

		vm, err := factory.Create(runCtx, profile.Guest)
		if err != nil {
			return report, fmt.Errorf("vm-smoke: create %s profile: %w", profile.Name, err)
		}
		if vm == nil {
			return report, fmt.Errorf("vm-smoke: %s profile factory returned a nil guest", profile.Name)
		}
		active = vm
		profileStarted := time.Now()
		profileReport, err = proveSmokeProfile(runCtx, vm, network, profile, profileReport)
		report.Ready += time.Since(profileStarted)
		report.Profiles = append(report.Profiles, profileReport)
		report.Boot += profileReport.BootToReady
		if profileReport.RSSBytes > report.PeakRSSBytes {
			report.PeakRSSBytes = profileReport.RSSBytes
		}
		if profileReport.IdleCPU > report.PeakIdleCPU {
			report.PeakIdleCPU = profileReport.IdleCPU
		}
		if profileReport.HostDiskBytes > report.HostDiskBytes {
			report.HostDiskBytes = profileReport.HostDiskBytes
		}
		if err != nil {
			return report, fmt.Errorf("vm-smoke: %s profile: %w", profile.Name, err)
		}

		cleanupStarted := time.Now()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		stopErr := active.Stop(cleanupCtx)
		deleteErr := active.Delete(cleanupCtx)
		verifyErr := verifyGuestCleanup(cleanupCtx, active)
		cleanupCancel()
		report.Cleanup += time.Since(cleanupStarted)
		if err := errors.Join(stopErr, deleteErr, verifyErr); err != nil {
			return report, fmt.Errorf("vm-smoke: clean %s profile: %w", profile.Name, err)
		}
		active = nil
	}
	return report, nil
}

func smokeProfiles() []SmokeProfile {
	serviceMemory := DefaultMemoryMiB
	if serviceMemory > MaxGuestMemoryMiB {
		serviceMemory = MaxGuestMemoryMiB
	}
	return []SmokeProfile{
		{Name: "control-only", Guest: Guest{ID: "gru-member-1", Region: vmnet.GRU, VCPU: 1, MemoryMiB: smokeControlMemoryMiB, Control: true}},
		{Name: "service", Guest: Guest{ID: "gru-member-1", Region: vmnet.GRU, VCPU: 1, MemoryMiB: serviceMemory, Control: true, Service: true}},
	}
}

func supportsSmokeProfile(ctx context.Context, factory VMFactory, profile SmokeProfile) (bool, error) {
	if profile.Guest.VCPU != 1 || profile.Guest.MemoryMiB < smokeControlMemoryMiB || profile.Guest.MemoryMiB > MaxGuestMemoryMiB {
		return false, fmt.Errorf("vm-smoke: profile %s exceeds the 1 vCPU/512 MiB limit", profile.Name)
	}
	capabilities, ok := factory.(smokeProfileSupport)
	if !ok {
		return true, nil
	}
	supported, err := capabilities.SupportsSmokeProfile(ctx, profile)
	if err != nil {
		return false, fmt.Errorf("vm-smoke: inspect %s profile support: %w", profile.Name, err)
	}
	return supported, nil
}

func proveSmokeProfile(ctx context.Context, vm VM, network NetworkController, profile SmokeProfile, report SmokeProfileReport) (SmokeProfileReport, error) {
	executor, ok := vm.(guestExecutor)
	if !ok {
		return report, errors.New("guest execution channel is not configured")
	}
	persistent, ok := vm.(smokePersistentGuest)
	if !ok {
		return report, errors.New("guest persistent-data channel is not configured")
	}
	diskObserver, ok := vm.(smokeHostDiskObserver)
	if !ok {
		return report, errors.New("guest cannot report host disk usage")
	}
	if _, ok := vm.(smokeOwnedResourceVerifier); !ok {
		return report, errors.New("guest cannot verify owned-resource cleanup")
	}
	exchange, ok := network.(smokeNetworkExchange)
	if !ok {
		return report, errors.New("qualification network cannot prove a guest exchange")
	}

	started := time.Now()
	if err := vm.StartReady(ctx); err != nil {
		return report, fmt.Errorf("guest did not become ready: %w", err)
	}
	report.BootToReady = time.Since(started)
	initial, err := vm.Inspect(ctx)
	if err != nil {
		return report, fmt.Errorf("inspect initial guest readiness: %w", err)
	}
	if err := validateObservationIdentity(initial, profile.Guest); err != nil {
		return report, fmt.Errorf("initial guest readiness: %w", err)
	}
	if err := proveGuestRuntime(ctx, executor); err != nil {
		return report, err
	}
	if err := exchange.ProveGuestExchange(ctx, vm); err != nil {
		return report, fmt.Errorf("guest network exchange: %w", err)
	}

	payload := make([]byte, 4096)
	if _, err := cryptorand.Read(payload); err != nil {
		return report, fmt.Errorf("create persistence proof: %w", err)
	}
	const persistencePath = "smoke/persistence.bin"
	if err := persistent.DataWrite(ctx, persistencePath, payload); err != nil {
		return report, fmt.Errorf("write persistent data: %w", err)
	}
	if err := vm.Stop(ctx); err != nil {
		return report, fmt.Errorf("stop for persistence proof: %w", err)
	}
	restarted := time.Now()
	if err := vm.StartReady(ctx); err != nil {
		return report, fmt.Errorf("restart for persistence proof: %w", err)
	}
	report.RestartToReady = time.Since(restarted)
	if err := proveGuestRuntime(ctx, executor); err != nil {
		return report, fmt.Errorf("runtime after restart: %w", err)
	}
	persisted, err := persistent.DataRead(ctx, persistencePath)
	if err != nil {
		return report, fmt.Errorf("read persistent data after restart: %w", err)
	}
	if !bytes.Equal(persisted, payload) {
		return report, errors.New("data disk did not preserve bytes across stop/start")
	}

	report.HostDiskBytes, err = diskObserver.HostDiskUsageBytes(ctx)
	if err != nil {
		return report, fmt.Errorf("observe host disk usage: %w", err)
	}
	if report.HostDiskBytes == 0 {
		return report, errors.New("host disk usage observation is zero")
	}
	observation, err := observeMeasuredUsage(ctx, vm, profile.Guest)
	if err != nil {
		return report, err
	}
	report.RSSBytes, report.IdleCPU = observation.RSSBytes, observation.IdleCPU
	return report, nil
}

func proveGuestRuntime(ctx context.Context, executor guestExecutor) error {
	pid1, _, err := executeGuest(ctx, executor, "/usr/bin/readlink", "/proc/1/exe")
	if err != nil {
		return fmt.Errorf("inspect PID 1: %w", err)
	}
	pid1Path := strings.TrimSpace(string(pid1))
	if !filepath.IsAbs(pid1Path) || filepath.Base(pid1Path) != "systemd" {
		return fmt.Errorf("PID 1 is %q, not systemd", pid1Path)
	}
	state, _, err := executeGuest(ctx, executor, "/usr/bin/systemctl", "is-system-running", "--wait")
	if err != nil {
		return fmt.Errorf("systemd is not running: %w", err)
	}
	if systemState := strings.TrimSpace(string(state)); systemState != "running" {
		return fmt.Errorf("systemd is not running: state is %q", systemState)
	}
	cgroup, _, err := executeGuest(ctx, executor, "/usr/bin/stat", "-fc", "%T", "/sys/fs/cgroup")
	if err != nil {
		return fmt.Errorf("inspect cgroup filesystem: %w", err)
	}
	if strings.TrimSpace(string(cgroup)) != "cgroup2fs" {
		return fmt.Errorf("guest cgroup filesystem is %q, not cgroup v2", strings.TrimSpace(string(cgroup)))
	}
	mount, _, err := executeGuest(ctx, executor, "/usr/bin/findmnt", "-no", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale")
	if err != nil {
		return fmt.Errorf("inspect data mount: %w", err)
	}
	mountFields := strings.Fields(string(mount))
	if len(mountFields) != 3 || mountFields[0] != "/dev/vdb" || mountFields[1] != "ext4" || mountFields[2] != "/var/lib/terrascale" {
		return fmt.Errorf("data disk mount is invalid: %q", strings.TrimSpace(string(mount)))
	}
	network, _, err := executeGuest(ctx, executor, "/usr/bin/networkctl", "status", "eth0", "--no-pager")
	if err != nil {
		return fmt.Errorf("inspect guest network: %w", err)
	}
	if err := validateGuestNetworkConfiguration(network); err != nil {
		return err
	}
	return nil
}

// validateGuestNetworkConfiguration checks only the configured interface.
// The separate smokeNetworkExchange is the connectivity proof.
func validateGuestNetworkConfiguration(output []byte) error {
	text := string(output)
	routable := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(strings.TrimSuffix(fields[0], ":"), "state") && strings.EqualFold(fields[1], "routable") {
			routable = true
			break
		}
	}
	if !routable {
		return errors.New("guest eth0 is not routable")
	}
	for _, token := range strings.Fields(text) {
		value := strings.Trim(token, "[](),")
		if address, err := netip.ParseAddr(value); err == nil && address.Is4() && address.IsGlobalUnicast() {
			return nil
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
			return nil
		}
	}
	return errors.New("guest eth0 has no usable IPv4 address")
}

func observeMeasuredUsage(ctx context.Context, vm VM, guest Guest) (VMObservation, error) {
	deadline := time.Now().Add(maxSmokeUsageWait)
	var last VMObservation
	for {
		observation, err := vm.Inspect(ctx)
		if err != nil {
			return VMObservation{}, fmt.Errorf("inspect guest resources: %w", err)
		}
		last = observation
		if err := validateObservationIdentity(observation, guest); err != nil {
			return VMObservation{}, err
		}
		if observation.RSSBytes > 0 && observation.CPUSampled && observation.IdleCPU >= 0 && !math.IsNaN(observation.IdleCPU) && !math.IsInf(observation.IdleCPU, 0) {
			return observation, nil
		}
		if time.Now().After(deadline) {
			return VMObservation{}, fmt.Errorf("host resource observation was incomplete: rss=%d cpu=%g sampled=%t", last.RSSBytes, last.IdleCPU, last.CPUSampled)
		}
		timer := time.NewTimer(smokeUsagePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return VMObservation{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func validateObservationIdentity(observation VMObservation, guest Guest) error {
	if !observation.Running || !observation.Ready {
		return errors.New("guest reported not ready after StartReady")
	}
	if observation.ID != guest.ID {
		return fmt.Errorf("readiness identity mismatch: %q", observation.ID)
	}
	if observation.Region != guest.Region {
		return fmt.Errorf("readiness Region mismatch: %q", observation.Region)
	}
	if observation.MemoryMiB != guest.MemoryMiB {
		return fmt.Errorf("readiness memory mismatch: %d MiB", observation.MemoryMiB)
	}
	return nil
}

func verifyGuestCleanup(ctx context.Context, vm VM) error {
	verifier, ok := vm.(smokeOwnedResourceVerifier)
	if !ok {
		return errors.New("vm-smoke: guest cannot verify owned-resource cleanup")
	}
	return verifier.VerifyNoOwnedResources(ctx)
}

func executeGuest(ctx context.Context, executor guestExecutor, path string, args ...string) ([]byte, []byte, error) {
	budget := &smokeOutputBudget{}
	stdout := smokeOutput{budget: budget}
	stderr := smokeOutput{budget: budget}
	err := executor.Execute(ctx, sandboxvm.Command{Path: path, Args: append([]string(nil), args...), Stdout: &stdout, Stderr: &stderr})
	if stdout.exceeded() || stderr.exceeded() {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("guest command %s exceeded the %d-byte output limit", path, smokeOutputLimit)
	}
	if err != nil {
		detail := strings.TrimSpace(string(stderr.Bytes()))
		if detail == "" {
			return stdout.Bytes(), stderr.Bytes(), err
		}
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("%w: %s", err, detail)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

type smokeOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
	budget   *smokeOutputBudget
}

func (b *smokeOutput) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(value)
	stored := written
	if b.budget != nil {
		stored = b.budget.reserve(written)
	} else if remaining := smokeOutputLimit - b.buffer.Len(); stored > remaining {
		stored = remaining
	}
	if stored > 0 {
		_, _ = b.buffer.Write(value[:stored])
	}
	if stored < written {
		b.overflow = true
	}
	return written, nil
}

func (b *smokeOutput) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *smokeOutput) exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

type smokeOutputBudget struct {
	mu   sync.Mutex
	used int
}

func (b *smokeOutputBudget) reserve(requested int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := smokeOutputLimit - b.used
	if remaining <= 0 {
		return 0
	}
	if requested > remaining {
		requested = remaining
	}
	b.used += requested
	return requested
}
