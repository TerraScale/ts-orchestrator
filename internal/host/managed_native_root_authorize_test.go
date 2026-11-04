//go:build linux

package host

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
)

func TestManagedNativeRootAuthorizesLiveRunnerAndRevokesStaleWitnesses(t *testing.T) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	membership, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "0::")
	if !ok || membership == "" || !filepath.IsAbs(membership) || filepath.Clean(membership) != membership {
		t.Skip("requires one unified cgroup v2 membership")
	}
	cgroupPath := filepath.Join("/sys/fs/cgroup", membership)
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(cgroupPath, &filesystem); err != nil || filesystem.Type != cgroup2SuperMagic {
		t.Skipf("requires a live kernel cgroup v2 witness: %v", err)
	}
	pid := os.Getpid()
	contained, err := nativeCgroupContainsPID(cgroupPath, pid)
	if err != nil || !contained {
		t.Fatalf("test process lacks its kernel cgroup witness: contained=%t err=%v", contained, err)
	}
	limit, err := readCgroupMemoryMax(cgroupPath)
	if err != nil {
		t.Fatal(err)
	}
	start := currentStartTime(pid)
	if start == "" {
		t.Fatal("test process has no live /proc start time")
	}
	role := filepath.Base(cgroupPath)
	peer := nativerootoci.Peer{PID: pid, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newAgent := func(t *testing.T) (*Agent, *processRunner, *managedNativeRoot, Desired) {
		t.Helper()
		desired := Desired{Role: role, Digest: digest,
			ManagedMember: &ManagedMemberLaunch{VolumeID: "fixture-volume", CgroupMemoryMaxBytes: limit}}
		fingerprint, err := desiredFingerprint(desired)
		if err != nil {
			t.Fatal(err)
		}
		runner := &processRunner{cgroups: filepath.Dir(cgroupPath), records: map[string]processRecord{
			role: {Role: role, Digest: digest, Fingerprint: fingerprint, PID: pid, StartTime: start},
		}}
		root := &managedNativeRoot{role: role, fingerprint: fingerprint}
		agent := &Agent{cfg: AgentConfig{WorkloadIdentity: WorkloadIdentity{UID: peer.UID, GID: peer.GID},
			ClockCheck: func() error { return nil }}, runner: runner,
			nativeRoots: map[string]*managedNativeRoot{role: root}}
		if err := agent.acceptSession(session{SessionID: "0000000000GW5TVN8XNYT7ZYN0", Epoch: 1,
			ExpiresAt: time.Now().Add(sessionTTL)}); err != nil {
			t.Fatal(err)
		}
		agent.managedGate(desired)
		if err := agent.pinManagedNativeRootDesired(role, fingerprint); err != nil {
			t.Fatal(err)
		}
		return agent, runner, root, desired
	}

	agent, runner, root, desired := newAgent(t)
	observed, err := runner.Observe(t.Context(), role)
	if err != nil || !observed.Running || observed.PID != pid || observed.Digest != digest ||
		observed.Fingerprint != root.fingerprint || observed.CgroupMemoryMaxBytes != limit {
		t.Fatalf("concrete process runner did not observe the live cgroup member: %+v, %v", observed, err)
	}
	deadline, err := agent.authorizeManagedNativeRoot(t.Context(), peer, desired, root)
	if err != nil || !deadline.Equal(agent.nativeDesired[role].until) || !deadline.After(time.Now()) {
		t.Fatalf("live member authorization deadline = %s, err = %v", deadline, err)
	}

	for _, test := range []struct {
		name   string
		change func(*Agent, *processRunner, *managedNativeRoot, *Desired, *nativerootoci.Peer)
		want   string
	}{
		{name: "expired desired", change: func(a *Agent, _ *processRunner, _ *managedNativeRoot, _ *Desired, _ *nativerootoci.Peer) {
			a.nativeDesired[role] = nativeRootDesired{fingerprint: a.nativeDesired[role].fingerprint, until: time.Now().Add(-time.Second)}
		}, want: "no longer active"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "outside role cgroup" {
				outside, err := nativeCgroupContainsPID(cgroupPath, 1)
				if err != nil || outside || currentStartTime(1) == "" {
					t.Skip("requires a live PID 1 outside the test role cgroup")
				}
			}
			a, r, active, d := newAgent(t)
			p := peer
			test.change(a, r, active, &d, &p)
			if _, err := a.authorizeManagedNativeRoot(t.Context(), p, d, active); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("stale native root witness was accepted or denied by wrong check: %v", err)
			}
		})
	}
}
