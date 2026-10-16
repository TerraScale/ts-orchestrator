//go:build linux

package execution

import (
	"context"
	"reflect"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

func TestRuntimeSpecRefusesAdmissionDrift(t *testing.T) {
	pins := RuntimePins{
		Process: runtimespec.Process{User: runtimespec.User{UID: 65534, GID: 65534}, Args: []string{"/terrabase"},
			Cwd: "/", NoNewPrivileges: true, Capabilities: &runtimespec.LinuxCapabilities{}},
		Resources: runtimespec.LinuxResources{Memory: &runtimespec.LinuxMemory{Limit: new(int64(64 << 20))}},
		Mounts:    []runtimespec.Mount{{Source: "/run/retained/volume", Destination: "/retained", Type: "bind", Options: []string{"rbind", "nosuid", "nodev", "noexec", "noatime"}}},
		Volume:    hostvolume.MountPins{MountPath: "/run/retained/volume"}, VolumeDestination: "/retained",
	}
	makeSpec := func() *runtimespec.Spec {
		return &runtimespec.Spec{Root: &runtimespec.Root{Readonly: true}, Process: &pins.Process, Mounts: pins.Mounts,
			Linux: &runtimespec.Linux{CgroupsPath: "/terrascale/ts-member", Resources: &pins.Resources, Namespaces: []runtimespec.LinuxNamespace{{Type: runtimespec.PIDNamespace}, {Type: runtimespec.MountNamespace}}}}
	}
	if err := verifyRuntimeSpec(makeSpec(), pins, "ts-member"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runtimespec.Spec){
		"writable root": func(spec *runtimespec.Spec) { spec.Root.Readonly = false },
		"different process": func(spec *runtimespec.Spec) {
			process := *spec.Process
			process.Args = []string{"/different-member"}
			spec.Process = &process
		},
		"different limits": func(spec *runtimespec.Spec) {
			spec.Linux.Resources = &runtimespec.LinuxResources{Memory: &runtimespec.LinuxMemory{Limit: new(int64(128 << 20))}}
		},
		"different mount": func(spec *runtimespec.Spec) {
			spec.Mounts = []runtimespec.Mount{{Source: "/run/another-volume", Destination: "/retained", Type: "bind"}}
		},
		"different cgroup":     func(spec *runtimespec.Spec) { spec.Linux.CgroupsPath = "/other" },
		"host PID namespace":   func(spec *runtimespec.Spec) { spec.Linux.Namespaces[0].Path = "/proc/1/ns/pid" },
		"host mount namespace": func(spec *runtimespec.Spec) { spec.Linux.Namespaces[1].Path = "/proc/1/ns/mnt" },
		"user namespace": func(spec *runtimespec.Spec) {
			spec.Linux.Namespaces = append(spec.Linux.Namespaces, runtimespec.LinuxNamespace{Type: runtimespec.UserNamespace})
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := makeSpec()
			mutate(spec)
			if err := verifyRuntimeSpec(spec, pins, "ts-member"); err == nil {
				t.Fatal("actual runtime drift accepted")
			}
		})
	}
	if !reflect.DeepEqual(makeSpec().Process, &pins.Process) {
		t.Fatal("drift fixtures mutated admitted process pins")
	}
}

func TestRuntimeObserverRequiresConcreteClient(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context()} {
		if _, err := (RuntimeObserver{}).Observe(ctx, RuntimePins{}); err == nil {
			t.Fatal("missing concrete runtime client accepted")
		}
	}
}
