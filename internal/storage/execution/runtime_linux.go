//go:build linux

package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/moby/swarmkit/v2/api"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// RuntimePins come from verified service admission, never task-supplied pins.
// These values describe what to observe; they do not authorize execution.
type RuntimePins struct {
	Task                *api.Task
	ContainerSpecSHA256 string
	Image               string
	Process             runtimespec.Process
	Resources           runtimespec.LinuxResources
	Mounts              []runtimespec.Mount
	Volume              hostvolume.MountPins
	VolumeDestination   string
}

// RuntimeObservation preserves both the host identity and kernel-derived
// member namespace identity. A caller-provided observation is not authority.
type RuntimeObservation struct {
	Process                      memberstatus.ProcessObservation
	ContainerID                  string
	PIDNamespace, MountNamespace uint64
	State                        containerd.ProcessStatus
}

type RuntimeObserver struct {
	Client *containerd.Client
}

// Observe inspects a real created or running container after NewTask has
// allocated its namespaces. A created process cannot supply serving evidence.
func (o RuntimeObserver) Observe(ctx context.Context, pins RuntimePins) (RuntimeObservation, error) {
	if ctx == nil || ctx.Err() != nil || o.Client == nil {
		return RuntimeObservation{}, ErrUnsafe
	}
	binding, err := TaskSHA256(pins.Task)
	if err != nil {
		return RuntimeObservation{}, err
	}
	generic := pins.Task.Spec.GetGeneric()
	if !Stateful(pins.Task) || generic == nil || generic.Kind != "terrascale.stateful-container.v1" ||
		generic.Payload == nil || generic.Payload.TypeUrl != "terrascale.tech/runtime/stateful-container/v1" ||
		pins.ContainerSpecSHA256 != binding || pins.Image == "" ||
		pins.Process.User.UID == 0 || pins.Process.User.GID == 0 ||
		pins.Volume.UID != pins.Process.User.UID || pins.Volume.GID != pins.Process.User.GID ||
		pins.Resources.Memory == nil || pins.Resources.Memory.Limit == nil || *pins.Resources.Memory.Limit <= 0 {
		return RuntimeObservation{}, ErrUnsafe
	}
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	id := "ts-" + pins.Task.ID
	container, err := o.Client.LoadContainer(ctx, id)
	if err != nil {
		return RuntimeObservation{}, err
	}
	verify := func() error {
		info, err := container.Info(ctx)
		if err != nil {
			return err
		}
		if info.ID != id || info.Image != pins.Image || info.Runtime.Name != "io.containerd.runc.v2" ||
			info.Labels["terrascale.task"] != pins.Task.ID || info.Labels["terrascale.service"] != pins.Task.ServiceID ||
			info.Labels["terrascale.spec"] != binding || info.Labels["terrascale.task-binding"] != binding {
			return errors.New("actual container identity differs from admitted task")
		}
		spec, err := container.Spec(ctx)
		if err != nil {
			return err
		}
		return verifyRuntimeSpec(spec, pins, id)
	}
	if err := verify(); err != nil {
		return RuntimeObservation{}, errors.Join(ErrUnsafe, err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return RuntimeObservation{}, err
	}
	status, err := task.Status(ctx)
	if err != nil || (status.Status != containerd.Created && status.Status != containerd.Running) || task.Pid() < 2 {
		return RuntimeObservation{}, errors.Join(ErrUnsafe, err)
	}
	pid := int(task.Pid())
	processes, err := task.Pids(ctx)
	if err != nil {
		return RuntimeObservation{}, err
	}
	found := false
	for _, process := range processes {
		found = found || process.Pid == task.Pid()
	}
	if !found {
		return RuntimeObservation{}, errors.New("container init is absent from actual runtime processes")
	}
	before, err := memberstatus.ObserveContainerProcess(pid, pid)
	if err != nil {
		return RuntimeObservation{}, err
	}
	if before.UID != pins.Process.User.UID || before.GID != pins.Process.User.GID || before.ProtocolPID() != 1 {
		return RuntimeObservation{}, errors.New("actual container member user or init identity differs")
	}
	if err := verifyRuntimeLimits(before.Cgroup, id, pins.Resources); err != nil {
		return RuntimeObservation{}, err
	}
	mount, err := hostvolume.ObserveMount(pins.Volume)
	if err != nil {
		return RuntimeObservation{}, err
	}
	defer mount.Close()
	if err := mount.VerifyContainerMount(pid, pins.VolumeDestination); err != nil {
		return RuntimeObservation{}, err
	}
	var pidNS, mountNS unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &pidNS); err != nil {
		return RuntimeObservation{}, err
	}
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &mountNS); err != nil {
		return RuntimeObservation{}, err
	}
	if err := verify(); err != nil {
		return RuntimeObservation{}, err
	}
	current, err := container.Task(ctx, nil)
	if err != nil || current.Pid() != task.Pid() {
		return RuntimeObservation{}, errors.Join(ErrUnsafe, err)
	}
	currentStatus, err := current.Status(ctx)
	if err != nil || currentStatus.Status != status.Status {
		return RuntimeObservation{}, errors.Join(ErrUnsafe, err)
	}
	after, err := memberstatus.ObserveContainerProcess(pid, pid)
	if err != nil || before != after {
		return RuntimeObservation{}, memberstatus.ErrStaleBinding
	}
	if err := mount.Recheck(); err != nil {
		return RuntimeObservation{}, err
	}
	if err := verifyRuntimeLimits(after.Cgroup, id, pins.Resources); err != nil {
		return RuntimeObservation{}, err
	}
	if err := mount.VerifyContainerMount(pid, pins.VolumeDestination); err != nil {
		return RuntimeObservation{}, err
	}
	return RuntimeObservation{Process: before, ContainerID: id, PIDNamespace: pidNS.Ino, MountNamespace: mountNS.Ino, State: status.Status}, nil
}

func verifyRuntimeSpec(actual *runtimespec.Spec, pins RuntimePins, id string) error {
	if actual == nil || actual.Process == nil || actual.Linux == nil || actual.Root == nil || !actual.Root.Readonly ||
		!reflect.DeepEqual(*actual.Process, pins.Process) || !reflect.DeepEqual(actual.Linux.Resources, &pins.Resources) ||
		!reflect.DeepEqual(actual.Mounts, pins.Mounts) || actual.Linux.CgroupsPath != "/terrascale/"+id {
		return errors.New("actual OCI process, resources, mounts, or cgroup differs from admission")
	}
	pidNS, mountNS, boundVolume := 0, 0, 0
	for _, namespace := range actual.Linux.Namespaces {
		switch namespace.Type {
		case runtimespec.PIDNamespace:
			pidNS++
			if namespace.Path != "" {
				return errors.New("container must own its PID namespace")
			}
		case runtimespec.MountNamespace:
			mountNS++
			if namespace.Path != "" {
				return errors.New("container must own its mount namespace")
			}
		case runtimespec.UserNamespace:
			return errors.New("member user namespace mapping is not admitted")
		}
	}
	for _, mount := range actual.Mounts {
		if mount.Destination == pins.VolumeDestination {
			boundVolume++
			if mount.Source != pins.Volume.MountPath || mount.Type != "bind" {
				return errors.New("OCI volume bind differs from retained host mount")
			}
		}
	}
	if pidNS != 1 || mountNS != 1 || boundVolume != 1 || !pins.Process.NoNewPrivileges ||
		pins.Process.Capabilities == nil || len(pins.Process.Capabilities.Bounding)+len(pins.Process.Capabilities.Effective)+
		len(pins.Process.Capabilities.Permitted)+len(pins.Process.Capabilities.Inheritable)+len(pins.Process.Capabilities.Ambient) != 0 {
		return errors.New("OCI member isolation or retained bind is incomplete")
	}
	return nil
}

func verifyRuntimeLimits(cgroup, id string, resources runtimespec.LinuxResources) error {
	value, ok := strings.CutPrefix(cgroup, "0::")
	value = strings.TrimSuffix(value, "\n")
	if !ok || value != "/terrascale/"+id || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("actual member cgroup differs from the container task")
	}
	limit, err := os.ReadFile(path.Join("/sys/fs/cgroup", value, "memory.max"))
	if err != nil {
		return err
	}
	current, err := strconv.ParseInt(strings.TrimSpace(string(limit)), 10, 64)
	if err != nil || resources.Memory == nil || resources.Memory.Limit == nil || current != *resources.Memory.Limit {
		return errors.New("actual member cgroup memory limit differs from admission")
	}
	if resources.Memory.Swap == nil || *resources.Memory.Swap != *resources.Memory.Limit {
		return errors.New("member resource policy must exclude swap")
	}
	swap, err := os.ReadFile(path.Join("/sys/fs/cgroup", value, "memory.swap.max"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(swap)) != "0" {
		return errors.New("actual member cgroup permits swap")
	}
	if resources.CPU == nil || resources.CPU.Quota == nil || resources.CPU.Period == nil ||
		*resources.CPU.Quota <= 0 || *resources.CPU.Period == 0 {
		return errors.New("member CPU bandwidth requires exact admitted quota and period")
	}
	cpu, err := os.ReadFile(path.Join("/sys/fs/cgroup", value, "cpu.max"))
	if err != nil {
		return err
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 || fields[0] != strconv.FormatInt(*resources.CPU.Quota, 10) ||
		fields[1] != strconv.FormatUint(*resources.CPU.Period, 10) {
		return errors.New("actual member cgroup CPU bandwidth differs from admission")
	}
	if resources.Pids == nil || resources.Pids.Limit == nil || *resources.Pids.Limit <= 0 {
		return errors.New("member process count requires an admitted limit")
	}
	pids, err := os.ReadFile(path.Join("/sys/fs/cgroup", value, "pids.max"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(pids)) != strconv.FormatInt(*resources.Pids.Limit, 10) {
		return errors.New("actual member cgroup process limit differs from admission")
	}
	return nil
}
