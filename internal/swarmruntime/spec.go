package swarmruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

const ContainerKind = "terrascale.container.v1"
const FunctionWorkerSlot = "terrascale.function-worker-slot"
const DiskResource = "terrascale.disk-bytes"
const containerTypeURL = "terrascale.tech/runtime/container/v1"

// DataRoot is the only host tree a container may bind; each source directory is owned by the container user.
const DataRoot = "/var/lib/ts-data"

// LabelReadyPath names the HTTP path probed for readiness; absent means DefaultReadyPath.
const LabelReadyPath = "terrascale.ready-path"
const DefaultReadyPath = "/readyz"

// ContainerRuntime encodes the supported, stateless container contract.
func ContainerRuntime(spec *api.ContainerSpec) (*api.TaskSpec_Generic, error) {
	if err := validateContainer(spec); err != nil {
		return nil, err
	}
	b, err := spec.Marshal()
	if err != nil {
		return nil, err
	}
	return &api.TaskSpec_Generic{Generic: &api.GenericRuntimeSpec{
		Kind: ContainerKind, Payload: &types.Any{TypeUrl: containerTypeURL, Value: b},
	}}, nil
}

// DecodeContainer refuses unsupported runtime fields rather than silently ignoring them.
func DecodeContainer(task *api.Task) (*api.ContainerSpec, error) {
	spec, err := decodeContainer(task)
	if err != nil {
		return nil, err
	}
	if task.ServiceAnnotations.Labels[LabelRole] != FunctionWorkerRole {
		if _, err := DiskBytes(task.Spec.Resources); err != nil {
			return nil, err
		}
	}
	return spec, nil
}

func decodeContainer(task *api.Task) (*api.ContainerSpec, error) {
	if task == nil || task.ID == "" || task.ServiceID == "" || len(task.ID) > 64 || strings.IndexFunc(task.ID, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) >= 0 {
		return nil, fmt.Errorf("invalid task identity")
	}
	g := task.Spec.GetGeneric()
	if g == nil || g.Kind != ContainerKind || g.Payload == nil || g.Payload.TypeUrl != containerTypeURL || len(g.Payload.Value) > 128<<10 {
		return nil, fmt.Errorf("unsupported container runtime payload")
	}
	spec := new(api.ContainerSpec)
	if err := spec.Unmarshal(g.Payload.Value); err != nil {
		return nil, fmt.Errorf("decode container: %w", err)
	}
	encoded, err := spec.Marshal()
	if err != nil || !bytes.Equal(encoded, g.Payload.Value) {
		return nil, fmt.Errorf("container payload contains unknown or noncanonical fields")
	}
	if err := validateContainer(spec); err != nil {
		return nil, err
	}
	for _, labels := range []map[string]string{task.Annotations.Labels, task.ServiceAnnotations.Labels} {
		if labels["terrascale.stateful"] == "true" || labels["terrascale.role"] == "terrabase" {
			return nil, fmt.Errorf("stateful execution requires qualified fencing and volume hooks")
		}
	}
	r := task.Spec.Resources
	if r == nil || r.Limits == nil || r.Limits.NanoCPUs < 10_000_000 || r.Limits.NanoCPUs > 1_000_000_000_000 || r.Limits.MemoryBytes < 16<<20 {
		return nil, fmt.Errorf("container requires positive CPU and memory limits")
	}
	disk, slot, err := containerGenericResources(r.Limits.Generic)
	if err != nil {
		return nil, err
	}
	function := task.ServiceAnnotations.Labels[LabelRole] == FunctionWorkerRole
	if function && (!slot || r.Reservations == nil || !proto.Equal(r.Limits, r.Reservations)) {
		return nil, fmt.Errorf("function worker requires one dedicated host slot and fully reserved resources")
	}
	if function && len(spec.Mounts) != 0 {
		return nil, fmt.Errorf("function worker does not accept bind mounts")
	}
	if !function && slot || r.SwapBytes != nil || r.MemorySwappiness != nil {
		return nil, fmt.Errorf("unsupported container resource controls")
	}
	if rr := r.Reservations; rr != nil && (rr.NanoCPUs < 0 || rr.MemoryBytes < 0 || rr.NanoCPUs > r.Limits.NanoCPUs || rr.MemoryBytes > r.Limits.MemoryBytes) {
		return nil, fmt.Errorf("invalid container resource reservations")
	}
	if r.Reservations != nil {
		reservedDisk, reservedSlot, err := containerGenericResources(r.Reservations.Generic)
		if err != nil || !function && reservedSlot {
			return nil, fmt.Errorf("unsupported container resource reservations")
		}
		if disk != 0 || reservedDisk != 0 {
			if _, err := DiskBytes(r); err != nil {
				return nil, err
			}
		}
	} else if disk != 0 {
		return nil, fmt.Errorf("disk requires equal limits and reservations")
	}
	if len(task.Spec.Networks) != 0 || task.Spec.LogDriver != nil || len(task.Spec.ResourceReferences) != 0 || len(task.Networks) != 0 || len(task.Volumes) != 0 {
		return nil, fmt.Errorf("network, volume, secret and custom log attachments are unsupported")
	}
	if task.Endpoint != nil {
		reserved := task.Endpoint.Ports
		if task.Endpoint.Spec != nil {
			reserved = task.Endpoint.Spec.Ports
			if len(task.Endpoint.Ports) != 0 && !proto.Equal(&api.EndpointSpec{Ports: task.Endpoint.Ports}, &api.EndpointSpec{Ports: reserved}) {
				return nil, fmt.Errorf("assigned ports differ from service host-port reservations")
			}
		}
		ports := make(map[uint32]bool)
		for _, port := range reserved {
			if port == nil || port.Protocol != api.ProtocolTCP || port.PublishMode != api.PublishModeHost || port.PublishedPort != port.TargetPort || port.TargetPort < 1024 || port.TargetPort > 65535 || ports[port.TargetPort] {
				return nil, fmt.Errorf("container requires unique unprivileged TCP host-port reservations")
			}
			ports[port.TargetPort] = true
		}
	}
	return spec, nil
}

// DiskBytes returns the exact, fully reserved discrete disk budget.
func DiskBytes(resources *api.ResourceRequirements) (int64, error) {
	if resources == nil || resources.Limits == nil || resources.Reservations == nil || !proto.Equal(resources.Limits, resources.Reservations) {
		return 0, fmt.Errorf("disk requires equal resource limits and reservations")
	}
	disk, _, err := containerGenericResources(resources.Limits.Generic)
	if err != nil {
		return 0, err
	}
	if disk == 0 {
		return 0, fmt.Errorf("container requires one positive discrete disk budget")
	}
	return disk, nil
}

func containerGenericResources(resources []*api.GenericResource) (disk int64, slot bool, err error) {
	for _, resource := range resources {
		discrete := resource.GetDiscreteResourceSpec()
		if discrete == nil {
			return 0, false, fmt.Errorf("container resources must be discrete")
		}
		switch discrete.Kind {
		case DiskResource:
			if disk != 0 || discrete.Value <= 0 {
				return 0, false, fmt.Errorf("container requires one positive discrete disk budget")
			}
			disk = discrete.Value
		case FunctionWorkerSlot:
			if slot || discrete.Value != 1 {
				return 0, false, fmt.Errorf("function worker requires one dedicated host slot")
			}
			slot = true
		default:
			return 0, false, fmt.Errorf("unsupported container generic resource")
		}
	}
	return disk, slot, nil
}

func hasFunctionWorkerSlot(resources []*api.GenericResource) bool {
	_, slot, err := containerGenericResources(resources)
	return err == nil && slot
}

func validateContainer(s *api.ContainerSpec) error {
	if s == nil {
		return fmt.Errorf("container spec required")
	}
	ref, err := reference.ParseNormalizedNamed(s.Image)
	if err != nil {
		return fmt.Errorf("invalid container image: %w", err)
	}
	canonical, ok := ref.(reference.Canonical)
	if !ok || canonical.Digest().Algorithm().String() != "sha256" || canonical.Digest().Validate() != nil {
		return fmt.Errorf("container image requires a sha256 digest")
	}
	uid, gid, ok := strings.Cut(s.User, ":")
	u, ue := strconv.ParseUint(uid, 10, 32)
	g, ge := strconv.ParseUint(gid, 10, 32)
	if !ok || ue != nil || ge != nil || u == 0 || g == 0 {
		return fmt.Errorf("container requires numeric non-root uid:gid")
	}
	if s.Dir != "" && (!path.IsAbs(s.Dir) || path.Clean(s.Dir) != s.Dir) {
		return fmt.Errorf("container working directory must be absolute and clean")
	}
	for _, e := range s.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.IndexByte(e, 0) >= 0 {
			return fmt.Errorf("invalid container environment")
		}
		for i, r := range k {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || i > 0 && r >= '0' && r <= '9') {
				return fmt.Errorf("invalid container environment name")
			}
		}
	}
	for _, arg := range append(slices.Clone(s.Command), s.Args...) {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("invalid container command argument")
		}
	}
	if err := validateMounts(s.Mounts); err != nil {
		return err
	}
	if _, ok := s.Labels[LabelReadyPath]; len(s.Labels) > 1 || len(s.Labels) == 1 && !ok {
		return fmt.Errorf("container labels accept only %s", LabelReadyPath)
	}
	if !validReadyPath(ReadyPath(s)) {
		return fmt.Errorf("container readiness path must be a clean absolute URL path")
	}
	allowed := &api.ContainerSpec{Image: s.Image, Command: s.Command, Args: s.Args, Env: s.Env, Dir: s.Dir, User: s.User, Mounts: s.Mounts, Labels: s.Labels}
	if !proto.Equal(s, allowed) {
		return fmt.Errorf("unsupported container option; only image, command, args, env, dir, user, bind mounts and readiness path are accepted")
	}
	return nil
}

// validateMounts admits plain bind mounts of distinct, non-nested DataRoot directories.
// Each target must already be a directory in the image: the rootfs is a read-only view.
// Nesting is refused so a container cannot swap another mount's source for a symlink.
func validateMounts(mounts []api.Mount) error {
	if len(mounts) > 8 {
		return fmt.Errorf("container supports at most 8 bind mounts")
	}
	for i, m := range mounts {
		if m.Type != api.MountTypeBind || m.Consistency != api.MountConsistencyDefault || m.BindOptions != nil || m.VolumeOptions != nil || m.TmpfsOptions != nil {
			return fmt.Errorf("container mounts must be plain bind mounts")
		}
		if !strings.HasPrefix(m.Source, DataRoot+"/") || path.Clean(m.Source) != m.Source || strings.ContainsAny(m.Source, ",:\x00") {
			return fmt.Errorf("container bind mount source must be a clean directory under %s", DataRoot)
		}
		if !path.IsAbs(m.Target) || path.Clean(m.Target) != m.Target || m.Target == "/" || strings.ContainsAny(m.Target, ",:\x00") || nested(m.Target, "/run/ts-orch") || nested(m.Target, "/proc") || nested(m.Target, "/sys") || nested(m.Target, "/dev") {
			return fmt.Errorf("container bind mount target must be a clean absolute application path")
		}
		for _, other := range mounts[:i] {
			if nested(m.Source, other.Source) || nested(other.Source, m.Source) || nested(m.Target, other.Target) || nested(other.Target, m.Target) {
				return fmt.Errorf("container bind mounts must not overlap")
			}
		}
	}
	return nil
}

// nested reports whether p is dir or below it.
func nested(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// ReadyPath is the HTTP path that reports the container ready with status 200.
func ReadyPath(s *api.ContainerSpec) string {
	if p, ok := s.Labels[LabelReadyPath]; ok {
		return p
	}
	return DefaultReadyPath
}

func validReadyPath(p string) bool {
	if len(p) > 256 || !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/-._~", r)) {
			return false
		}
	}
	return true
}

// ContainerTaskFingerprint identifies the immutable executable task and its
// function proof selectors; the fingerprint itself grants no authority.
func ContainerTaskFingerprint(t *api.Task) (string, error) {
	if _, err := DecodeContainer(t); err != nil {
		return "", err
	}
	return taskFingerprint(t), nil
}

func taskFingerprint(t *api.Task) string {
	h := sha256.New()
	h.Write(t.Spec.GetGeneric().Payload.Value)
	h.Write([]byte(t.ServiceID))
	b, _ := t.Spec.Resources.Marshal()
	h.Write(b)
	if t.Endpoint != nil {
		b, _ := t.Endpoint.Marshal()
		h.Write(b)
	}
	if t.ServiceAnnotations.Labels[LabelRole] == "function-worker" {
		for _, key := range slices.Sorted(maps.Keys(t.ServiceAnnotations.Labels)) {
			fmt.Fprintf(h, "%q=%q\n", key, t.ServiceAnnotations.Labels[key])
		}
	}
	h.Write(binary.BigEndian.AppendUint64(nil, t.Spec.ForceUpdate))
	return fmt.Sprintf("%x", h.Sum(nil))
}
