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
const containerTypeURL = "terrascale.tech/runtime/container/v1"

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
	function := task.ServiceAnnotations.Labels[LabelRole] == "function-worker"
	if function && (!hasFunctionWorkerSlot(r.Limits.Generic) || r.Reservations == nil || !proto.Equal(r.Limits, r.Reservations)) {
		return nil, fmt.Errorf("function worker requires one dedicated host slot and fully reserved resources")
	}
	if !function && len(r.Limits.Generic) != 0 || r.SwapBytes != nil || r.MemorySwappiness != nil {
		return nil, fmt.Errorf("unsupported container resource controls")
	}
	if rr := r.Reservations; rr != nil && (rr.NanoCPUs < 0 || rr.MemoryBytes < 0 || rr.NanoCPUs > r.Limits.NanoCPUs || rr.MemoryBytes > r.Limits.MemoryBytes || !function && len(rr.Generic) != 0) {
		return nil, fmt.Errorf("invalid container resource reservations")
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

func hasFunctionWorkerSlot(resources []*api.GenericResource) bool {
	if len(resources) != 1 {
		return false
	}
	discrete := resources[0].GetDiscreteResourceSpec()
	return discrete != nil && discrete.Kind == FunctionWorkerSlot && discrete.Value == 1
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
	allowed := &api.ContainerSpec{Image: s.Image, Command: s.Command, Args: s.Args, Env: s.Env, Dir: s.Dir, User: s.User}
	if !proto.Equal(s, allowed) {
		return fmt.Errorf("unsupported container option; only image, command, args, env, dir and user are accepted")
	}
	return nil
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
		h.Write(binary.BigEndian.AppendUint64(nil, t.Spec.ForceUpdate))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
