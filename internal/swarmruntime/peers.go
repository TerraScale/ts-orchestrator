package swarmruntime

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

// PeersDirectory holds <service>/peers on the host, which the mesh replaces
// by atomic rename; a task sees its service's directory read-only here, so
// it reads PeersFile: one sorted "<node> <region> <netbird-ipv4>\n" line per
// targeted region whose node answers the mesh.
const (
	PeersDirectory = "/run/ts-orch/peers"
	PeersFile      = PeersDirectory + "/peers"
)

// peersEnv is set by ts-orch only; a spec that sets one is refused.
var peersEnv = []string{"TS_NODE", "TS_PEERS_FILE", "TS_REGION"}

// NodeName is the shape of TS_NODE and TS_REGION.
var NodeName = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// taskEnv is the spec's env plus, on a mesh host, the peers variables.
func (s ServiceSpec) taskEnv() ([]string, error) {
	for _, key := range peersEnv {
		if _, set := s.Env[key]; set {
			return nil, fmt.Errorf("env %s is set by ts-orch, not the spec", key)
		}
	}
	env := maps.Clone(s.Env)
	if s.Region != "" || s.Node != "" {
		if !NodeName.MatchString(s.Region) || !NodeName.MatchString(s.Node) {
			return nil, fmt.Errorf("region %q and node %q must match %s", s.Region, s.Node, NodeName)
		}
		if env == nil {
			env = map[string]string{}
		}
		maps.Copy(env, map[string]string{"TS_REGION": s.Region, "TS_NODE": s.Node, "TS_PEERS_FILE": PeersFile})
	}
	var out []string
	for _, key := range slices.Sorted(maps.Keys(env)) {
		out = append(out, key+"="+env[key])
	}
	return out, nil
}

// peersMount binds the service's peers directory into a task that reads
// TS_PEERS_FILE; the mesh writes the file before it applies the service.
func (c *controller) peersMount() ([]runtimespec.Mount, error) {
	if !slices.Contains(c.spec.Env, "TS_PEERS_FILE="+PeersFile) {
		return nil, nil
	}
	name := c.task.ServiceAnnotations.Labels[LabelServiceSpec]
	if !intentName.MatchString(name) {
		return nil, errors.New("TS_PEERS_FILE needs a declared service")
	}
	source := filepath.Join(PeersDirectory, name)
	if _, err := os.Stat(filepath.Join(source, "peers")); err != nil {
		return nil, fmt.Errorf("peers file is not written yet: %w", err)
	}
	return []runtimespec.Mount{{Destination: PeersDirectory, Type: "bind", Source: source, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}}}, nil
}
