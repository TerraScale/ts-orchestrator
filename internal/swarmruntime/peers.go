package swarmruntime

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
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

func (s ServiceSpec) NeedsPeers() bool {
	return s.Name != netbird.ServerServiceName && (s.Dependencies == nil || slices.Contains(*s.Dependencies, "peers"))
}

func (s ServiceSpec) taskEnv() ([]string, error) {
	if s.Dependencies != nil && (len(*s.Dependencies) > 1 || len(*s.Dependencies) == 1 && (*s.Dependencies)[0] != "peers") {
		return nil, errors.New("dependencies must contain only peers, without duplicates")
	}
	if s.Name != netbird.ServerServiceName && !s.NeedsPeers() {
		for _, mount := range s.Mounts {
			if peersPath(mount.Source) || peersPath(mount.Target) {
				return nil, errors.New("a peers file mount requires the peers dependency")
			}
		}
	}
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
		maps.Copy(env, map[string]string{"TS_REGION": s.Region, "TS_NODE": s.Node})
		if s.NeedsPeers() {
			env["TS_PEERS_FILE"] = PeersFile
		}
	}
	var out []string
	for _, key := range slices.Sorted(maps.Keys(env)) {
		out = append(out, key+"="+env[key])
	}
	return out, nil
}

// withLocalNode names the host that runs the task as its TS_NODE: the mesh
// renders the spec on the region's founder, but a task a worker runs is that
// worker's node (R10: a second TerraBase per region).
func withLocalNode(env []string, hostname func() (string, error)) ([]string, error) {
	i := slices.IndexFunc(env, func(e string) bool { return strings.HasPrefix(e, "TS_NODE=") })
	if i < 0 {
		return env, nil
	}
	node, err := hostname()
	if err != nil || !NodeName.MatchString(node) {
		return nil, fmt.Errorf("this host's name %q is not a node name: %v", node, err)
	}
	env = slices.Clone(env)
	env[i] = "TS_NODE=" + node
	return env, nil
}

func peersPath(path string) bool {
	path = filepath.Clean(path)
	return path == PeersDirectory || strings.HasPrefix(path, PeersDirectory+"/")
}

func (c *controller) peersMount() ([]runtimespec.Mount, error) {
	if c.task.ServiceAnnotations.Name == netbird.ServerServiceName {
		c.spec.Env = slices.DeleteFunc(slices.Clone(c.spec.Env), func(env string) bool {
			return strings.HasPrefix(env, "TS_PEERS_FILE=")
		})
		return nil, nil
	}
	if !slices.Contains(c.spec.Env, "TS_PEERS_FILE="+PeersFile) {
		return nil, nil
	}
	name := c.task.ServiceAnnotations.Labels[LabelServiceSpec]
	if !intentName.MatchString(name) {
		return nil, errors.New("TS_PEERS_FILE needs a declared service")
	}
	source := filepath.Join(PeersDirectory, name)
	data, err := os.ReadFile(filepath.Join(source, "peers"))
	if err != nil {
		return nil, fmt.Errorf("peers file is not written yet: %w", err)
	}
	address, err := client.Address()
	if err != nil {
		return nil, fmt.Errorf("peers need this host's mesh address: %w", err)
	}
	node, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	var region string
	for _, env := range c.spec.Env {
		if strings.HasPrefix(env, "TS_REGION=") {
			region = strings.TrimPrefix(env, "TS_REGION=")
		}
	}
	if err := ValidatePeers(data, node, region, address); err != nil {
		return nil, err
	}
	return []runtimespec.Mount{{Destination: PeersDirectory, Type: "bind", Source: source, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}}}, nil
}

func ValidatePeers(data []byte, node, region, address string) error {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("peers generation is empty or unterminated")
	}
	own := false
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !NodeName.MatchString(fields[0]) || !NodeName.MatchString(fields[1]) {
			return errors.New("peers generation has an invalid identity")
		}
		ip := net.ParseIP(fields[2])
		if ip == nil || ip.To4() == nil || ip.To4().String() != fields[2] || seen[fields[0]] {
			return errors.New("peers generation has an invalid address or duplicate node")
		}
		seen[fields[0]] = true
		if fields[0] == node {
			if fields[1] != region || fields[2] != address {
				return errors.New("peers generation has a stale local address or region")
			}
			own = true
		}
	}
	if !own {
		return errors.New("peers generation is missing this host")
	}
	return nil
}
