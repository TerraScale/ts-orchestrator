package vmnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HostTools are the absolute host executables admitted by HostRunner. Plans
// keep stable logical names so cleanup journals remain portable across boots;
// the runner resolves those names immediately before exec.
type HostTools struct {
	IP     string
	NFT    string
	TC     string
	Sysctl string
}

// DiscoverHostTools resolves the three host-network tools required by a
// qualification plan. NewHostRunner performs the final path and mode checks.
func DiscoverHostTools() (HostTools, error) {
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "nft", "tc", "sysctl"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return HostTools{}, fmt.Errorf("vmnet: resolve %s: %w", name, err)
		}
		paths[name] = path
	}
	return HostTools{IP: paths["ip"], NFT: paths["nft"], TC: paths["tc"], Sysctl: paths["sysctl"]}, nil
}

// HostRunner executes a NetworkPlan without a shell. It accepts only the
// logical commands emitted by this package and substitutes validated absolute
// paths for both ip and tools run inside a network namespace.
type HostRunner struct {
	tools HostTools
}

// NewHostRunner validates the exact executables used for host mutations.
func NewHostRunner(tools HostTools) (*HostRunner, error) {
	for name, path := range map[string]string{"ip": tools.IP, "nft": tools.NFT, "tc": tools.TC, "sysctl": tools.Sysctl} {
		if err := validateHostTool(name, path); err != nil {
			return nil, err
		}
	}
	return &HostRunner{tools: tools}, nil
}

// DiscoverHostRunner resolves and validates the host tools in one operation.
func DiscoverHostRunner() (*HostRunner, error) {
	tools, err := DiscoverHostTools()
	if err != nil {
		return nil, err
	}
	return NewHostRunner(tools)
}

func validateHostTool(name, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("vmnet: %s path must be clean and absolute", name)
	}
	if filepath.Base(path) != name {
		return fmt.Errorf("vmnet: %s path basename must be %q", name, name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("vmnet: inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("vmnet: %s path is not an executable regular file", name)
	}
	return nil
}

func (r *HostRunner) Run(ctx context.Context, executable string, args []string) error {
	if ctx == nil {
		return errors.New("vmnet: nil host-runner context")
	}
	return r.execute(ctx, executable, args, false)
}

// RunCleanup executes one cleanup command and treats only a provider-owned
// resource's explicit not-found result as success.
func (r *HostRunner) RunCleanup(ctx context.Context, executable string, args []string) error {
	if ctx == nil {
		return errors.New("vmnet: nil host-runner context")
	}
	if !admittedCleanup(executable, args) {
		return errors.New("vmnet: cleanup command is not admitted")
	}
	return r.execute(ctx, executable, args, true)
}

func (r *HostRunner) execute(ctx context.Context, executable string, args []string, cleanup bool) error {
	path, argv, err := r.resolve(executable, args)
	if err != nil {
		return err
	}
	var output limitedOutput
	process := exec.CommandContext(ctx, path, argv...)
	process.Stdout = &output
	process.Stderr = &output
	process.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	if err := process.Run(); err != nil {
		if cleanup && missingCleanup(args, output.String()) {
			return nil
		}
		detail := output.String()
		if detail != "" {
			return fmt.Errorf("vmnet: run %s: %w: %s", executable, err, detail)
		}
		return fmt.Errorf("vmnet: run %s: %w", executable, err)
	}
	return nil
}

func (r *HostRunner) resolve(executable string, args []string) (string, []string, error) {
	if r == nil {
		return "", nil, errors.New("vmnet: nil host runner")
	}
	if executable != "ip" {
		return "", nil, fmt.Errorf("vmnet: host executable %q is not admitted", executable)
	}
	argv := append([]string(nil), args...)
	if len(argv) >= 2 && argv[0] == "netns" && argv[1] == "exec" {
		if len(argv) < 4 {
			return "", nil, errors.New("vmnet: network-namespace command is incomplete")
		}
		switch argv[3] {
		case "nft":
			argv[3] = r.tools.NFT
		case "tc":
			argv[3] = r.tools.TC
		case "sysctl":
			argv[3] = r.tools.Sysctl
		default:
			return "", nil, fmt.Errorf("vmnet: network-namespace executable %q is not admitted", argv[3])
		}
	}
	return r.tools.IP, argv, nil
}

func admittedCleanup(executable string, args []string) bool {
	if executable != "ip" {
		return false
	}
	if len(args) == 3 && args[0] == "netns" && args[1] == "del" {
		_, _, ok := ownedNamespace(args[2])
		return ok
	}
	if len(args) == 5 && args[0] == "-n" && args[2] == "link" && args[3] == "del" {
		prefix, from, ok := ownedNamespace(args[1])
		return ok && ownedVeth(args[4], prefix, from)
	}
	if len(args) == 8 && args[0] == "netns" && args[1] == "exec" && args[3] == "nft" && args[4] == "delete" && args[5] == "table" && args[6] == "inet" {
		prefix, _, ok := ownedNamespace(args[2])
		return ok && args[7] == prefix+"_vmnet"
	}
	return false
}

func ownedNamespace(value string) (string, RegionCode, bool) {
	for _, region := range launchRegions {
		suffix := "-n-" + strings.ToLower(string(region))
		if !strings.HasSuffix(value, suffix) {
			continue
		}
		prefix := strings.TrimSuffix(value, suffix)
		if validIdentifier(prefix, "prefix", 5) == nil {
			return prefix, region, true
		}
	}
	return "", "", false
}

func ownedVeth(value, prefix string, from RegionCode) bool {
	for _, to := range launchRegions {
		if from != to && value == fmt.Sprintf("%s-v-%s-%s", prefix, strings.ToLower(string(from)), strings.ToLower(string(to))) {
			return true
		}
	}
	return false
}

func missingCleanup(args []string, output string) bool {
	if !admittedCleanup("ip", args) {
		return false
	}
	for _, marker := range []string{"no such file or directory", "cannot find device", "does not exist"} {
		if strings.Contains(strings.ToLower(output), marker) {
			return true
		}
	}
	return false
}

type limitedOutput struct {
	bytes.Buffer
}

func (o *limitedOutput) Write(data []byte) (int, error) {
	const limit = 4096
	original := len(data)
	if remaining := limit - o.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = o.Buffer.Write(data)
	}
	return original, nil
}

func (o *limitedOutput) String() string {
	return strings.TrimSpace(o.Buffer.String())
}

var _ CleanupRunner = (*HostRunner)(nil)
