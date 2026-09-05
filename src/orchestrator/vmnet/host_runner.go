package vmnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

// HostTools are the exact absolute host executables admitted by HostRunner and
// serialized into setup and cleanup plans.
type HostTools struct {
	IP       string
	NFT      string
	TC       string
	Sysctl   string
	IPTables string
}

// ToolPaths is the canonical name used by network declarations and journals.
// HostTools remains an alias for callers compiled against the first version of
// the qualification package.
type ToolPaths = HostTools

// DiscoverHostTools resolves the host-network tools required by a
// qualification plan. NewHostRunner performs the final path and mode checks.
func DiscoverHostTools() (HostTools, error) {
	paths := make(map[string]string, 5)
	for _, name := range []string{"ip", "nft", "tc", "sysctl", "iptables"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return HostTools{}, fmt.Errorf("vmnet: resolve %s: %w", name, err)
		}
		if !filepath.IsAbs(path) {
			path, err = filepath.Abs(path)
			if err != nil {
				return HostTools{}, fmt.Errorf("vmnet: make %s path absolute: %w", name, err)
			}
		}
		path, err = filepath.EvalSymlinks(filepath.Clean(path))
		if err != nil {
			return HostTools{}, fmt.Errorf("vmnet: resolve %s symlinks: %w", name, err)
		}
		paths[name] = filepath.Clean(path)
	}
	tools := HostTools{IP: paths["ip"], NFT: paths["nft"], TC: paths["tc"], Sysctl: paths["sysctl"], IPTables: paths["iptables"]}
	if err := tools.Validate(); err != nil {
		return HostTools{}, err
	}
	return tools, nil
}

// DiscoverToolPaths is the declaration-oriented spelling of DiscoverHostTools.
func DiscoverToolPaths() (ToolPaths, error) { return DiscoverHostTools() }

// HostRunner executes a NetworkPlan without a shell. It accepts only the exact
// validated paths for ip, tools inside a namespace, and exact host INPUT rules.
type HostRunner struct {
	tools HostTools
}

// NewHostRunner validates the exact executables used for host mutations.
func NewHostRunner(tools HostTools) (*HostRunner, error) {
	if err := tools.Validate(); err != nil {
		return nil, err
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

// Validate proves that every declared tool is an executable regular file at a
// clean absolute path with the expected basename.
func (tools HostTools) Validate() error {
	for _, tool := range tools.entries() {
		name, path := tool.name, tool.path
		if err := validateHostTool(name, path); err != nil {
			return err
		}
	}
	return nil
}

func (tools HostTools) validatePaths() error {
	for _, tool := range tools.entries() {
		if err := validateHostToolPath(tool.name, tool.path); err != nil {
			return err
		}
	}
	return nil
}

func (tools HostTools) entries() []struct{ name, path string } {
	return []struct{ name, path string }{
		{name: "ip", path: tools.IP},
		{name: "nft", path: tools.NFT},
		{name: "tc", path: tools.TC},
		{name: "sysctl", path: tools.Sysctl},
		{name: "iptables", path: tools.IPTables},
	}
}

func validateHostTool(name, path string) error {
	if err := validateHostToolPath(name, path); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("vmnet: resolve %s path: %w", name, err)
	}
	if resolved != path {
		return fmt.Errorf("vmnet: %s path must not contain symbolic links", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("vmnet: inspect %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vmnet: %s path must not be a symbolic link", name)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("vmnet: %s path is not an executable regular file", name)
	}
	if !trustedToolOwner(info) {
		return fmt.Errorf("vmnet: %s executable is not owned by root or the current user", name)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("vmnet: inspect %s parent directory: %w", name, err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("vmnet: %s parent directory is writable by group or others", name)
	}
	if !trustedToolOwner(parent) {
		return fmt.Errorf("vmnet: %s parent directory is not owned by root or the current user", name)
	}
	return nil
}

func trustedToolOwner(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return true
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return true
	}
	uid := value.FieldByName("Uid")
	if !uid.IsValid() || !uid.CanUint() {
		return true
	}
	owner := uid.Uint()
	effective := os.Geteuid()
	return owner == 0 || effective < 0 || owner == uint64(effective)
}

func validateHostToolPath(name, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("vmnet: %s path must be clean and absolute", name)
	}
	if filepath.Base(path) != name && !(name == "iptables" && iptablesMulticall(path)) {
		return fmt.Errorf("vmnet: %s path basename must be %q", name, name)
	}
	return nil
}

// ToolPaths returns the exact executable paths this runner admits.
func (r *HostRunner) ToolPaths() ToolPaths {
	if r == nil {
		return ToolPaths{}
	}
	return r.tools
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
	if !r.admittedCleanup(executable, args) {
		return errors.New("vmnet: cleanup command is not admitted")
	}
	return r.execute(ctx, executable, args, true)
}

func (r *HostRunner) execute(ctx context.Context, executable string, args []string, cleanup bool) error {
	if r != nil && executable == r.tools.IPTables {
		return r.executeHostInput(ctx, args, cleanup)
	}
	path, argv, err := r.resolve(executable, args)
	if err != nil {
		return err
	}
	if err := validateHostTool("ip", path); err != nil {
		return err
	}
	if len(argv) >= 4 && argv[0] == "netns" && argv[1] == "exec" {
		if err := validateHostTool(filepath.Base(argv[3]), argv[3]); err != nil {
			return err
		}
	}
	var output limitedOutput
	process := exec.CommandContext(ctx, path, argv...)
	process.Stdout = &output
	process.Stderr = &output
	process.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := process.Run(); err != nil {
		if cleanup && r.missingCleanup(args, output.String()) {
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
	if executable == r.tools.IPTables {
		if !admittedHostInput(args) {
			return "", nil, errors.New("vmnet: host input command is not admitted")
		}
		return executable, iptablesArguments(executable, args), nil
	}
	if executable != r.tools.IP {
		return "", nil, fmt.Errorf("vmnet: host executable %q is not admitted", executable)
	}
	argv := append([]string(nil), args...)
	if len(argv) >= 2 && argv[0] == "netns" && argv[1] == "exec" {
		if len(argv) < 4 {
			return "", nil, errors.New("vmnet: network-namespace command is incomplete")
		}
		switch argv[3] {
		case r.tools.NFT, r.tools.TC, r.tools.Sysctl:
		default:
			return "", nil, fmt.Errorf("vmnet: network-namespace executable %q is not admitted", argv[3])
		}
	}
	return r.tools.IP, argv, nil
}

func (r *HostRunner) admittedCleanup(executable string, args []string) bool {
	if r != nil && executable == r.tools.IPTables {
		return admittedHostInput(args) && args[4] == "-D"
	}
	if r == nil || executable != r.tools.IP {
		return false
	}
	if len(args) == 3 && args[0] == "netns" && args[1] == "del" {
		_, _, _, ok := ownedNamespace(args[2])
		return ok
	}
	return false
}

func ownedNamespace(value string) (string, string, RegionCode, bool) {
	separator := strings.LastIndex(value, "-n-")
	if separator < 0 {
		return "", "", "", false
	}
	code := value[separator+3:]
	region := RegionCode(strings.ToUpper(code))
	if !validRegion(region) || strings.ToLower(string(region)) != code {
		return "", "", "", false
	}
	owner := value[:separator]
	split := strings.LastIndexByte(owner, '-')
	if split <= 0 || split == len(owner)-1 {
		return "", "", "", false
	}
	prefix, token := owner[:split], owner[split+1:]
	if validIdentifier(prefix, "prefix", 5) == nil && runTokenPattern.MatchString(token) {
		return prefix, token, region, true
	}
	return "", "", "", false
}

func (r *HostRunner) missingCleanup(args []string, output string) bool {
	if r == nil || !r.admittedCleanup(r.tools.IP, args) {
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
