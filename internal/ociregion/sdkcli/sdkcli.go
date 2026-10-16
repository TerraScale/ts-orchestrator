// Package sdkcli serves the read-only OCI CLI command surface the region
// operator tools use (inspect-foundation, private-peer readback, inventory,
// object head) from the OCI Go SDK inside the single binary.
//
// It returns the same "data" document the Python CLI printed with
// --output json: SDK models are marshaled and their camelCase member names are
// rewritten to the CLI's kebab-case, except inside user-keyed maps such as
// tags and metadata. Commands it does not serve report handled=false so the
// caller can decide whether a CLI fallback is allowed.
package sdkcli

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Backend selects how the region tools reach OCI.
type Backend string

const (
	// BackendAuto serves supported commands in-binary and falls back to the
	// Python CLI for the rest. It is the default while the migration is
	// incomplete.
	BackendAuto Backend = "auto"
	// BackendSDK never runs the Python CLI; unsupported commands fail.
	BackendSDK Backend = "sdk"
	// BackendCLI keeps the previous Python CLI behavior for every command.
	BackendCLI Backend = "cli"
)

// BackendEnv names the environment variable that selects the backend.
const BackendEnv = "TS_OCI_BACKEND"

// SelectedBackend reads BackendEnv, defaulting to BackendAuto.
func SelectedBackend() (Backend, error) {
	switch backend := Backend(strings.TrimSpace(os.Getenv(BackendEnv))); backend {
	case "":
		return BackendAuto, nil
	case BackendAuto, BackendSDK, BackendCLI:
		return backend, nil
	default:
		return "", fmt.Errorf("%s=%q is not auto, sdk, or cli", BackendEnv, backend)
	}
}

// ErrUnsupported marks a command this package does not serve.
var ErrUnsupported = errors.New("OCI command is not served in-binary")

// Command is a parsed CLI invocation: its word path and its flags.
type Command struct {
	Path  string
	Flags map[string]string
	All   bool
	// used records the flags a handler read, so a flag no handler serves
	// (for example a list filter) is never silently dropped.
	used map[string]bool
}

// Parse splits CLI arguments into the command path and its flags.
func Parse(args []string) (Command, error) {
	command := Command{Flags: map[string]string{}, used: map[string]bool{}}
	var path []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			if len(command.Flags) > 0 || command.All {
				return Command{}, fmt.Errorf("positional OCI argument %q follows a flag", arg)
			}
			path = append(path, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		if name == "all" {
			command.All = true
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return Command{}, fmt.Errorf("OCI flag --%s has no value", name)
		}
		if _, repeated := command.Flags[name]; repeated {
			return Command{}, fmt.Errorf("OCI flag --%s is repeated", name)
		}
		command.Flags[name] = args[i+1]
		i++
	}
	command.Path = strings.Join(path, " ")
	return command, nil
}

// value returns a flag's value, or "", and records that it was read.
func (c Command) value(name string) string {
	if c.used != nil {
		c.used[name] = true
	}
	return c.Flags[name]
}

// unused lists the flags no handler read, in sorted order.
func (c Command) unused() []string {
	var names []string
	for name := range c.Flags {
		if !c.used[name] {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (c Command) flag(name string) (string, error) {
	value := c.value(name)
	if value == "" {
		return "", fmt.Errorf("OCI %s requires --%s", c.Path, name)
	}
	return value, nil
}

// optional returns a pointer to a present flag value, or nil.
func (c Command) optional(name string) *string {
	if value := c.value(name); value != "" {
		return &value
	}
	return nil
}

// Client serves commands for one region through the shared rate-limited factory.
type Client struct {
	factory *ociclient.Factory
	// endpoint overrides every service host; tests point it at a fake.
	endpoint string
}

// Factory is the shared rate-limited factory this client reads through.
func (c *Client) Factory() *ociclient.Factory { return c.factory }

func (c *Client) pin(client *common.BaseClient) {
	if c.endpoint != "" {
		client.Host = c.endpoint
	}
}

var (
	clientsMu sync.Mutex
	clients   = map[string]*Client{}
	// newFactory is replaced in tests.
	newFactory = ociclient.OperatorConfig
)

// ForRegion returns the shared client for region. An empty region selects
// the bootstrap region, which serves the tenancy-global IAM reads the CLI
// sent to the profile's default region.
func ForRegion(region string) (*Client, error) {
	if region == "" {
		region = catalog.OCIRegion(catalog.Bootstrap)
	}
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if client := clients[region]; client != nil {
		return client, nil
	}
	factory, err := newFactory(region)
	if err != nil {
		return nil, err
	}
	client := &Client{factory: factory}
	clients[region] = client
	return client, nil
}

// Call serves one CLI command and returns the CLI "data" document as JSON.
// handled is false, with ErrUnsupported, when the command is not served.
func (c *Client) Call(ctx context.Context, args []string) (data jsontext.Value, handled bool, err error) {
	command, err := Parse(args)
	if err != nil {
		return nil, false, err
	}
	if _, ok := command.Flags["output"]; ok {
		return nil, false, errors.New("OCI --output is fixed to json")
	}
	if _, ok := command.Flags["region"]; ok {
		return nil, false, errors.New("OCI --region is selected by the caller")
	}
	handler, ok := handlers[command.Path]
	if !ok {
		return nil, false, fmt.Errorf("%w: %s", ErrUnsupported, command.Path)
	}
	value, err := handler(ctx, c, command)
	if err != nil {
		return nil, true, fmt.Errorf("OCI read failed: %s: %w", command.Path, err)
	}
	if unused := command.unused(); len(unused) > 0 {
		// The read ignored a flag, so its result may be wider than asked
		// for. Report the command as unsupported rather than answer it.
		return nil, false, fmt.Errorf("%w: %s with --%s", ErrUnsupported, command.Path, strings.Join(unused, ", --"))
	}
	data, err = Render(value)
	return data, true, err
}

// Render marshals an SDK value and rewrites member names to the CLI's
// kebab-case. Members of user-keyed maps keep their keys.
func Render(value any) (jsontext.Value, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode OCI response: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		return nil, fmt.Errorf("decode OCI response: %w", err)
	}
	wire, err = json.Marshal(kebab(decoded, false), json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode CLI-shaped OCI response: %w", err)
	}
	return jsontext.Value(wire), nil
}

// userKeyed are SDK members whose object keys are user data, not schema.
var userKeyed = map[string]bool{
	"freeformTags": true, "definedTags": true, "systemTags": true, "metadata": true, "extendedMetadata": true,
	"securityAttributes": true, "schemaData": true, "opcMeta": true, "lockedAttributes": true,
}

// nameKeyed are SDK members keyed by user-defined resource names (an NLB's
// backend sets and listeners, a load balancer's named sets) whose values are
// still schema objects: only the immediate keys are preserved, so a listener's
// default-backend-set-name keeps resolving to its backend set.
var nameKeyed = map[string]bool{
	"backendSets": true, "listeners": true, "certificates": true, "hostnames": true,
	"pathRouteSets": true, "ruleSets": true, "routingPolicies": true, "sslCipherSuites": true,
}

func kebab(value any, preserveKeys bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, member := range typed {
			name := key
			if !preserveKeys {
				name = Kebab(key)
			}
			if named, ok := member.(map[string]any); ok && !preserveKeys && nameKeyed[key] {
				entries := make(map[string]any, len(named))
				for entryName, entry := range named {
					entries[entryName] = kebab(entry, false)
				}
				result[name] = entries
				continue
			}
			// The members of a user-keyed map are user data at any depth
			// (defined tags nest one level), so preserve keys below it.
			result[name] = kebab(member, preserveKeys || userKeyed[key])
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, member := range typed {
			result[index] = kebab(member, preserveKeys)
		}
		return result
	default:
		return value
	}
}

// Kebab converts an SDK camelCase member name to the CLI's kebab-case. A run
// of capitals stays one word ("sizeInGBs" -> "size-in-gbs", "vpusPerGB" ->
// "vpus-per-gb"), matching the Python SDK attribute names.
func Kebab(name string) string {
	var out strings.Builder
	runes := []rune(name)
	for index, r := range runes {
		if unicode.IsUpper(r) && index > 0 {
			previous := runes[index-1]
			if unicode.IsLower(previous) || unicode.IsDigit(previous) {
				out.WriteByte('-')
			}
		}
		out.WriteRune(unicode.ToLower(r))
	}
	return out.String()
}

// pages collects every page of a list call, bounded so a misbehaving
// endpoint cannot loop.
func pages[T any](all bool, fetch func(page *string) ([]T, *string, error)) ([]T, error) {
	var items []T
	var page *string
	for range 256 {
		batch, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		items = append(items, batch...)
		if !all || next == nil || *next == "" {
			if items == nil {
				items = []T{}
			}
			return items, nil
		}
		page = next
	}
	return nil, errors.New("OCI list exceeds its page bound")
}
