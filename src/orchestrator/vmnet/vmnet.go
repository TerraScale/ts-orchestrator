// Package vmnet contains the test-only host-network plan used by the
// Firecracker qualification estate.  It deliberately has no production
// networking implementation: callers provide a Runner and can therefore use
// a fake without changing the host running the tests.
package vmnet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner is the only mutation seam in this package. Arguments are passed to
// an executable directly; a shell is never involved.
type Runner interface {
	Run(context.Context, string, []string) error
}

// RecordingCall is one mutation request captured by RecordingRunner without
// executing it.
type RecordingCall struct {
	Command     Command
	Cleanup     bool
	Canceled    bool
	HasDeadline bool
	Deadline    time.Time
}

// RecordingRunner is a non-host test runner. It only stores defensive copies
// of commands and journals and is the public runner allowed to use a custom
// CoordinationRoot.
type RecordingRunner struct {
	mu       sync.Mutex
	calls    []RecordingCall
	journals []Journal
}

func (r *RecordingRunner) Run(ctx context.Context, executable string, args []string) error {
	return r.record(ctx, false, executable, args)
}

func (r *RecordingRunner) RunCleanup(ctx context.Context, executable string, args []string) error {
	return r.record(ctx, true, executable, args)
}

func (r *RecordingRunner) record(ctx context.Context, cleanup bool, executable string, args []string) error {
	if r == nil {
		return errors.New("vmnet: nil recording runner")
	}
	deadline, hasDeadline := ctx.Deadline()
	r.mu.Lock()
	r.calls = append(r.calls, RecordingCall{
		Command: Command{Executable: executable, Args: append([]string(nil), args...)},
		Cleanup: cleanup, Canceled: ctx.Err() != nil,
		HasDeadline: hasDeadline, Deadline: deadline,
	})
	r.mu.Unlock()
	return nil
}

func (r *RecordingRunner) WriteJournal(_ context.Context, journal Journal) error {
	if r == nil {
		return errors.New("vmnet: nil recording runner")
	}
	r.mu.Lock()
	r.journals = append(r.journals, journal.copy())
	r.mu.Unlock()
	return nil
}

func (r *RecordingRunner) Calls() []RecordingCall {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := append([]RecordingCall(nil), r.calls...)
	for index := range result {
		result[index].Command = result[index].Command.copy()
	}
	return result
}

func (r *RecordingRunner) Journals() []Journal {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := append([]Journal(nil), r.journals...)
	for index := range result {
		result[index] = result[index].copy()
	}
	return result
}

type internalNonHostRunner interface {
	Runner
	vmnetNonHostRunner()
}

// CleanupRunner may normalize an absent owned resource while replaying a
// cleanup journal. Other failures, including permission errors, remain fatal.
type CleanupRunner interface {
	Runner
	RunCleanup(context.Context, string, []string) error
}

// FuncRunner adapts a function to Runner.
type FuncRunner func(context.Context, string, []string) error

func (f FuncRunner) Run(ctx context.Context, executable string, args []string) error {
	return f(ctx, executable, args)
}

// Command is one shell-free host command. Args never contain a shell command
// line and are copied when a plan is built or returned.
type Command struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
}

func command(executable string, args ...string) Command {
	return Command{Executable: executable, Args: append([]string(nil), args...)}
}

func (c Command) copy() Command {
	c.Args = append([]string(nil), c.Args...)
	return c
}

// RegionCode is an uppercase three-letter Region identifier. Non-launch
// Regions must be explicitly declared in Config.Regions.
type RegionCode string

const (
	GRU RegionCode = "GRU"
	SFO RegionCode = "SFO"
	FRA RegionCode = "FRA"
)

var launchRegions = []RegionCode{GRU, SFO, FRA}

var transitPrefix = netip.MustParsePrefix("10.78.252.0/22")

const MaxRegions = 20

const networkPlanVersion = 9

// StableCIDR returns the deterministic qualification subnet for a launch
// Region.
func StableCIDR(region RegionCode) string {
	switch region {
	case GRU:
		return "10.77.0.0/24"
	case SFO:
		return "10.77.1.0/24"
	case FRA:
		return "10.77.2.0/24"
	default:
		return ""
	}
}

// StableGateway returns the first usable address in a launch Region.
func StableGateway(region RegionCode) string {
	cidr := StableCIDR(region)
	if cidr == "" {
		return ""
	}
	prefix, _ := netip.ParsePrefix(cidr)
	return prefix.Addr().Next().String()
}

// StableGuestAddress returns the deterministic address for a one-based guest
// ordinal in a launch Region. It is useful when constructing guest boot
// configuration alongside this host-side plan.
func StableGuestAddress(region RegionCode, ordinal int) (string, error) {
	if regionIndex(region) < 0 || regionIndex(region) >= 3 || ordinal < 1 || ordinal > 32 {
		return "", fmt.Errorf("vmnet: guest ordinal %d is invalid for %s", ordinal, region)
	}
	prefix, _ := netip.ParsePrefix(StableCIDR(region))
	address := prefix.Addr().As4()
	address[3] = byte(9 + ordinal)
	return netip.AddrFrom4(address).String(), nil
}

// StableGuestMAC returns a locally administered unicast MAC for a one-based
// guest ordinal. It is derived only from the closed launch-Region allocation.
func StableGuestMAC(region RegionCode, ordinal int) (string, error) {
	index := regionIndex(region)
	if index < 0 || index >= 3 || ordinal < 1 || ordinal > 32 {
		return "", fmt.Errorf("vmnet: guest ordinal %d is invalid for %s", ordinal, region)
	}
	return fmt.Sprintf("02:fc:77:%02x:%02x:01", index+1, ordinal), nil
}

// GuestSpec declares one Firecracker guest's host-side TAP and stable address.
// Empty TAP and Address values receive deterministic values from the guest's
// sorted position in its Region.
type GuestSpec struct {
	ID      string `json:"id"`
	TAP     string `json:"tap,omitempty"`
	Address string `json:"address,omitempty"`
}

// RegionSpec declares one isolated network namespace and its guests.
// Additional Regions retain declaration order after GRU/SFO/FRA and receive
// slots 3..19. Append admissions to preserve existing slots. Empty CIDR selects
// 10.77.<slot>.0/24. Additional Regions require at least two guests.
type RegionSpec struct {
	Code   RegionCode  `json:"code"`
	CIDR   string      `json:"cidr"`
	Guests []GuestSpec `json:"guests"`
}

// TransportProtocol is the closed set of protocols admitted for host
// endpoint forwarding. UDP is restricted to the qualification NTP endpoint;
// DNS names are installed in guest configuration.
type TransportProtocol string

const TCP TransportProtocol = "tcp"
const UDP TransportProtocol = "udp"

func validEndpointTransport(name string, protocol TransportProtocol, guestPort, hostPort uint16) bool {
	return protocol == TCP && guestPort != 0 && hostPort != 0 || protocol == UDP && name == "ntp" && guestPort == 123 && hostPort == 18123
}

// EndpointSpec declares one bounded guest-to-host listener mapping. Addresses
// are assigned by Plan so callers cannot forward traffic to an ambient host.
type EndpointSpec struct {
	Name      string            `json:"name"`
	Region    RegionCode        `json:"region"`
	Protocol  TransportProtocol `json:"protocol"`
	GuestPort uint16            `json:"guest_port"`
	HostPort  uint16            `json:"host_port"`
	DNSNames  []string          `json:"dns_names,omitempty"`
}

// EndpointForward is a fully resolved guest-to-host mapping. Only this exact
// address and port tuple receives DNAT, SNAT, and forwarding rules.
type EndpointForward struct {
	Name         string            `json:"name"`
	Region       RegionCode        `json:"region"`
	Protocol     TransportProtocol `json:"protocol"`
	GuestAddress string            `json:"guest_address"`
	GuestPort    uint16            `json:"guest_port"`
	HostAddress  string            `json:"host_address"`
	HostPort     uint16            `json:"host_port"`
	DNSNames     []string          `json:"dns_names,omitempty"`
}

// EndpointListener is one root-namespace listener required by the resolved
// forwards. Several Regions may share the same listener.
type EndpointListener struct {
	Name     string            `json:"name"`
	Protocol TransportProtocol `json:"protocol"`
	Address  string            `json:"address"`
	Port     uint16            `json:"port"`
}

// DNSRecord is one guest configuration record. The network package declares
// records but does not run an open DNS proxy; vmqual can render these as
// /etc/hosts entries in the named Region.
type DNSRecordType string

const DNSA DNSRecordType = "A"

type DNSRecord struct {
	Region  RegionCode    `json:"region"`
	Name    string        `json:"name"`
	Type    DNSRecordType `json:"type"`
	Address string        `json:"address"`
}

// RegionUplink is the run-owned veth pair joining a Region namespace to the
// root namespace. Deleting RegionNamespace deletes both ends atomically.
type RegionUplink struct {
	Region             RegionCode `json:"region"`
	RegionNamespace    string     `json:"region_namespace"`
	RegionDevice       string     `json:"region_device"`
	RootDevice         string     `json:"root_device"`
	CIDR               string     `json:"cidr"`
	RegionAddress      string     `json:"region_address"`
	RootAddress        string     `json:"root_address"`
	HostServiceAddress string     `json:"host_service_address"`
	OwnsServiceAddress bool       `json:"owns_service_address"`
}

// FaultSpec declares a directional cross-Region impairment. Latency, loss,
// jitter, and bandwidth affect From→To; Partition cuts both directions.
type FaultSpec struct {
	From             RegionCode    `json:"from"`
	To               RegionCode    `json:"to"`
	Latency          time.Duration `json:"latency,omitempty"`
	Jitter           time.Duration `json:"jitter,omitempty"`
	LossPercent      float64       `json:"loss_percent,omitempty"`
	ReorderPercent   float64       `json:"reorder_percent,omitempty"`
	DuplicatePercent float64       `json:"duplicate_percent,omitempty"`
	BandwidthKbit    uint64        `json:"bandwidth_kbit,omitempty"`
	Partition        bool          `json:"partition,omitempty"`
}

// Config is the declarative input to Plan.
type Config struct {
	// Prefix is limited to a short lowercase token because Linux interface
	// names are limited to 15 bytes. The default is "ts".
	Prefix  string       `json:"prefix,omitempty"`
	Regions []RegionSpec `json:"regions"`
	Faults  []FaultSpec  `json:"faults,omitempty"`
	// Endpoints nil selects the four qualification listeners for every
	// declared Region. A non-nil slice declares the complete allowed set.
	Endpoints []EndpointSpec `json:"endpoints,omitempty"`
	TAPUID    uint32         `json:"tap_uid,omitempty"`
	TAPGID    uint32         `json:"tap_gid,omitempty"`
	// RunID is a 128-bit lowercase hexadecimal ownership identity. Empty uses
	// one cryptographically random identity shared by this controller process.
	RunID string `json:"run_id,omitempty"`
	// CoordinationRoot is the private host directory shared by every vmnet
	// controller in one lock domain. Empty uses /run/terrascale/vmnet.
	CoordinationRoot string `json:"coordination_root,omitempty"`
	// Tools contains the exact absolute executables serialized into every
	// setup, fault, and cleanup command. Empty discovers the host toolchain.
	Tools ToolPaths `json:"tools,omitempty"`
}

// DefaultConfig returns the six-guest GRU/SFO/FRA qualification topology.
func DefaultConfig() Config {
	config := Config{Prefix: "ts"}
	for _, region := range launchRegions {
		config.Regions = append(config.Regions, RegionSpec{
			Code: region, CIDR: StableCIDR(region),
			Guests: []GuestSpec{{ID: strings.ToLower(string(region)) + "-member-1"}, {ID: strings.ToLower(string(region)) + "-member-2"}},
		})
	}
	return config
}

// RegionNetwork describes the addresses and names derived for one Region.
type RegionNetwork struct {
	Code          RegionCode     `json:"code"`
	CIDR          string         `json:"cidr"`
	Namespace     string         `json:"namespace"`
	NamespacePath string         `json:"namespace_path"`
	Bridge        string         `json:"bridge"`
	Gateway       string         `json:"gateway"`
	Uplink        RegionUplink   `json:"uplink"`
	Guests        []GuestNetwork `json:"guests"`
}

// GuestNetwork is a resolved guest declaration.
type GuestNetwork struct {
	ID      string `json:"id"`
	TAP     string `json:"tap"`
	Address string `json:"address"`
	MAC     string `json:"mac"`
}

// CleanupPlan is safe to replay. A CleanupRunner normalizes only explicitly
// absent owned namespaces, root veths, and exact host INPUT rules after a crash.
type CleanupPlan struct {
	Version          int                `json:"version"`
	Prefix           string             `json:"prefix"`
	RunID            string             `json:"run_id"`
	CoordinationRoot string             `json:"coordination_root"`
	Tools            ToolPaths          `json:"tools"`
	Fingerprint      string             `json:"fingerprint"`
	Regions          []RegionCode       `json:"regions"`
	Uplinks          []RegionUplink     `json:"uplinks"`
	Forwards         []EndpointForward  `json:"forwards,omitempty"`
	Listeners        []EndpointListener `json:"listeners,omitempty"`
	DNSRecords       []DNSRecord        `json:"dns_records,omitempty"`
	Commands         []Command          `json:"commands"`
	HostInput        []Command          `json:"host_input,omitempty"`
	RootLinks        []RootLinkCleanup  `json:"root_links"`
}

func (p CleanupPlan) copy() CleanupPlan {
	p.RootLinks = append([]RootLinkCleanup(nil), p.RootLinks...)
	for i := range p.RootLinks {
		p.RootLinks[i].Command = p.RootLinks[i].Command.copy()
	}
	p.HostInput = append([]Command(nil), p.HostInput...)
	for i := range p.HostInput {
		p.HostInput[i] = p.HostInput[i].copy()
	}
	p.Regions = append([]RegionCode(nil), p.Regions...)
	p.Uplinks = append([]RegionUplink(nil), p.Uplinks...)
	p.Forwards = copyForwards(p.Forwards)
	p.Listeners = append([]EndpointListener(nil), p.Listeners...)
	p.DNSRecords = slices.Clone(p.DNSRecords)
	p.Commands = append([]Command(nil), p.Commands...)
	for i := range p.Commands {
		p.Commands[i] = p.Commands[i].copy()
	}
	return p
}

// Validate proves that every cleanup target belongs to exactly this run. The
// plan admits owned namespace, root veth, and exact host INPUT rule deletion only.
// Subordinate network resources are created inside the owned namespaces.
func (p CleanupPlan) Validate() error {
	if p.Version != networkPlanVersion || validIdentifier(p.Prefix, "prefix", 5) != nil || !runIDPattern.MatchString(p.RunID) || !validSHA256Hex(p.Fingerprint) {
		return errors.New("vmnet: invalid cleanup plan metadata")
	}
	if err := validateHostCoordinationRoot(p.CoordinationRoot); err != nil {
		return err
	}
	// Namespace and host INPUT cleanup use the exact journaled executables.
	if err := p.Tools.validatePaths(); err != nil {
		return err
	}
	if err := validateHostTool("ip", p.Tools.IP); err != nil {
		return err
	}
	if len(p.HostInput) != 0 {
		if err := validateHostTool("iptables", p.Tools.IPTables); err != nil {
			return err
		}
	}
	if len(p.Regions) == 0 || len(p.Regions) > MaxRegions || len(p.Commands) != len(p.Regions) || len(p.Uplinks) != len(p.Regions) {
		return errors.New("vmnet: cleanup plan must contain one command per declared Region")
	}
	seen := make(map[RegionCode]bool, len(p.Commands))
	for index, cleanup := range p.Commands {
		if cleanup.Executable != p.Tools.IP || len(cleanup.Args) != 3 || cleanup.Args[0] != "netns" || cleanup.Args[1] != "del" {
			return errors.New("vmnet: cleanup plan contains a non-namespace command")
		}
		prefix, runID, region, ok := ownedNamespace(cleanup.Args[2])
		expectedRegion := p.Regions[len(p.Regions)-1-index]
		if !validRegion(expectedRegion) || !ok || prefix != p.Prefix || runID != p.RunID || region != expectedRegion || cleanup.Args[2] != regionNetworkName(p.Prefix, p.RunID, expectedRegion) || seen[region] {
			return errors.New("vmnet: cleanup namespace is not uniquely owned by this run")
		}
		seen[region] = true
	}
	for index := 1; index < len(p.Regions); index++ {
		if regionIndex(p.Regions[index]) < 3 && regionIndex(p.Regions[index-1]) >= regionIndex(p.Regions[index]) {
			return errors.New("vmnet: cleanup Regions are not canonical")
		}
	}
	if err := validateResolvedEndpoints(p.Prefix, p.RunID, p.Regions, p.Uplinks, p.Forwards, p.Listeners, p.DNSRecords); err != nil {
		return fmt.Errorf("vmnet: invalid cleanup endpoint manifest: %w", err)
	}
	if !reflect.DeepEqual(p.HostInput, hostInputCommands(p.Tools, p.Prefix, p.RunID, p.Uplinks, p.Forwards, true)) {
		return errors.New("vmnet: cleanup host input rules differ from the owned endpoint manifest")
	}
	if len(p.RootLinks) != len(p.Uplinks) {
		return errors.New("vmnet: cleanup omits owned root links")
	}
	for i, uplink := range p.Uplinks {
		if !reflect.DeepEqual(p.RootLinks[i], rootLinkCleanup(p.Tools, p.Prefix, p.RunID, uplink)) {
			return errors.New("vmnet: root link cleanup differs from its owned uplink")
		}
	}
	return nil
}

// Validate checks the complete crash-recovery record before any privileged
// cleanup command executes.
func (j Journal) Validate() error {
	if j.Version != networkPlanVersion || j.Prefix == "" || j.RunID == "" || j.Fingerprint == "" {
		return errors.New("vmnet: invalid network journal metadata")
	}
	if j.Prefix != j.Cleanup.Prefix || j.RunID != j.Cleanup.RunID || j.CoordinationRoot != j.Cleanup.CoordinationRoot || j.Tools != j.Cleanup.Tools || j.Fingerprint != j.Cleanup.Fingerprint {
		return errors.New("vmnet: network journal and cleanup ownership differ")
	}
	return j.Cleanup.Validate()
}

func (j Journal) copy() Journal {
	j.Cleanup = j.Cleanup.copy()
	return j
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Run replays every cleanup command and reports the first error. It continues
// after errors because rollback must remain useful when an earlier resource is
// already absent. Context cancellation is intentionally not converted to a
// shell escape or an unbounded retry.
func (p CleanupPlan) Run(ctx context.Context, runner Runner) error {
	if runner == nil {
		return errors.New("vmnet: nil runner")
	}
	if ctx == nil {
		return errors.New("vmnet: nil context")
	}
	p = p.copy()
	if err := p.Validate(); err != nil {
		return err
	}
	if err := validateRunnerTools(runner, p.Tools); err != nil {
		return err
	}
	if err := validateRunnerCoordinationRoot(runner, p.CoordinationRoot); err != nil {
		return err
	}
	coordinator, unlock := lockRunCoordinator(p.RunID)
	defer unlock()
	if err := coordinator.bind(p.Fingerprint); err != nil {
		return err
	}
	if coordinator.hostLease == nil {
		lease, _, err := acquireHostLease(p.CoordinationRoot, p.RunID, p.Fingerprint, p.Uplinks)
		if err != nil {
			return err
		}
		coordinator.hostLease = lease
	}
	coordinator.applied = false
	coordinator.cleanupRequired = true
	coordinator.resetFaults(nil)
	if err := coordinator.hostLease.publish(); err != nil {
		return fmt.Errorf("vmnet: publish host allocation for cleanup: %w", err)
	}
	err := p.runLocked(ctx, runner)
	if err != nil {
		return err
	}
	if err := coordinator.hostLease.complete(); err != nil {
		return fmt.Errorf("vmnet: release host allocation: %w", err)
	}
	coordinator.hostLease = nil
	coordinator.cleanupRequired = false
	return nil
}

func (p CleanupPlan) runLocked(ctx context.Context, runner Runner) error {
	// Cleanup is a safety operation. It must still run when the controller's
	// request was cancelled, but no individual host command may hang forever.
	baseContext := context.WithoutCancel(ctx)
	cleanupContext, cleanupCancel := context.WithTimeout(baseContext, 45*time.Second)
	defer cleanupCancel()
	var first error
	for _, c := range append(append([]Command(nil), p.HostInput...), p.Commands...) {
		commandContext, cancel := context.WithTimeout(cleanupContext, 10*time.Second)
		var err error
		if cleanupRunner, ok := runner.(CleanupRunner); ok {
			err = cleanupRunner.RunCleanup(commandContext, c.Executable, append([]string(nil), c.Args...))
		} else {
			err = runner.Run(commandContext, c.Executable, append([]string(nil), c.Args...))
		}
		cancel()
		if err != nil && first == nil {
			first = err
		}
	}
	for _, link := range p.RootLinks {
		commandContext, cancel := context.WithTimeout(cleanupContext, 10*time.Second)
		var err error
		if host, ok := runner.(interface {
			cleanupRootLink(context.Context, RootLinkCleanup) error
		}); ok {
			err = host.cleanupRootLink(commandContext, link)
		} else if _, ok := runner.(interface{ vmnetNonHostRunner() }); ok {
			if cleanupRunner, ok := runner.(CleanupRunner); ok {
				err = cleanupRunner.RunCleanup(commandContext, link.Command.Executable, append([]string(nil), link.Command.Args...))
			} else {
				err = runner.Run(commandContext, link.Command.Executable, append([]string(nil), link.Command.Args...))
			}
		} else {
			err = errors.New("vmnet: root link cleanup requires an ownership-verifying runner")
		}
		cancel()
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Journal is the crash-recovery record. The caller should persist this value
// before calling Apply. It contains only provider-owned identifiers and the
// exact cleanup argv, never credentials.
type Journal struct {
	Version          int         `json:"version"`
	Prefix           string      `json:"prefix"`
	RunID            string      `json:"run_id"`
	CoordinationRoot string      `json:"coordination_root"`
	Tools            ToolPaths   `json:"tools"`
	Fingerprint      string      `json:"fingerprint"`
	Cleanup          CleanupPlan `json:"cleanup"`
}

// JournalWriter persists the cleanup record in the controller's durable
// journal. It is called before the first host mutation by ApplyWithJournal.
type JournalWriter interface {
	WriteJournal(context.Context, Journal) error
}

// NetworkPlan is a deterministic setup and cleanup plan.
type NetworkPlan struct {
	Version          int                `json:"version"`
	Prefix           string             `json:"prefix"`
	RunID            string             `json:"run_id"`
	CoordinationRoot string             `json:"coordination_root"`
	Tools            ToolPaths          `json:"tools"`
	Fingerprint      string             `json:"fingerprint"`
	Regions          []RegionNetwork    `json:"regions"`
	Uplinks          []RegionUplink     `json:"uplinks,omitempty"`
	Faults           []FaultSpec        `json:"faults,omitempty"`
	Forwards         []EndpointForward  `json:"forwards,omitempty"`
	Listeners        []EndpointListener `json:"listeners,omitempty"`
	DNSRecords       []DNSRecord        `json:"dns_records,omitempty"`
	Commands         []Command          `json:"commands"`
	Cleanup          CleanupPlan        `json:"cleanup"`
	Journal          Journal            `json:"journal"`
}

const (
	maxPlanCommands = 16000
	maxPlanGuests   = MaxRegions * 32
	maxPlanForwards = MaxRegions * 16
	maxDNSRecords   = maxPlanForwards * maxEndpointDNS
	maxEndpointDNS  = 8
)

// Validate reconstructs the only canonical plan that could own these
// resources. Exported plan fields are intentionally serializable, so callers
// must not be able to turn a recovered or hand-edited value into arbitrary ip
// commands by recalculating only its fingerprint.
func (p NetworkPlan) Validate() error {
	if p.Version != networkPlanVersion || validIdentifier(p.Prefix, "prefix", 5) != nil || !runIDPattern.MatchString(p.RunID) || !validSHA256Hex(p.Fingerprint) {
		return errors.New("vmnet: invalid network plan metadata")
	}
	if len(p.Regions) == 0 || len(p.Regions) > MaxRegions || len(p.Commands) == 0 || len(p.Commands) > maxPlanCommands {
		return errors.New("vmnet: network plan exceeds topology bounds")
	}
	if err := validateHostCoordinationRoot(p.CoordinationRoot); err != nil {
		return err
	}
	if err := p.Tools.Validate(); err != nil {
		return err
	}
	config, err := p.canonicalConfig()
	if err != nil {
		return err
	}
	expected, err := Plan(config)
	if err != nil {
		return fmt.Errorf("vmnet: reconstruct canonical network plan: %w", err)
	}
	if !reflect.DeepEqual(p, expected) {
		return errors.New("vmnet: network plan is not canonical for its run ownership")
	}
	return nil
}

func (p NetworkPlan) canonicalConfig() (Config, error) {
	uid, gid, err := p.tapOwnership()
	if err != nil {
		return Config{}, err
	}
	config := Config{
		Prefix:           p.Prefix,
		RunID:            p.RunID,
		CoordinationRoot: p.CoordinationRoot,
		Tools:            p.Tools,
		Faults:           append([]FaultSpec(nil), p.Faults...),
		Endpoints:        make([]EndpointSpec, 0, len(p.Forwards)),
		TAPUID:           uid,
		TAPGID:           gid,
		Regions:          make([]RegionSpec, 0, len(p.Regions)),
	}
	totalGuests := 0
	for _, region := range p.Regions {
		totalGuests += len(region.Guests)
		if totalGuests > maxPlanGuests {
			return Config{}, errors.New("vmnet: network plan has too many guests")
		}
		spec := RegionSpec{Code: region.Code, CIDR: region.CIDR, Guests: make([]GuestSpec, 0, len(region.Guests))}
		for _, guest := range region.Guests {
			spec.Guests = append(spec.Guests, GuestSpec{ID: guest.ID, TAP: guest.TAP, Address: guest.Address})
		}
		config.Regions = append(config.Regions, spec)
	}
	for _, forward := range p.Forwards {
		config.Endpoints = append(config.Endpoints, EndpointSpec{
			Name: forward.Name, Region: forward.Region, Protocol: forward.Protocol,
			GuestPort: forward.GuestPort, HostPort: forward.HostPort,
			DNSNames: append([]string(nil), forward.DNSNames...),
		})
	}
	return config, nil
}

func (p NetworkPlan) tapOwnership() (uint32, uint32, error) {
	expected := make(map[string]bool)
	for _, region := range p.Regions {
		for _, guest := range region.Guests {
			expected[region.Namespace+"\x00"+guest.TAP] = true
		}
	}
	if len(expected) == 0 || len(expected) > maxPlanGuests {
		return 0, 0, errors.New("vmnet: network plan has an invalid guest count")
	}
	seen := make(map[string]bool, len(expected))
	var uid, gid uint32
	ownershipSet := false
	for _, command := range p.Commands {
		args := command.Args
		if len(args) < 3 || args[0] != "-n" || args[2] != "tuntap" {
			continue
		}
		if len(args) < 8 || args[3] != "add" || args[4] != "dev" || args[6] != "mode" || args[7] != "tap" {
			return 0, 0, errors.New("vmnet: malformed TAP creation command")
		}
		key := args[1] + "\x00" + args[5]
		if !expected[key] || seen[key] {
			return 0, 0, errors.New("vmnet: TAP creation is not uniquely owned by a declared guest")
		}
		seen[key] = true
		commandUID, commandGID, err := parseTAPOwner(args[8:])
		if err != nil {
			return 0, 0, err
		}
		if ownershipSet && (uid != commandUID || gid != commandGID) {
			return 0, 0, errors.New("vmnet: TAP ownership differs between guests")
		}
		uid, gid, ownershipSet = commandUID, commandGID, true
	}
	if len(seen) != len(expected) {
		return 0, 0, errors.New("vmnet: network plan lacks one TAP creation per guest")
	}
	return uid, gid, nil
}

func parseTAPOwner(args []string) (uint32, uint32, error) {
	var uid, gid uint32
	for len(args) != 0 {
		if len(args) < 2 {
			return 0, 0, errors.New("vmnet: malformed TAP ownership")
		}
		value, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil || value == 0 {
			return 0, 0, errors.New("vmnet: invalid TAP ownership value")
		}
		switch args[0] {
		case "user":
			if uid != 0 {
				return 0, 0, errors.New("vmnet: duplicate TAP user")
			}
			uid = uint32(value)
		case "group":
			if gid != 0 {
				return 0, 0, errors.New("vmnet: duplicate TAP group")
			}
			gid = uint32(value)
		default:
			return 0, 0, errors.New("vmnet: unsupported TAP ownership field")
		}
		args = args[2:]
	}
	return uid, gid, nil
}

type toolBoundRunner interface {
	ToolPaths() ToolPaths
}

func validateRunnerTools(runner Runner, expected ToolPaths) error {
	if runner == nil {
		return errors.New("vmnet: nil runner")
	}
	bound, ok := runner.(toolBoundRunner)
	if ok && bound.ToolPaths() != expected {
		return errors.New("vmnet: runner tools differ from the network plan")
	}
	return nil
}

func validateRunnerCoordinationRoot(runner Runner, root string) error {
	if root == defaultHostCoordinationDir {
		return nil
	}
	if _, ok := runner.(*RecordingRunner); ok {
		return nil
	}
	if _, ok := runner.(internalNonHostRunner); !ok {
		return errors.New("vmnet: custom coordination root requires the non-host recording runner")
	}
	return nil
}

func (p NetworkPlan) copy() NetworkPlan {
	p.Regions = append([]RegionNetwork(nil), p.Regions...)
	for i := range p.Regions {
		p.Regions[i].Guests = append([]GuestNetwork(nil), p.Regions[i].Guests...)
	}
	p.Uplinks = append([]RegionUplink(nil), p.Uplinks...)
	p.Faults = append([]FaultSpec(nil), p.Faults...)
	p.Forwards = copyForwards(p.Forwards)
	p.Listeners = append([]EndpointListener(nil), p.Listeners...)
	p.DNSRecords = slices.Clone(p.DNSRecords)
	p.Commands = append([]Command(nil), p.Commands...)
	for i := range p.Commands {
		p.Commands[i] = p.Commands[i].copy()
	}
	p.Cleanup = p.Cleanup.copy()
	p.Journal = p.Journal.copy()
	return p
}

func copyForwards(forwards []EndpointForward) []EndpointForward {
	result := append([]EndpointForward(nil), forwards...)
	for i := range result {
		result[i].DNSNames = append([]string(nil), result[i].DNSNames...)
	}
	return result
}

// Endpoint returns a defensive copy of a resolved Region mapping.
func (p NetworkPlan) Endpoint(region RegionCode, name string) (EndpointForward, bool) {
	if p.Validate() != nil {
		return EndpointForward{}, false
	}
	for _, endpoint := range p.Forwards {
		if endpoint.Region == region && endpoint.Name == name {
			endpoint.DNSNames = append([]string(nil), endpoint.DNSNames...)
			return endpoint, true
		}
	}
	return EndpointForward{}, false
}

// Listener returns the shared root listener for an endpoint name.
func (p NetworkPlan) Listener(name string) (EndpointListener, bool) {
	if p.Validate() != nil {
		return EndpointListener{}, false
	}
	for _, listener := range p.Listeners {
		if listener.Name == name {
			return listener, true
		}
	}
	return EndpointListener{}, false
}

// RegionDNSRecords returns defensive copies of the guest records for region.
func (p NetworkPlan) RegionDNSRecords(region RegionCode) []DNSRecord {
	if p.Validate() != nil {
		return nil
	}
	var records []DNSRecord
	for _, record := range p.DNSRecords {
		if record.Region == region {
			records = append(records, record)
		}
	}
	return records
}

// CleanupPlan returns a defensive copy of the crash-safe cleanup record.
func (p NetworkPlan) CleanupPlan() CleanupPlan { return p.Cleanup.copy() }

// Apply accepts only a runner that also durably writes Journal. Callers with a
// separate journal implementation should use ApplyWithJournal. This keeps the
// journal-before-mutation rule mandatory at the vmnet boundary.
func (p NetworkPlan) Apply(ctx context.Context, runner Runner) error {
	writer, ok := runner.(JournalWriter)
	if !ok {
		return errors.New("vmnet: durable journal writer is required before apply")
	}
	return p.ApplyWithJournal(ctx, runner, writer)
}

// ApplyWithJournal durably records cleanup before applying setup. A journal
// write failure performs no host mutation.
func (p NetworkPlan) ApplyWithJournal(ctx context.Context, runner Runner, writer JournalWriter) error {
	if writer == nil {
		return errors.New("vmnet: nil journal writer")
	}
	if runner == nil {
		return errors.New("vmnet: nil runner")
	}
	if ctx == nil {
		return errors.New("vmnet: nil context")
	}
	p = p.copy()
	if err := p.Validate(); err != nil {
		return err
	}
	if err := validateRunnerTools(runner, p.Tools); err != nil {
		return err
	}
	if err := validateRunnerCoordinationRoot(runner, p.CoordinationRoot); err != nil {
		return err
	}
	coordinator, unlock := lockRunCoordinator(p.RunID)
	defer unlock()
	if err := coordinator.bind(p.Fingerprint); err != nil {
		return err
	}
	if coordinator.applied {
		return nil
	}
	if coordinator.cleanupRequired {
		return errors.New("vmnet: incomplete cleanup must be replayed before apply")
	}
	if coordinator.hostLease == nil {
		lease, recovered, err := acquireHostLease(p.CoordinationRoot, p.RunID, p.Fingerprint, p.Uplinks)
		if err != nil {
			return err
		}
		coordinator.hostLease = lease
		if recovered {
			coordinator.cleanupRequired = true
			return errors.New("vmnet: recovered host allocation requires cleanup before apply")
		}
	}
	if host, ok := runner.(interface {
		checkHostInputCollision(context.Context, []Command) error
	}); ok {
		if err := host.checkHostInputCollision(ctx, p.Commands); err != nil {
			coordinator.hostLease.unlock()
			coordinator.hostLease = nil
			return err
		}
	}
	if host, ok := runner.(interface {
		checkRootLinkCollisions(context.Context, []RootLinkCleanup) error
	}); ok {
		if err := host.checkRootLinkCollisions(ctx, p.Cleanup.RootLinks); err != nil {
			coordinator.hostLease.unlock()
			coordinator.hostLease = nil
			return err
		}
	}
	if err := writer.WriteJournal(ctx, p.Journal.copy()); err != nil {
		coordinator.hostLease.unlock()
		coordinator.hostLease = nil
		coordinator.fingerprint = ""
		return fmt.Errorf("vmnet: write cleanup journal: %w", err)
	}
	coordinator.cleanupRequired = true
	if err := coordinator.hostLease.publish(); err != nil {
		return fmt.Errorf("vmnet: publish host allocation: %w", err)
	}
	if err := p.applyLocked(ctx, runner); err != nil {
		return err
	}
	coordinator.applied = true
	coordinator.cleanupRequired = false
	coordinator.resetFaults(p.Faults)
	return nil
}

func (p NetworkPlan) applyLocked(ctx context.Context, runner Runner) error {
	for i, c := range p.Commands {
		if err := ctx.Err(); err != nil {
			cleanupErr := p.Cleanup.runLocked(ctx, runner)
			return applyError(i, err, cleanupErr)
		}
		if err := runner.Run(ctx, c.Executable, append([]string(nil), c.Args...)); err != nil {
			cleanupErr := p.Cleanup.runLocked(ctx, runner)
			return applyError(i, err, cleanupErr)
		}
	}
	return nil
}

func applyError(index int, applyErr, cleanupErr error) error {
	if cleanupErr != nil {
		return fmt.Errorf("vmnet: command %d failed: %w (cleanup: %v)", index, applyErr, cleanupErr)
	}
	return fmt.Errorf("vmnet: command %d failed: %w", index, applyErr)
}

// Rollback is an explicit alias useful to controller crash handlers.
func (p NetworkPlan) Rollback(ctx context.Context, runner Runner) error {
	return p.Cleanup.Run(ctx, runner)
}

var (
	identifierPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	dnsNamePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	runIDPattern           = regexp.MustCompile(`^[a-f0-9]{32}$`)
	runTokenPattern        = regexp.MustCompile(`^[a-f0-9]{32}$`)
	defaultRunIDOnce       sync.Once
	defaultRunIDValue      string
	defaultRunIDError      error
	runCoordinatorRegistry = struct {
		sync.Mutex
		entries map[string]*runCoordinatorEntry
	}{entries: make(map[string]*runCoordinatorEntry)}
)

type runCoordinator struct {
	fingerprint     string
	applied         bool
	cleanupRequired bool
	partitions      map[string]bool
	hostLease       *hostLease
}

type runCoordinatorEntry struct {
	mu          sync.Mutex
	coordinator runCoordinator
	references  int
}

func lockRunCoordinator(runID string) (*runCoordinator, func()) {
	runCoordinatorRegistry.Lock()
	entry := runCoordinatorRegistry.entries[runID]
	if entry == nil {
		entry = &runCoordinatorEntry{coordinator: runCoordinator{partitions: make(map[string]bool)}}
		runCoordinatorRegistry.entries[runID] = entry
	}
	entry.references++
	runCoordinatorRegistry.Unlock()

	entry.mu.Lock()
	return &entry.coordinator, func() {
		// The entry mutex is still held here, so the registry can inspect state
		// without racing another operation. An inactive entry is retired only
		// after this package has completed cleanup successfully.
		runCoordinatorRegistry.Lock()
		entry.references--
		if entry.references == 0 && !entry.coordinator.applied && !entry.coordinator.cleanupRequired && entry.coordinator.hostLease == nil && runCoordinatorRegistry.entries[runID] == entry {
			delete(runCoordinatorRegistry.entries, runID)
		}
		runCoordinatorRegistry.Unlock()
		entry.mu.Unlock()
	}
}

func (c *runCoordinator) bind(fingerprint string) error {
	if (c.applied || c.cleanupRequired) && c.fingerprint != fingerprint {
		return errors.New("vmnet: run identity is already bound to a different network plan")
	}
	c.fingerprint = fingerprint
	return nil
}

func (c *runCoordinator) resetFaults(faults []FaultSpec) {
	c.partitions = make(map[string]bool)
	for _, fault := range faults {
		if fault.Partition {
			c.partitions[regionPairKey(fault.From, fault.To)] = true
		}
	}
}

func regionPairKey(a, b RegionCode) string {
	if regionIndex(a) > regionIndex(b) {
		a, b = b, a
	}
	return string(a) + "\x00" + string(b)
}

// DefaultRunID returns the per-process network ownership identity. Repeated
// Plan calls in one qualification process must resolve the same namespace
// names because the CLI builds the VM and network views independently.
func DefaultRunID() (string, error) {
	defaultRunIDOnce.Do(func() {
		var value [16]byte
		if _, err := rand.Read(value[:]); err != nil {
			defaultRunIDError = fmt.Errorf("vmnet: generate run ID: %w", err)
			return
		}
		defaultRunIDValue = hex.EncodeToString(value[:])
	})
	return defaultRunIDValue, defaultRunIDError
}

func validIdentifier(value, field string, max int) error {
	if len(value) == 0 || len(value) > max || !identifierPattern.MatchString(value) {
		return fmt.Errorf("vmnet: %s must be a lowercase identifier of 1-%d characters", field, max)
	}
	return nil
}

func regionIndex(code RegionCode) int {
	for i, candidate := range launchRegions {
		if candidate == code {
			return i
		}
	}
	if len(code) == 3 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' && code[2] >= 'A' && code[2] <= 'Z' {
		return 3 + int(code[0]-'A')*676 + int(code[1]-'A')*26 + int(code[2]-'A')
	}
	return -1
}

func validRegion(code RegionCode) bool { return regionIndex(code) >= 0 }

func allocationIndex(codes []RegionCode, code RegionCode) int {
	if index := regionIndex(code); index >= 0 && index < 3 {
		return index
	}
	next := 3
	for _, candidate := range codes {
		if regionIndex(candidate) < 3 {
			continue
		}
		if candidate == code {
			return next
		}
		next++
	}
	return -1
}

func parseCIDR(value, field string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 24 || prefix.Bits() > 30 || prefix != prefix.Masked() || !prefix.Addr().IsPrivate() || !prefix.Addr().IsGlobalUnicast() {
		return netip.Prefix{}, fmt.Errorf("vmnet: %s must be a canonical private-unicast IPv4 CIDR (/24-/30)", field)
	}
	return prefix, nil
}

func broadcast(prefix netip.Prefix) netip.Addr {
	hostBits := 32 - prefix.Bits()
	offset := uint32(1)<<uint(hostBits) - 1
	address, _ := addIPv4(prefix.Addr(), offset)
	return address
}

func addIPv4(address netip.Addr, offset uint32) (netip.Addr, bool) {
	if !address.Is4() {
		return netip.Addr{}, false
	}
	bytes := address.As4()
	value := binary.BigEndian.Uint32(bytes[:])
	if offset > ^uint32(0)-value {
		return netip.Addr{}, false
	}
	value += offset
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes), true
}

func netemDuration(duration time.Duration) string {
	if duration%time.Second == 0 {
		return strconv.FormatInt(int64(duration/time.Second), 10) + "s"
	}
	if duration%time.Millisecond == 0 {
		return strconv.FormatInt(int64(duration/time.Millisecond), 10) + "ms"
	}
	return strconv.FormatInt(int64(duration/time.Microsecond), 10) + "us"
}

func runToken(runID string) string {
	digest := sha256.Sum256([]byte(runID))
	return hex.EncodeToString(digest[:6])
}

func regionNetworkName(prefix, runID string, code RegionCode) string {
	return prefix + "-" + runID + "-n-" + strings.ToLower(string(code))
}

func interfaceToken(runID string) string { return runToken(runID)[:4] }

func regionBridgeName(prefix, runID string, code RegionCode) string {
	return prefix + "b" + interfaceToken(runID) + strings.ToLower(string(code))
}

func networkTable(prefix, runID string) string {
	return prefix + "_" + runID + "_vmnet"
}

func faultChain(from, to RegionCode) string {
	return "fault_" + strings.ToLower(string(from)) + "_" + strings.ToLower(string(to))
}

func linkDevice(prefix, runID string, from, to RegionCode) string {
	return prefix + "v" + interfaceToken(runID)[:3] + strings.ToLower(string(from)) + strings.ToLower(string(to))
}

func uplinkDevice(prefix, runID string, region RegionCode, root bool) string {
	side := "u"
	if root {
		side = "h"
	}
	return prefix + side + runToken(runID)[:6] + strings.ToLower(string(region))
}

func hostServiceAddress(runID string) netip.Addr {
	digest := sha256.Sum256([]byte("vmnet-service\x00" + runID))
	// The service half of the benchmark range is 198.19.0.0/16. A /32 keeps
	// the listener unreachable until a declared Region route and nft mapping
	// have both been installed.
	offset := binary.BigEndian.Uint32(digest[:4]) & ((1 << 16) - 1)
	address, _ := addIPv4(netip.AddrFrom4([4]byte{198, 19, 0, 0}), offset)
	return address
}

func regionUplink(prefix, runID string, region RegionCode, allocation int, ownsService bool) RegionUplink {
	digest := sha256.Sum256([]byte("vmnet-uplink\x00" + runID))
	// Keep all uplinks in the other benchmark half, 198.18.0.0/16.
	// This is disjoint from host service /32s and avoids ambient CGNAT
	// policies (including Tailscale anti-spoof filtering). Each Region gets
	// one of 16,384 deterministic /30s with no external route.
	slot := (binary.BigEndian.Uint32(digest[:4]) + uint32(allocation)) & ((1 << 14) - 1)
	base, _ := addIPv4(netip.AddrFrom4([4]byte{198, 18, 0, 0}), slot*4)
	rootAddress, _ := addIPv4(base, 1)
	regionAddress, _ := addIPv4(base, 2)
	return RegionUplink{
		Region: region, RegionNamespace: regionNetworkName(prefix, runID, region),
		RegionDevice: uplinkDevice(prefix, runID, region, false),
		RootDevice:   uplinkDevice(prefix, runID, region, true),
		CIDR:         netip.PrefixFrom(base, 30).String(), RegionAddress: regionAddress.String(),
		RootAddress: rootAddress.String(), HostServiceAddress: hostServiceAddress(runID).String(),
		OwnsServiceAddress: ownsService,
	}
}

func defaultEndpointSpecs(regions []RegionNetwork) []EndpointSpec {
	endpoints := make([]EndpointSpec, 0, len(regions)*4)
	for _, region := range regions {
		endpoints = append(endpoints,
			EndpointSpec{Name: "nats", Region: region.Code, Protocol: TCP, GuestPort: 4222, HostPort: 4222},
			EndpointSpec{Name: "artifacts", Region: region.Code, Protocol: TCP, GuestPort: 8443, HostPort: 8443, DNSNames: []string{"releases.terrascale.tech"}},
			EndpointSpec{Name: "smoke", Region: region.Code, Protocol: TCP, GuestPort: 18080, HostPort: 18080},
			EndpointSpec{Name: "ntp", Region: region.Code, Protocol: UDP, GuestPort: 123, HostPort: 18123},
		)
	}
	return endpoints
}

func validDNSName(name string) bool {
	return len(name) <= 253 && dnsNamePattern.MatchString(name)
}

func validateResolvedEndpoints(prefix, runID string, regions []RegionCode, uplinks []RegionUplink, forwards []EndpointForward, listeners []EndpointListener, records []DNSRecord) error {
	if len(uplinks) != len(regions) || len(forwards) > maxPlanForwards || len(records) > maxDNSRecords {
		return errors.New("endpoint manifest exceeds topology bounds")
	}
	declared := make(map[RegionCode]bool, len(regions))
	serviceAddress := hostServiceAddress(runID).String()
	for index, region := range regions {
		declared[region] = true
		expected := regionUplink(prefix, runID, region, allocationIndex(regions, region), index == 0)
		if uplinks[index] != expected {
			return fmt.Errorf("Region %s uplink is not run-owned", region)
		}
	}

	type listenerKey struct {
		protocol TransportProtocol
		port     uint16
	}
	wantedListeners := make(map[string]listenerKey)
	wantedListenerNamesByPort := make(map[uint16]string)
	wantedRecords := make([]DNSRecord, 0)
	seenForwards := make(map[string]bool, len(forwards))
	seenGuestPorts := make(map[string]bool, len(forwards))
	lastRegion, lastName := RegionCode(""), ""
	for index, forward := range forwards {
		if !declared[forward.Region] || validIdentifier(forward.Name, "endpoint name", 32) != nil || !validEndpointTransport(forward.Name, forward.Protocol, forward.GuestPort, forward.HostPort) || forward.HostAddress != serviceAddress || len(forward.DNSNames) > maxEndpointDNS {
			return errors.New("invalid endpoint forward")
		}
		guestAddress, err := netip.ParseAddr(forward.GuestAddress)
		if err != nil || !guestAddress.Is4() || !guestAddress.IsPrivate() {
			return errors.New("endpoint guest address is not private IPv4")
		}
		key := string(forward.Region) + "\x00" + forward.Name
		if seenForwards[key] {
			return errors.New("duplicate endpoint forward")
		}
		seenForwards[key] = true
		guestPortKey := string(forward.Region) + "\x00" + string(forward.Protocol) + "\x00" + strconv.FormatUint(uint64(forward.GuestPort), 10)
		if seenGuestPorts[guestPortKey] {
			return errors.New("duplicate guest endpoint port")
		}
		seenGuestPorts[guestPortKey] = true
		if index > 0 && (regionIndex(lastRegion) > regionIndex(forward.Region) || lastRegion == forward.Region && lastName >= forward.Name) {
			return errors.New("endpoint forwards are not canonical")
		}
		lastRegion, lastName = forward.Region, forward.Name
		listener := listenerKey{protocol: forward.Protocol, port: forward.HostPort}
		if prior, ok := wantedListeners[forward.Name]; ok && prior != listener {
			return errors.New("shared endpoint listener differs between Regions")
		}
		if priorName, ok := wantedListenerNamesByPort[forward.HostPort]; ok && priorName != forward.Name {
			return errors.New("distinct endpoint listeners share one host port")
		}
		wantedListeners[forward.Name] = listener
		wantedListenerNamesByPort[forward.HostPort] = forward.Name
		for dnsIndex, name := range forward.DNSNames {
			if !validDNSName(name) || dnsIndex > 0 && forward.DNSNames[dnsIndex-1] >= name {
				return errors.New("invalid or noncanonical endpoint DNS name")
			}
			wantedRecords = append(wantedRecords, DNSRecord{Region: forward.Region, Name: name, Type: DNSA, Address: forward.GuestAddress})
		}
	}

	wantedListenerSlice := make([]EndpointListener, 0, len(wantedListeners))
	for name, listener := range wantedListeners {
		wantedListenerSlice = append(wantedListenerSlice, EndpointListener{Name: name, Protocol: listener.protocol, Address: serviceAddress, Port: listener.port})
	}
	sort.Slice(wantedListenerSlice, func(i, j int) bool { return wantedListenerSlice[i].Name < wantedListenerSlice[j].Name })
	sort.Slice(wantedRecords, func(i, j int) bool {
		if wantedRecords[i].Region != wantedRecords[j].Region {
			return regionIndex(wantedRecords[i].Region) < regionIndex(wantedRecords[j].Region)
		}
		return wantedRecords[i].Name < wantedRecords[j].Name
	})
	for index := 1; index < len(wantedRecords); index++ {
		if wantedRecords[index-1].Region == wantedRecords[index].Region && wantedRecords[index-1].Name == wantedRecords[index].Name {
			return errors.New("duplicate endpoint DNS record")
		}
	}
	if len(wantedListenerSlice) == 0 {
		wantedListenerSlice = nil
		wantedRecords = nil
	}
	if !slices.Equal(listeners, wantedListenerSlice) || !slices.Equal(records, wantedRecords) {
		return errors.New("listener or DNS manifest does not match endpoint forwards")
	}
	return nil
}

func validatePercentage(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 100
}

const (
	maxNetemDelay         = 24 * time.Hour
	maxNetemBandwidthKbit = uint64(1_000_000_000)
)

func validateFault(fault FaultSpec, allowPartition bool) error {
	if !validRegion(fault.From) || !validRegion(fault.To) || fault.From == fault.To {
		return fmt.Errorf("vmnet: invalid fault link %s -> %s", fault.From, fault.To)
	}
	if fault.Latency < 0 || fault.Latency > maxNetemDelay || fault.Jitter < 0 || fault.Jitter > maxNetemDelay || fault.Latency%time.Microsecond != 0 || fault.Jitter%time.Microsecond != 0 || fault.BandwidthKbit > maxNetemBandwidthKbit || !validatePercentage(fault.LossPercent) || !validatePercentage(fault.ReorderPercent) || !validatePercentage(fault.DuplicatePercent) {
		return fmt.Errorf("vmnet: invalid fault values for %s -> %s", fault.From, fault.To)
	}
	if fault.Jitter > 0 && fault.Latency == 0 {
		return fmt.Errorf("vmnet: jitter requires latency for %s -> %s", fault.From, fault.To)
	}
	if fault.ReorderPercent > 0 && fault.Latency == 0 {
		return fmt.Errorf("vmnet: reordering requires latency for %s -> %s", fault.From, fault.To)
	}
	if !allowPartition && fault.Partition {
		return errors.New("vmnet: use Partition for bidirectional link cuts")
	}
	if fault.BandwidthKbit == 0 && !fault.Partition && fault.Latency == 0 && fault.Jitter == 0 && fault.LossPercent == 0 && fault.ReorderPercent == 0 && fault.DuplicatePercent == 0 {
		return fmt.Errorf("vmnet: fault for %s -> %s has no effect", fault.From, fault.To)
	}
	return nil
}

func transitIP(index int, side int) (netip.Addr, netip.Addr, error) {
	// 10.78.252.0/22 is reserved solely for deterministic cross-Region /30
	// links. Stable guest networks occupy 10.77.0.0/16.
	base := index * 4
	if index < 0 || base > 1020 {
		return netip.Addr{}, netip.Addr{}, errors.New("vmnet: too many Region links")
	}
	a, _ := addIPv4(transitPrefix.Addr(), uint32(base+1))
	b, _ := addIPv4(transitPrefix.Addr(), uint32(base+2))
	if side == 0 {
		return a, b, nil
	}
	return b, a, nil
}

// Plan validates the declaration and builds deterministic shell-free argv.
// It does not open sockets, create files, or touch host networking.
func Plan(config Config) (NetworkPlan, error) {
	prefix := config.Prefix
	if prefix == "" {
		prefix = "ts"
	}
	if err := validIdentifier(prefix, "prefix", 5); err != nil {
		return NetworkPlan{}, err
	}
	runID := config.RunID
	if runID == "" {
		var err error
		runID, err = DefaultRunID()
		if err != nil {
			return NetworkPlan{}, err
		}
	}
	if !runIDPattern.MatchString(runID) {
		return NetworkPlan{}, errors.New("vmnet: run ID must be 32 lowercase hexadecimal characters")
	}
	coordinationRoot := config.CoordinationRoot
	if coordinationRoot == "" {
		coordinationRoot = defaultHostCoordinationDir
	}
	if err := validateHostCoordinationRoot(coordinationRoot); err != nil {
		return NetworkPlan{}, err
	}
	tools := config.Tools
	if tools == (ToolPaths{}) {
		var err error
		tools, err = DiscoverToolPaths()
		if err != nil {
			return NetworkPlan{}, err
		}
	}
	if err := tools.Validate(); err != nil {
		return NetworkPlan{}, err
	}
	if len(config.Regions) == 0 || len(config.Regions) > MaxRegions {
		return NetworkPlan{}, errors.New("vmnet: 1-20 Regions are required")
	}
	regions := append([]RegionSpec(nil), config.Regions...)
	sort.SliceStable(regions, func(i, j int) bool {
		a, b := regionIndex(regions[i].Code), regionIndex(regions[j].Code)
		if a >= 3 && b >= 3 {
			return false
		}
		return a < b
	})
	codes := make([]RegionCode, len(regions))
	for index, region := range regions {
		codes[index] = region.Code
	}
	resolved := make([]RegionNetwork, 0, len(regions))
	seenRegions := make(map[RegionCode]bool, len(regions))
	seenTAPs := make(map[string]bool)
	allGuests := make(map[string]bool)
	seenCIDRs := make([]netip.Prefix, 0, len(regions))
	for _, spec := range regions {
		if !validRegion(spec.Code) {
			return NetworkPlan{}, fmt.Errorf("vmnet: unsupported Region %q", spec.Code)
		}
		if seenRegions[spec.Code] {
			return NetworkPlan{}, fmt.Errorf("vmnet: duplicate Region %q", spec.Code)
		}
		seenRegions[spec.Code] = true
		cidr := spec.CIDR
		if cidr == "" {
			cidr = fmt.Sprintf("10.77.%d.0/24", allocationIndex(codes, spec.Code))
		}
		prefixCIDR, err := parseCIDR(cidr, "Region CIDR")
		if err != nil {
			return NetworkPlan{}, err
		}
		if prefixCIDR.Overlaps(transitPrefix) {
			return NetworkPlan{}, fmt.Errorf("vmnet: Region CIDR %s overlaps reserved transit network %s", prefixCIDR, transitPrefix)
		}
		for _, prior := range seenCIDRs {
			if prefixCIDR.Overlaps(prior) {
				return NetworkPlan{}, fmt.Errorf("vmnet: Region CIDRs overlap (%s and %s)", prefixCIDR, prior)
			}
		}
		seenCIDRs = append(seenCIDRs, prefixCIDR)
		if allocationIndex(codes, spec.Code) >= MaxRegions {
			return NetworkPlan{}, errors.New("vmnet: at most17 additional Region slots are available")
		}
		if regionIndex(spec.Code) >= 3 && len(spec.Guests) < 2 {
			return NetworkPlan{}, fmt.Errorf("vmnet: additional Region %s requires at least two guests", spec.Code)
		}
		if regionIndex(spec.Code) >= 3 {
			for _, baseline := range launchRegions {
				if prefixCIDR.Overlaps(netip.MustParsePrefix(StableCIDR(baseline))) {
					return NetworkPlan{}, errors.New("vmnet: additional Region overlaps reserved launch subnet")
				}
			}
		}
		if len(spec.Guests) == 0 || len(spec.Guests) > 32 {
			return NetworkPlan{}, fmt.Errorf("vmnet: Region %s must have 1-32 guests", spec.Code)
		}
		guests := append([]GuestSpec(nil), spec.Guests...)
		sort.Slice(guests, func(i, j int) bool { return guests[i].ID < guests[j].ID })
		seenGuests := make(map[string]bool, len(guests))
		seenAddresses := make(map[netip.Addr]bool, len(guests))
		resolvedGuests := make([]GuestNetwork, 0, len(guests))
		gateway, ok := addIPv4(prefixCIDR.Addr(), 1)
		if !ok || !prefixCIDR.Contains(gateway) || gateway == broadcast(prefixCIDR) {
			return NetworkPlan{}, fmt.Errorf("vmnet: Region %s CIDR has no usable gateway", spec.Code)
		}
		for guestIndex, guest := range guests {
			if err := validIdentifier(guest.ID, "guest ID", 32); err != nil {
				return NetworkPlan{}, err
			}
			if seenGuests[guest.ID] || allGuests[guest.ID] {
				return NetworkPlan{}, fmt.Errorf("vmnet: duplicate guest %q in %s", guest.ID, spec.Code)
			}
			seenGuests[guest.ID] = true
			allGuests[guest.ID] = true
			tap := guest.TAP
			if tap == "" {
				tap = fmt.Sprintf("%st%s%s%02d", prefix, interfaceToken(runID), strings.ToLower(string(spec.Code)), guestIndex+1)
			}
			if err := validIdentifier(tap, "TAP", 15); err != nil {
				return NetworkPlan{}, err
			}
			if seenTAPs[tap] {
				return NetworkPlan{}, fmt.Errorf("vmnet: duplicate TAP %q", tap)
			}
			seenTAPs[tap] = true
			address := guest.Address
			if address == "" {
				// The first guest is network+10; each subsequent guest increments it.
				guestAddress, ok := addIPv4(prefixCIDR.Addr(), uint32(10+guestIndex))
				if !ok || !prefixCIDR.Contains(guestAddress) || guestAddress == broadcast(prefixCIDR) {
					return NetworkPlan{}, fmt.Errorf("vmnet: Region %s CIDR is too small for default guest ordinal %d", spec.Code, guestIndex+1)
				}
				address = guestAddress.String()
			}
			guestAddress, err := netip.ParseAddr(address)
			if err != nil || !guestAddress.Is4() || !prefixCIDR.Contains(guestAddress) || guestAddress == prefixCIDR.Addr() || guestAddress == gateway || guestAddress == broadcast(prefixCIDR) || seenAddresses[guestAddress] {
				return NetworkPlan{}, fmt.Errorf("vmnet: guest %s address %q is outside %s", guest.ID, address, prefixCIDR)
			}
			seenAddresses[guestAddress] = true
			mac := fmt.Sprintf("02:fc:77:%02x:%02x:01", allocationIndex(codes, spec.Code)+1, guestIndex+1)
			resolvedGuests = append(resolvedGuests, GuestNetwork{ID: guest.ID, TAP: tap, Address: guestAddress.String(), MAC: mac})
		}
		namespace := regionNetworkName(prefix, runID, spec.Code)
		resolved = append(resolved, RegionNetwork{Code: spec.Code, CIDR: prefixCIDR.String(), Namespace: namespace, NamespacePath: "/run/netns/" + namespace, Bridge: regionBridgeName(prefix, runID, spec.Code), Gateway: gateway.String(), Guests: resolvedGuests})
	}
	for index := range resolved {
		resolved[index].Uplink = regionUplink(prefix, runID, resolved[index].Code, allocationIndex(codes, resolved[index].Code), index == 0)
	}

	endpointSpecs := config.Endpoints
	if endpointSpecs == nil {
		endpointSpecs = defaultEndpointSpecs(resolved)
	} else {
		if len(endpointSpecs) > maxPlanForwards {
			return NetworkPlan{}, errors.New("vmnet: endpoint declarations exceed topology bounds")
		}
		endpointSpecs = append([]EndpointSpec(nil), endpointSpecs...)
		for index := range endpointSpecs {
			if len(endpointSpecs[index].DNSNames) > maxEndpointDNS {
				return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q has too many DNS names", endpointSpecs[index].Name)
			}
			endpointSpecs[index].DNSNames = append([]string(nil), endpointSpecs[index].DNSNames...)
		}
	}
	if len(endpointSpecs) > maxPlanForwards {
		return NetworkPlan{}, errors.New("vmnet: endpoint declarations exceed topology bounds")
	}
	sort.Slice(endpointSpecs, func(i, j int) bool {
		if endpointSpecs[i].Region != endpointSpecs[j].Region {
			return regionIndex(endpointSpecs[i].Region) < regionIndex(endpointSpecs[j].Region)
		}
		return endpointSpecs[i].Name < endpointSpecs[j].Name
	})
	regionByCode := make(map[RegionCode]RegionNetwork, len(resolved))
	for _, region := range resolved {
		regionByCode[region.Code] = region
	}
	forwards := make([]EndpointForward, 0, len(endpointSpecs))
	listenersByName := make(map[string]EndpointListener)
	listenerNamesByPort := make(map[uint16]string)
	dnsRecords := make([]DNSRecord, 0)
	seenEndpoints := make(map[string]bool, len(endpointSpecs))
	seenGuestPorts := make(map[string]bool, len(endpointSpecs))
	seenDNS := make(map[string]bool)
	for _, spec := range endpointSpecs {
		region, ok := regionByCode[spec.Region]
		if !ok {
			return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q references undeclared Region %s", spec.Name, spec.Region)
		}
		if err := validIdentifier(spec.Name, "endpoint name", 32); err != nil {
			return NetworkPlan{}, err
		}
		if !validEndpointTransport(spec.Name, spec.Protocol, spec.GuestPort, spec.HostPort) {
			return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q must declare nonzero TCP ports or the fixed qualification NTP endpoint", spec.Name)
		}
		key := string(spec.Region) + "\x00" + spec.Name
		if seenEndpoints[key] {
			return NetworkPlan{}, fmt.Errorf("vmnet: duplicate endpoint %q in %s", spec.Name, spec.Region)
		}
		seenEndpoints[key] = true
		guestPortKey := string(spec.Region) + "\x00" + string(spec.Protocol) + "\x00" + strconv.FormatUint(uint64(spec.GuestPort), 10)
		if seenGuestPorts[guestPortKey] {
			return NetworkPlan{}, fmt.Errorf("vmnet: duplicate guest endpoint port %d in %s", spec.GuestPort, spec.Region)
		}
		seenGuestPorts[guestPortKey] = true
		dnsNames := append([]string(nil), spec.DNSNames...)
		sort.Strings(dnsNames)
		for dnsIndex, name := range dnsNames {
			if !validDNSName(name) {
				return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q has invalid DNS name %q", spec.Name, name)
			}
			dnsKey := string(spec.Region) + "\x00" + name
			if dnsIndex > 0 && dnsNames[dnsIndex-1] == name || seenDNS[dnsKey] {
				return NetworkPlan{}, fmt.Errorf("vmnet: duplicate DNS name %q in %s", name, spec.Region)
			}
			seenDNS[dnsKey] = true
			dnsRecords = append(dnsRecords, DNSRecord{Region: spec.Region, Name: name, Type: DNSA, Address: region.Gateway})
		}
		forward := EndpointForward{
			Name: spec.Name, Region: spec.Region, Protocol: spec.Protocol,
			GuestAddress: region.Gateway, GuestPort: spec.GuestPort,
			HostAddress: hostServiceAddress(runID).String(), HostPort: spec.HostPort,
			DNSNames: dnsNames,
		}
		forwards = append(forwards, forward)
		listener := EndpointListener{Name: spec.Name, Protocol: spec.Protocol, Address: forward.HostAddress, Port: spec.HostPort}
		if prior, exists := listenersByName[spec.Name]; exists && prior != listener {
			return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q listener differs between Regions", spec.Name)
		}
		if priorName, exists := listenerNamesByPort[spec.HostPort]; exists && priorName != spec.Name {
			return NetworkPlan{}, fmt.Errorf("vmnet: endpoint %q shares host port %d with %q", spec.Name, spec.HostPort, priorName)
		}
		listenersByName[spec.Name] = listener
		listenerNamesByPort[spec.HostPort] = spec.Name
	}
	listeners := make([]EndpointListener, 0, len(listenersByName))
	for _, listener := range listenersByName {
		listeners = append(listeners, listener)
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Name < listeners[j].Name })
	sort.Slice(dnsRecords, func(i, j int) bool {
		if dnsRecords[i].Region != dnsRecords[j].Region {
			return regionIndex(dnsRecords[i].Region) < regionIndex(dnsRecords[j].Region)
		}
		return dnsRecords[i].Name < dnsRecords[j].Name
	})
	if len(forwards) == 0 {
		forwards = nil
		listeners = nil
		dnsRecords = nil
	}
	manifestRegions := make([]RegionCode, 0, len(resolved))
	uplinks := make([]RegionUplink, 0, len(resolved))
	for _, region := range resolved {
		manifestRegions = append(manifestRegions, region.Code)
		uplinks = append(uplinks, region.Uplink)
	}
	if err := validateResolvedEndpoints(prefix, runID, manifestRegions, uplinks, forwards, listeners, dnsRecords); err != nil {
		return NetworkPlan{}, fmt.Errorf("vmnet: resolve endpoint manifest: %w", err)
	}

	commands := make([]Command, 0)
	cleanup := make([]Command, 0)
	table := networkTable(prefix, runID)
	for _, region := range resolved {
		uplinkPrefix := netip.MustParsePrefix(region.Uplink.CIDR)
		commands = append(commands,
			command(tools.IP, "netns", "add", region.Namespace),
			command(tools.IP, "-n", region.Namespace, "link", "set", "lo", "up"),
			command(tools.IP, "-n", region.Namespace, "link", "add", region.Bridge, "type", "bridge"),
			command(tools.IP, "-n", region.Namespace, "link", "set", "dev", region.Bridge, "mtu", "1500"),
			command(tools.IP, "-n", region.Namespace, "link", "set", region.Bridge, "up"),
			command(tools.IP, "-n", region.Namespace, "addr", "add", region.Gateway+"/"+strconv.Itoa(netip.MustParsePrefix(region.CIDR).Bits()), "dev", region.Bridge),
			command(tools.IP, "netns", "exec", region.Namespace, tools.Sysctl, "-q", "-w", "net.ipv4.ip_forward=1"),
			command(tools.IP, "link", "add", region.Uplink.RootDevice, "address", rootLinkAddress(prefix, runID, region.Code), "type", "veth", "peer", "name", region.Uplink.RegionDevice, "netns", region.Namespace),
			command(tools.IP, "-n", region.Namespace, "addr", "add", region.Uplink.RegionAddress+"/"+strconv.Itoa(uplinkPrefix.Bits()), "dev", region.Uplink.RegionDevice),
			command(tools.IP, "-n", region.Namespace, "link", "set", region.Uplink.RegionDevice, "up"),
			command(tools.IP, "addr", "add", region.Uplink.RootAddress+"/"+strconv.Itoa(uplinkPrefix.Bits()), "dev", region.Uplink.RootDevice),
		)
		if region.Uplink.OwnsServiceAddress {
			commands = append(commands, command(tools.IP, "addr", "add", region.Uplink.HostServiceAddress+"/32", "dev", region.Uplink.RootDevice))
		}
		commands = append(commands,
			command(tools.IP, "link", "set", region.Uplink.RootDevice, "up"),
			command(tools.IP, "-n", region.Namespace, "route", "add", region.Uplink.HostServiceAddress+"/32", "via", region.Uplink.RootAddress, "dev", region.Uplink.RegionDevice),
		)
		for _, guest := range region.Guests {
			tuntap := []string{"-n", region.Namespace, "tuntap", "add", "dev", guest.TAP, "mode", "tap"}
			if config.TAPUID != 0 {
				tuntap = append(tuntap, "user", strconv.FormatUint(uint64(config.TAPUID), 10))
			}
			if config.TAPGID != 0 {
				tuntap = append(tuntap, "group", strconv.FormatUint(uint64(config.TAPGID), 10))
			}
			commands = append(commands,
				command(tools.IP, tuntap...),
				command(tools.IP, "-n", region.Namespace, "link", "set", guest.TAP, "master", region.Bridge),
				command(tools.IP, "-n", region.Namespace, "link", "set", guest.TAP, "up"),
			)
		}
		commands = append(commands,
			command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "table", "inet", table),
			command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "chain", "inet", table, "forward", "{ type filter hook forward priority 0; policy drop; }"),
			command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "ct", "state", "established,related", "accept"),
			command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "chain", "inet", table, "prerouting", "{ type nat hook prerouting priority dstnat; policy accept; }"),
			command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "chain", "inet", table, "postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }"),
		)
		for _, forward := range forwards {
			if forward.Region != region.Code {
				continue
			}
			guestPort := strconv.FormatUint(uint64(forward.GuestPort), 10)
			hostPort := strconv.FormatUint(uint64(forward.HostPort), 10)
			commands = append(commands,
				command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "rule", "inet", table, "prerouting", "iifname", region.Bridge, "ip", "saddr", region.CIDR, "ip", "daddr", forward.GuestAddress, string(forward.Protocol), "dport", guestPort, "dnat", "ip", "to", forward.HostAddress+":"+hostPort),
				command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "rule", "inet", table, "postrouting", "oifname", region.Uplink.RegionDevice, "ip", "saddr", region.CIDR, "ip", "daddr", forward.HostAddress, string(forward.Protocol), "dport", hostPort, "snat", "ip", "to", region.Uplink.RegionAddress),
				command(tools.IP, "netns", "exec", region.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "iifname", region.Bridge, "oifname", region.Uplink.RegionDevice, "ip", "saddr", region.CIDR, "ip", "daddr", forward.HostAddress, string(forward.Protocol), "dport", hostPort, "accept"),
			)
		}
	}

	// Link pairs follow canonical launch order then declared admission order;
	// all namespaces exist before pair setup.
	for i := range resolved {
		for j := i + 1; j < len(resolved); j++ {
			a, b := resolved[i], resolved[j]
			va := linkDevice(prefix, runID, a.Code, b.Code)
			vb := linkDevice(prefix, runID, b.Code, a.Code)
			if err := validIdentifier(va, "veth", 15); err != nil {
				return NetworkPlan{}, err
			}
			if err := validIdentifier(vb, "veth", 15); err != nil {
				return NetworkPlan{}, err
			}
			left, right := allocationIndex(codes, a.Code), allocationIndex(codes, b.Code)
			if left > right {
				left, right = right, left
			}
			// Triangular slot numbering preserves existing links when Regions append.
			linkIndex := right*(right-1)/2 + left
			ipA, ipB, err := transitIP(linkIndex, 0)
			if err != nil {
				return NetworkPlan{}, err
			}
			commands = append(commands,
				// Creating the pair from inside a's namespace and placing the peer
				// directly in b means a controller crash can never strand a root-
				// namespace veth outside the run-scoped namespace cleanup.
				command(tools.IP, "-n", a.Namespace, "link", "add", va, "type", "veth", "peer", "name", vb, "netns", b.Namespace),
				command(tools.IP, "-n", a.Namespace, "addr", "add", ipA.String()+"/30", "dev", va),
				command(tools.IP, "-n", b.Namespace, "addr", "add", ipB.String()+"/30", "dev", vb),
				command(tools.IP, "-n", a.Namespace, "link", "set", va, "up"),
				command(tools.IP, "-n", b.Namespace, "link", "set", vb, "up"),
				command(tools.IP, "-n", a.Namespace, "route", "add", b.CIDR, "via", ipB.String(), "dev", va),
				command(tools.IP, "-n", b.Namespace, "route", "add", a.CIDR, "via", ipA.String(), "dev", vb),
				command(tools.IP, "netns", "exec", a.Namespace, tools.TC, "qdisc", "replace", "dev", va, "root", "netem"),
				command(tools.IP, "netns", "exec", b.Namespace, tools.TC, "qdisc", "replace", "dev", vb, "root", "netem"),
				command(tools.IP, "netns", "exec", a.Namespace, tools.NFT, "add", "chain", "inet", table, faultChain(a.Code, b.Code)),
				command(tools.IP, "netns", "exec", b.Namespace, tools.NFT, "add", "chain", "inet", table, faultChain(b.Code, a.Code)),
				// Insert fault dispatch ahead of the established-connection rule so a
				// live partition also cuts connections that conntrack already knows.
				command(tools.IP, "netns", "exec", a.Namespace, tools.NFT, "insert", "rule", "inet", table, "forward", "iifname", a.Bridge, "oifname", va, "jump", faultChain(a.Code, b.Code)),
				command(tools.IP, "netns", "exec", b.Namespace, tools.NFT, "insert", "rule", "inet", table, "forward", "iifname", b.Bridge, "oifname", vb, "jump", faultChain(b.Code, a.Code)),
				command(tools.IP, "netns", "exec", a.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "iifname", a.Bridge, "oifname", va, "accept"),
				command(tools.IP, "netns", "exec", a.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "iifname", va, "oifname", a.Bridge, "accept"),
				command(tools.IP, "netns", "exec", b.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "iifname", b.Bridge, "oifname", vb, "accept"),
				command(tools.IP, "netns", "exec", b.Namespace, tools.NFT, "add", "rule", "inet", table, "forward", "iifname", vb, "oifname", b.Bridge, "accept"),
			)
		}
	}

	// Faults are sorted by source/target and emitted last. This means a plan
	// can be diffed and replayed without depending on map or declaration order.
	faults := append([]FaultSpec(nil), config.Faults...)
	sort.Slice(faults, func(i, j int) bool {
		if faults[i].From != faults[j].From {
			return regionIndex(faults[i].From) < regionIndex(faults[j].From)
		}
		return regionIndex(faults[i].To) < regionIndex(faults[j].To)
	})
	seenFaults := make(map[string]bool, len(faults))
	for _, fault := range faults {
		if err := validateFault(fault, true); err != nil {
			return NetworkPlan{}, err
		}
		if !seenRegions[fault.From] || !seenRegions[fault.To] {
			return NetworkPlan{}, fmt.Errorf("vmnet: fault link references undeclared Region")
		}
		faultKey := string(fault.From) + "\x00" + string(fault.To)
		if seenFaults[faultKey] {
			return NetworkPlan{}, fmt.Errorf("vmnet: duplicate fault link %s -> %s", fault.From, fault.To)
		}
		seenFaults[faultKey] = true
		from := resolved[0]
		for _, region := range resolved {
			if region.Code == fault.From {
				from = region
				break
			}
		}
		to := resolved[0]
		for _, region := range resolved {
			if region.Code == fault.To {
				to = region
				break
			}
		}
		veth := linkDevice(prefix, runID, from.Code, to.Code)
		if fault.Partition {
			commands = append(commands,
				command(tools.IP, "netns", "exec", from.Namespace, tools.NFT, "flush", "chain", "inet", table, faultChain(from.Code, to.Code)),
				command(tools.IP, "netns", "exec", to.Namespace, tools.NFT, "flush", "chain", "inet", table, faultChain(to.Code, from.Code)),
				command(tools.IP, "netns", "exec", from.Namespace, tools.NFT, "add", "rule", "inet", table, faultChain(from.Code, to.Code), "drop"),
				command(tools.IP, "netns", "exec", to.Namespace, tools.NFT, "add", "rule", "inet", table, faultChain(to.Code, from.Code), "drop"),
			)
		}
		if fault.Latency != 0 || fault.Jitter != 0 || fault.LossPercent != 0 || fault.ReorderPercent != 0 || fault.DuplicatePercent != 0 || fault.BandwidthKbit != 0 {
			args := []string{"netns", "exec", from.Namespace, tools.TC, "qdisc", "replace", "dev", veth, "root", "netem"}
			if fault.Latency != 0 || fault.Jitter != 0 {
				args = append(args, "delay", netemDuration(fault.Latency))
				if fault.Jitter != 0 {
					args = append(args, netemDuration(fault.Jitter))
				}
			}
			if fault.LossPercent != 0 {
				args = append(args, "loss", strconv.FormatFloat(fault.LossPercent, 'f', -1, 64)+"%")
			}
			if fault.ReorderPercent != 0 {
				args = append(args, "reorder", strconv.FormatFloat(fault.ReorderPercent, 'f', -1, 64)+"%")
			}
			if fault.DuplicatePercent != 0 {
				args = append(args, "duplicate", strconv.FormatFloat(fault.DuplicatePercent, 'f', -1, 64)+"%")
			}
			if fault.BandwidthKbit != 0 {
				args = append(args, "rate", strconv.FormatUint(fault.BandwidthKbit, 10)+"kbit")
			}
			commands = append(commands, command(tools.IP, args...))
		}
	}
	commands = append(commands, hostInputCommands(tools, prefix, runID, uplinks, forwards, false)...)
	if len(commands) > maxPlanCommands {
		return NetworkPlan{}, fmt.Errorf("vmnet: generated command count %d exceeds %d", len(commands), maxPlanCommands)
	}
	// Every bridge, TAP, nft chain, qdisc, route, and Region-side veth lives in a
	// run-scoped namespace. Root peers are separately journaled: open sockets
	// can retain a namespace and its links after its name has been deleted.
	for i := len(resolved) - 1; i >= 0; i-- {
		region := resolved[i]
		cleanup = append(cleanup, command(tools.IP, "netns", "del", region.Namespace))
	}
	fingerprintInput, _ := json.Marshal(struct {
		RunID            string
		CoordinationRoot string
		Tools            ToolPaths
		Regions          []RegionNetwork
		Uplinks          []RegionUplink
		Forwards         []EndpointForward
		Listeners        []EndpointListener
		DNSRecords       []DNSRecord
		Commands         []Command
	}{runID, coordinationRoot, tools, resolved, uplinks, forwards, listeners, dnsRecords, commands})
	hash := sha256.Sum256(fingerprintInput)
	fingerprint := hex.EncodeToString(hash[:])
	cleanupRegions := make([]RegionCode, 0, len(resolved))
	for _, region := range resolved {
		cleanupRegions = append(cleanupRegions, region.Code)
	}
	cleanupPlan := CleanupPlan{
		Version: networkPlanVersion, Prefix: prefix, RunID: runID, CoordinationRoot: coordinationRoot, Tools: tools, Fingerprint: fingerprint,
		Regions: cleanupRegions, Uplinks: append([]RegionUplink(nil), uplinks...),
		Forwards: copyForwards(forwards), Listeners: append([]EndpointListener(nil), listeners...),
		DNSRecords: append([]DNSRecord(nil), dnsRecords...), Commands: cleanup,
		HostInput: hostInputCommands(tools, prefix, runID, uplinks, forwards, true),
	}
	for _, uplink := range uplinks {
		cleanupPlan.RootLinks = append(cleanupPlan.RootLinks, rootLinkCleanup(tools, prefix, runID, uplink))
	}
	journal := Journal{Version: networkPlanVersion, Prefix: prefix, RunID: runID, CoordinationRoot: coordinationRoot, Tools: tools, Fingerprint: fingerprint, Cleanup: cleanupPlan.copy()}
	plan := NetworkPlan{
		Version: networkPlanVersion, Prefix: prefix, RunID: runID, CoordinationRoot: coordinationRoot, Tools: tools, Fingerprint: fingerprint,
		Regions: resolved, Uplinks: append([]RegionUplink(nil), uplinks...),
		Faults: append([]FaultSpec(nil), faults...), Forwards: copyForwards(forwards),
		Listeners: append([]EndpointListener(nil), listeners...), DNSRecords: append([]DNSRecord(nil), dnsRecords...),
		Commands: commands, Cleanup: cleanupPlan, Journal: journal,
	}
	return plan, nil
}
