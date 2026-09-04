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

// RegionCode is one of the launch Regions. The closed set is intentional:
// changing an address allocation must be an explicit qualification decision.
type RegionCode string

const (
	GRU RegionCode = "GRU"
	SFO RegionCode = "SFO"
	FRA RegionCode = "FRA"
)

var launchRegions = []RegionCode{GRU, SFO, FRA}

var transitPrefix = netip.MustParsePrefix("10.78.255.0/24")

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
	if !validRegion(region) || ordinal < 1 || ordinal > 32 {
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
	if index < 0 || ordinal < 1 || ordinal > 32 {
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
type RegionSpec struct {
	Code   RegionCode  `json:"code"`
	CIDR   string      `json:"cidr"`
	Guests []GuestSpec `json:"guests"`
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
	TAPUID  uint32       `json:"tap_uid,omitempty"`
	TAPGID  uint32       `json:"tap_gid,omitempty"`
	// RunID is a 128-bit lowercase hexadecimal ownership identity. Empty uses
	// one cryptographically random identity shared by this controller process.
	RunID string `json:"run_id,omitempty"`
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
	Guests        []GuestNetwork `json:"guests"`
}

// GuestNetwork is a resolved guest declaration.
type GuestNetwork struct {
	ID      string `json:"id"`
	TAP     string `json:"tap"`
	Address string `json:"address"`
	MAC     string `json:"mac"`
}

// CleanupPlan is safe to replay. A CleanupRunner normalizes only an explicitly
// absent owned namespace, making privileged cleanup idempotent after a crash.
type CleanupPlan struct {
	Version     int          `json:"version"`
	Prefix      string       `json:"prefix"`
	RunID       string       `json:"run_id"`
	Tools       ToolPaths    `json:"tools"`
	Fingerprint string       `json:"fingerprint"`
	Regions     []RegionCode `json:"regions"`
	Commands    []Command    `json:"commands"`
}

func (p CleanupPlan) copy() CleanupPlan {
	p.Regions = append([]RegionCode(nil), p.Regions...)
	p.Commands = append([]Command(nil), p.Commands...)
	for i := range p.Commands {
		p.Commands[i] = p.Commands[i].copy()
	}
	return p
}

// Validate proves that every cleanup target belongs to exactly this run. The
// plan deliberately admits namespace deletion only; all subordinate network
// resources are created inside those namespaces.
func (p CleanupPlan) Validate() error {
	if p.Version != 2 || validIdentifier(p.Prefix, "prefix", 5) != nil || !runIDPattern.MatchString(p.RunID) || !validSHA256Hex(p.Fingerprint) {
		return errors.New("vmnet: invalid cleanup plan metadata")
	}
	// Namespace deletion uses only ip. The other paths remain bound into the
	// journal but their binaries need not survive until crash recovery.
	if err := p.Tools.validatePaths(); err != nil {
		return err
	}
	if err := validateHostTool("ip", p.Tools.IP); err != nil {
		return err
	}
	if len(p.Regions) == 0 || len(p.Regions) > len(launchRegions) || len(p.Commands) != len(p.Regions) {
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
		if regionIndex(p.Regions[index-1]) >= regionIndex(p.Regions[index]) {
			return errors.New("vmnet: cleanup Regions are not canonical")
		}
	}
	return nil
}

// Validate checks the complete crash-recovery record before any privileged
// cleanup command executes.
func (j Journal) Validate() error {
	if j.Version != 2 || j.Prefix == "" || j.RunID == "" || j.Fingerprint == "" {
		return errors.New("vmnet: invalid network journal metadata")
	}
	if j.Prefix != j.Cleanup.Prefix || j.RunID != j.Cleanup.RunID || j.Tools != j.Cleanup.Tools || j.Fingerprint != j.Cleanup.Fingerprint {
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
	// Cleanup is a safety operation. It must still run when the controller's
	// request was cancelled, but no individual host command may hang forever.
	baseContext := context.WithoutCancel(ctx)
	cleanupContext, cleanupCancel := context.WithTimeout(baseContext, 45*time.Second)
	defer cleanupCancel()
	var first error
	for _, c := range p.Commands {
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
	return first
}

// Journal is the crash-recovery record. The caller should persist this value
// before calling Apply. It contains only provider-owned identifiers and the
// exact cleanup argv, never credentials.
type Journal struct {
	Version     int         `json:"version"`
	Prefix      string      `json:"prefix"`
	RunID       string      `json:"run_id"`
	Tools       ToolPaths   `json:"tools"`
	Fingerprint string      `json:"fingerprint"`
	Cleanup     CleanupPlan `json:"cleanup"`
}

// JournalWriter persists the cleanup record in the controller's durable
// journal. It is called before the first host mutation by ApplyWithJournal.
type JournalWriter interface {
	WriteJournal(context.Context, Journal) error
}

// NetworkPlan is a deterministic setup and cleanup plan.
type NetworkPlan struct {
	Version     int             `json:"version"`
	Prefix      string          `json:"prefix"`
	RunID       string          `json:"run_id"`
	Tools       ToolPaths       `json:"tools"`
	Fingerprint string          `json:"fingerprint"`
	Regions     []RegionNetwork `json:"regions"`
	Faults      []FaultSpec     `json:"faults,omitempty"`
	Commands    []Command       `json:"commands"`
	Cleanup     CleanupPlan     `json:"cleanup"`
	Journal     Journal         `json:"journal"`
}

const (
	maxPlanCommands = 512
	maxPlanGuests   = 96
)

// Validate reconstructs the only canonical plan that could own these
// resources. Exported plan fields are intentionally serializable, so callers
// must not be able to turn a recovered or hand-edited value into arbitrary ip
// commands by recalculating only its fingerprint.
func (p NetworkPlan) Validate() error {
	if p.Version != 2 || validIdentifier(p.Prefix, "prefix", 5) != nil || !runIDPattern.MatchString(p.RunID) || !validSHA256Hex(p.Fingerprint) {
		return errors.New("vmnet: invalid network plan metadata")
	}
	if len(p.Regions) == 0 || len(p.Regions) > len(launchRegions) || len(p.Commands) == 0 || len(p.Commands) > maxPlanCommands {
		return errors.New("vmnet: network plan exceeds topology bounds")
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
		Prefix:  p.Prefix,
		RunID:   p.RunID,
		Tools:   p.Tools,
		Faults:  append([]FaultSpec(nil), p.Faults...),
		TAPUID:  uid,
		TAPGID:  gid,
		Regions: make([]RegionSpec, 0, len(p.Regions)),
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

func (p NetworkPlan) copy() NetworkPlan {
	p.Regions = append([]RegionNetwork(nil), p.Regions...)
	for i := range p.Regions {
		p.Regions[i].Guests = append([]GuestNetwork(nil), p.Regions[i].Guests...)
	}
	p.Faults = append([]FaultSpec(nil), p.Faults...)
	p.Commands = append([]Command(nil), p.Commands...)
	for i := range p.Commands {
		p.Commands[i] = p.Commands[i].copy()
	}
	p.Cleanup = p.Cleanup.copy()
	p.Journal = p.Journal.copy()
	return p
}

// CleanupPlan returns a defensive copy of the crash-safe cleanup record.
func (p NetworkPlan) CleanupPlan() CleanupPlan { return p.Cleanup.copy() }

// Apply executes setup in order. Any setup failure, including cancellation,
// triggers cleanup with context.WithoutCancel so a cancelled controller does
// not leave TAPs or namespaces behind.
func (p NetworkPlan) Apply(ctx context.Context, runner Runner) error {
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
	for i, c := range p.Commands {
		if err := ctx.Err(); err != nil {
			cleanupErr := p.Cleanup.Run(ctx, runner)
			return applyError(i, err, cleanupErr)
		}
		if err := runner.Run(ctx, c.Executable, append([]string(nil), c.Args...)); err != nil {
			cleanupErr := p.Cleanup.Run(ctx, runner)
			return applyError(i, err, cleanupErr)
		}
	}
	return nil
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
	if err := writer.WriteJournal(ctx, p.Journal.copy()); err != nil {
		return fmt.Errorf("vmnet: write cleanup journal: %w", err)
	}
	return p.Apply(ctx, runner)
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
	identifierPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	runIDPattern      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	runTokenPattern   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	defaultRunIDOnce  sync.Once
	defaultRunIDValue string
	defaultRunIDError error
)

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
	return -1
}

func validRegion(code RegionCode) bool { return regionIndex(code) >= 0 }

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
	return prefix + "b" + interfaceToken(runID) + strings.ToLower(string(code[:1]))
}

func networkTable(prefix, runID string) string {
	return prefix + "_" + runID + "_vmnet"
}

func faultChain(from, to RegionCode) string {
	return "fault_" + strings.ToLower(string(from)) + "_" + strings.ToLower(string(to))
}

func linkDevice(prefix, runID string, from, to RegionCode) string {
	return prefix + "v" + interfaceToken(runID) + strings.ToLower(string(from[:1])) + strings.ToLower(string(to[:1]))
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
	// 10.78.255.0/24 is reserved solely for deterministic cross-Region /30
	// links. Stable guest networks occupy 10.77.0.0/16.
	base := index * 4
	if base > 252 {
		return netip.Addr{}, netip.Addr{}, errors.New("vmnet: too many Region links")
	}
	a := netip.AddrFrom4([4]byte{10, 78, 255, byte(base + 1)})
	b := netip.AddrFrom4([4]byte{10, 78, 255, byte(base + 2)})
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
	if len(config.Regions) == 0 {
		return NetworkPlan{}, errors.New("vmnet: at least one Region is required")
	}
	regions := append([]RegionSpec(nil), config.Regions...)
	sort.Slice(regions, func(i, j int) bool { return regionIndex(regions[i].Code) < regionIndex(regions[j].Code) })
	resolved := make([]RegionNetwork, 0, len(regions))
	seenRegions := make(map[RegionCode]bool, len(regions))
	seenTAPs := make(map[string]bool)
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
			cidr = StableCIDR(spec.Code)
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
			if seenGuests[guest.ID] {
				return NetworkPlan{}, fmt.Errorf("vmnet: duplicate guest %q in %s", guest.ID, spec.Code)
			}
			seenGuests[guest.ID] = true
			tap := guest.TAP
			if tap == "" {
				tap = fmt.Sprintf("%st%s%s%02d", prefix, interfaceToken(runID), strings.ToLower(string(spec.Code[:1])), guestIndex+1)
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
			mac, _ := StableGuestMAC(spec.Code, guestIndex+1)
			resolvedGuests = append(resolvedGuests, GuestNetwork{ID: guest.ID, TAP: tap, Address: guestAddress.String(), MAC: mac})
		}
		namespace := regionNetworkName(prefix, runID, spec.Code)
		resolved = append(resolved, RegionNetwork{Code: spec.Code, CIDR: prefixCIDR.String(), Namespace: namespace, NamespacePath: "/run/netns/" + namespace, Bridge: regionBridgeName(prefix, runID, spec.Code), Gateway: gateway.String(), Guests: resolvedGuests})
	}

	commands := make([]Command, 0)
	cleanup := make([]Command, 0)
	table := networkTable(prefix, runID)
	for _, region := range resolved {
		commands = append(commands,
			command(tools.IP, "netns", "add", region.Namespace),
			command(tools.IP, "-n", region.Namespace, "link", "set", "lo", "up"),
			command(tools.IP, "-n", region.Namespace, "link", "add", region.Bridge, "type", "bridge"),
			command(tools.IP, "-n", region.Namespace, "link", "set", "dev", region.Bridge, "mtu", "1500"),
			command(tools.IP, "-n", region.Namespace, "link", "set", region.Bridge, "up"),
			command(tools.IP, "-n", region.Namespace, "addr", "add", region.Gateway+"/"+strconv.Itoa(netip.MustParsePrefix(region.CIDR).Bits()), "dev", region.Bridge),
			command(tools.IP, "netns", "exec", region.Namespace, tools.Sysctl, "-q", "-w", "net.ipv4.ip_forward=1"),
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
		)
	}

	// Link pairs are sorted by Region code and are created after all namespace
	// setup, so command order is independent of declaration order.
	linkIndex := 0
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
			linkIndex++
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

	// Every bridge, TAP, nft chain, qdisc, route, and veth lives inside one
	// run-scoped namespace. Deleting only those namespaces gives cleanup one
	// small, replay-safe ownership boundary and avoids partial inner teardown.
	for i := len(resolved) - 1; i >= 0; i-- {
		region := resolved[i]
		cleanup = append(cleanup, command(tools.IP, "netns", "del", region.Namespace))
	}
	fingerprintInput, _ := json.Marshal(struct {
		RunID    string
		Tools    ToolPaths
		Regions  []RegionNetwork
		Commands []Command
	}{runID, tools, resolved, commands})
	hash := sha256.Sum256(fingerprintInput)
	fingerprint := hex.EncodeToString(hash[:])
	cleanupRegions := make([]RegionCode, 0, len(resolved))
	for _, region := range resolved {
		cleanupRegions = append(cleanupRegions, region.Code)
	}
	cleanupPlan := CleanupPlan{Version: 2, Prefix: prefix, RunID: runID, Tools: tools, Fingerprint: fingerprint, Regions: cleanupRegions, Commands: cleanup}
	journal := Journal{Version: 2, Prefix: prefix, RunID: runID, Tools: tools, Fingerprint: fingerprint, Cleanup: cleanupPlan.copy()}
	return NetworkPlan{Version: 2, Prefix: prefix, RunID: runID, Tools: tools, Fingerprint: fingerprint, Regions: resolved, Faults: append([]FaultSpec(nil), faults...), Commands: commands, Cleanup: cleanupPlan, Journal: journal}, nil
}
