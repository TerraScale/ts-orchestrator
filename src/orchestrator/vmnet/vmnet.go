// Package vmnet contains the test-only host-network plan used by the
// Firecracker qualification estate.  It deliberately has no production
// networking implementation: callers provide a Runner and can therefore use
// a fake without changing the host running the tests.
package vmnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	From          RegionCode    `json:"from"`
	To            RegionCode    `json:"to"`
	Latency       time.Duration `json:"latency,omitempty"`
	Jitter        time.Duration `json:"jitter,omitempty"`
	LossPercent   float64       `json:"loss_percent,omitempty"`
	BandwidthKbit uint64        `json:"bandwidth_kbit,omitempty"`
	Partition     bool          `json:"partition,omitempty"`
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

// CleanupPlan is safe to replay. Missing resources are expected during
// rollback and are ignored by Run, making cleanup idempotent after a crash.
type CleanupPlan struct {
	Version     int       `json:"version"`
	Fingerprint string    `json:"fingerprint"`
	Commands    []Command `json:"commands"`
}

func (p CleanupPlan) copy() CleanupPlan {
	p.Commands = append([]Command(nil), p.Commands...)
	for i := range p.Commands {
		p.Commands[i] = p.Commands[i].copy()
	}
	return p
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
	// Cleanup is a safety operation. It must still run when the controller's
	// request was cancelled or its deadline expired.
	ctx = context.WithoutCancel(ctx)
	var first error
	for _, c := range p.Commands {
		var err error
		if cleanupRunner, ok := runner.(CleanupRunner); ok {
			err = cleanupRunner.RunCleanup(ctx, c.Executable, append([]string(nil), c.Args...))
		} else {
			err = runner.Run(ctx, c.Executable, append([]string(nil), c.Args...))
		}
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
	Fingerprint string          `json:"fingerprint"`
	Regions     []RegionNetwork `json:"regions"`
	Faults      []FaultSpec     `json:"faults,omitempty"`
	Commands    []Command       `json:"commands"`
	Cleanup     CleanupPlan     `json:"cleanup"`
	Journal     Journal         `json:"journal"`
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
	if ctx == nil {
		return errors.New("vmnet: nil context")
	}
	if err := writer.WriteJournal(ctx, p.Journal); err != nil {
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

var identifierPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

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
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 24 || prefix.Bits() > 30 || prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("vmnet: %s must be a canonical IPv4 CIDR (/24-/30)", field)
	}
	return prefix, nil
}

func broadcast(prefix netip.Prefix) netip.Addr {
	address := prefix.Addr()
	for bit := prefix.Bits(); bit < 32; bit++ {
		address = address.Next()
	}
	return address
}

func netemDuration(duration time.Duration) string {
	if duration%time.Millisecond == 0 {
		return strconv.FormatInt(int64(duration/time.Millisecond), 10) + "ms"
	}
	return duration.String()
}

func regionNetworkName(prefix string, code RegionCode, kind string) string {
	return prefix + "-" + kind + "-" + strings.ToLower(string(code))
}

func faultChain(prefix string, from, to RegionCode) string {
	return prefix + "_" + strings.ToLower(string(from)) + "_" + strings.ToLower(string(to))
}

func transitIP(index int, side int) (netip.Addr, netip.Addr, error) {
	// 169.254.240.0/24 is reserved solely for the three deterministic
	// cross-Region /30 links.
	base := 240 + index*4
	if base > 252 {
		return netip.Addr{}, netip.Addr{}, errors.New("vmnet: too many Region links")
	}
	a := netip.AddrFrom4([4]byte{169, 254, byte(base), 1})
	b := netip.AddrFrom4([4]byte{169, 254, byte(base), 2})
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
				tap = fmt.Sprintf("%s-t-%s-%02d", prefix, strings.ToLower(string(spec.Code)), guestIndex+1)
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
				// The first guest is .10; each subsequent guest increments it.
				base := uint32(prefixCIDR.Addr().As4()[3]) + uint32(10+guestIndex)
				address = netip.AddrFrom4([4]byte{prefixCIDR.Addr().As4()[0], prefixCIDR.Addr().As4()[1], prefixCIDR.Addr().As4()[2], byte(base)}).String()
			}
			guestAddress, err := netip.ParseAddr(address)
			gateway := netip.AddrFrom4([4]byte{prefixCIDR.Addr().As4()[0], prefixCIDR.Addr().As4()[1], prefixCIDR.Addr().As4()[2], 1})
			if err != nil || !guestAddress.Is4() || !prefixCIDR.Contains(guestAddress) || guestAddress == prefixCIDR.Addr() || guestAddress == gateway || guestAddress == broadcast(prefixCIDR) || seenAddresses[guestAddress] {
				return NetworkPlan{}, fmt.Errorf("vmnet: guest %s address %q is outside %s", guest.ID, address, prefixCIDR)
			}
			seenAddresses[guestAddress] = true
			mac, _ := StableGuestMAC(spec.Code, guestIndex+1)
			resolvedGuests = append(resolvedGuests, GuestNetwork{ID: guest.ID, TAP: tap, Address: guestAddress.String(), MAC: mac})
		}
		gateway := netip.AddrFrom4([4]byte{prefixCIDR.Addr().As4()[0], prefixCIDR.Addr().As4()[1], prefixCIDR.Addr().As4()[2], 1}).String()
		namespace := regionNetworkName(prefix, spec.Code, "n")
		resolved = append(resolved, RegionNetwork{Code: spec.Code, CIDR: prefixCIDR.String(), Namespace: namespace, NamespacePath: "/run/netns/" + namespace, Bridge: regionNetworkName(prefix, spec.Code, "b"), Gateway: gateway, Guests: resolvedGuests})
	}

	commands := make([]Command, 0)
	cleanup := make([]Command, 0)
	for _, region := range resolved {
		commands = append(commands,
			command("ip", "netns", "add", region.Namespace),
			command("ip", "-n", region.Namespace, "link", "set", "lo", "up"),
			command("ip", "-n", region.Namespace, "link", "add", region.Bridge, "type", "bridge"),
			command("ip", "-n", region.Namespace, "link", "set", region.Bridge, "up"),
			command("ip", "-n", region.Namespace, "addr", "add", region.Gateway+"/"+strconv.Itoa(netip.MustParsePrefix(region.CIDR).Bits()), "dev", region.Bridge),
			command("ip", "-n", region.Namespace, "link", "set", "dev", region.Bridge, "mtu", "1500"),
			command("ip", "netns", "exec", region.Namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"),
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
				command("ip", tuntap...),
				command("ip", "-n", region.Namespace, "link", "set", guest.TAP, "master", region.Bridge),
				command("ip", "-n", region.Namespace, "link", "set", guest.TAP, "up"),
			)
		}
		commands = append(commands,
			command("ip", "netns", "exec", region.Namespace, "nft", "add", "table", "inet", prefix+"_vmnet"),
			command("ip", "netns", "exec", region.Namespace, "nft", "add", "chain", "inet", prefix+"_vmnet", "forward", "{ type filter hook forward priority 0; policy drop; }"),
			command("ip", "netns", "exec", region.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "ct", "state", "established,related", "accept"),
			command("ip", "netns", "exec", region.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "iifname", region.Bridge, "oifname", region.Bridge, "accept"),
		)
	}

	// Link pairs are sorted by Region code and are created after all namespace
	// setup, so command order is independent of declaration order.
	linkIndex := 0
	for i := range resolved {
		for j := i + 1; j < len(resolved); j++ {
			a, b := resolved[i], resolved[j]
			va := fmt.Sprintf("%s-v-%s-%s", prefix, strings.ToLower(string(a.Code)), strings.ToLower(string(b.Code)))
			vb := fmt.Sprintf("%s-v-%s-%s", prefix, strings.ToLower(string(b.Code)), strings.ToLower(string(a.Code)))
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
				command("ip", "link", "add", va, "type", "veth", "peer", "name", vb),
				command("ip", "link", "set", va, "netns", a.Namespace),
				command("ip", "link", "set", vb, "netns", b.Namespace),
				command("ip", "-n", a.Namespace, "addr", "add", ipA.String()+"/30", "dev", va),
				command("ip", "-n", b.Namespace, "addr", "add", ipB.String()+"/30", "dev", vb),
				command("ip", "-n", a.Namespace, "route", "add", b.CIDR, "via", ipB.String(), "dev", va),
				command("ip", "-n", b.Namespace, "route", "add", a.CIDR, "via", ipA.String(), "dev", vb),
				command("ip", "-n", a.Namespace, "link", "set", va, "up"),
				command("ip", "-n", b.Namespace, "link", "set", vb, "up"),
				command("ip", "netns", "exec", a.Namespace, "nft", "add", "chain", "inet", prefix+"_vmnet", faultChain(prefix, a.Code, b.Code)),
				command("ip", "netns", "exec", b.Namespace, "nft", "add", "chain", "inet", prefix+"_vmnet", faultChain(prefix, b.Code, a.Code)),
				command("ip", "netns", "exec", a.Namespace, "nft", "insert", "rule", "inet", prefix+"_vmnet", "forward", "iifname", a.Bridge, "oifname", va, "jump", faultChain(prefix, a.Code, b.Code)),
				command("ip", "netns", "exec", b.Namespace, "nft", "insert", "rule", "inet", prefix+"_vmnet", "forward", "iifname", b.Bridge, "oifname", vb, "jump", faultChain(prefix, b.Code, a.Code)),
				command("ip", "netns", "exec", a.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "iifname", a.Bridge, "oifname", va, "accept"),
				command("ip", "netns", "exec", a.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "iifname", va, "oifname", a.Bridge, "accept"),
				command("ip", "netns", "exec", b.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "iifname", b.Bridge, "oifname", vb, "accept"),
				command("ip", "netns", "exec", b.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", "forward", "iifname", vb, "oifname", b.Bridge, "accept"),
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
		if !validRegion(fault.From) || !validRegion(fault.To) || fault.From == fault.To {
			return NetworkPlan{}, fmt.Errorf("vmnet: invalid fault link %s -> %s", fault.From, fault.To)
		}
		if !seenRegions[fault.From] || !seenRegions[fault.To] {
			return NetworkPlan{}, fmt.Errorf("vmnet: fault link references undeclared Region")
		}
		faultKey := string(fault.From) + "\x00" + string(fault.To)
		if seenFaults[faultKey] {
			return NetworkPlan{}, fmt.Errorf("vmnet: duplicate fault link %s -> %s", fault.From, fault.To)
		}
		seenFaults[faultKey] = true
		if fault.Latency < 0 || fault.Jitter < 0 || math.IsNaN(fault.LossPercent) || math.IsInf(fault.LossPercent, 0) || fault.LossPercent < 0 || fault.LossPercent > 100 || (fault.BandwidthKbit == 0 && !fault.Partition && fault.Latency == 0 && fault.Jitter == 0 && fault.LossPercent == 0) {
			return NetworkPlan{}, fmt.Errorf("vmnet: invalid fault values for %s -> %s", fault.From, fault.To)
		}
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
		veth := fmt.Sprintf("%s-v-%s-%s", prefix, strings.ToLower(string(from.Code)), strings.ToLower(string(to.Code)))
		if fault.Partition {
			commands = append(commands,
				command("ip", "netns", "exec", from.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", faultChain(prefix, from.Code, to.Code), "drop"),
				command("ip", "netns", "exec", to.Namespace, "nft", "add", "rule", "inet", prefix+"_vmnet", faultChain(prefix, to.Code, from.Code), "drop"),
			)
		}
		if fault.Latency != 0 || fault.Jitter != 0 || fault.LossPercent != 0 || fault.BandwidthKbit != 0 {
			args := []string{"netns", "exec", from.Namespace, "tc", "qdisc", "replace", "dev", veth, "root", "netem"}
			if fault.Latency != 0 || fault.Jitter != 0 {
				args = append(args, "delay", netemDuration(fault.Latency))
				if fault.Jitter != 0 {
					args = append(args, netemDuration(fault.Jitter))
				}
			}
			if fault.LossPercent != 0 {
				args = append(args, "loss", strconv.FormatFloat(fault.LossPercent, 'f', -1, 64)+"%")
			}
			if fault.BandwidthKbit != 0 {
				args = append(args, "rate", strconv.FormatUint(fault.BandwidthKbit, 10)+"kbit")
			}
			commands = append(commands, command("ip", args...))
		}
	}

	// Build inverse operations in reverse creation order. Rollback ignores
	// missing-resource failures, so this is safe after partial setup or crash.
	for i := len(resolved) - 1; i >= 0; i-- {
		for j := i - 1; j >= 0; j-- {
			a, b := resolved[j], resolved[i]
			va := fmt.Sprintf("%s-v-%s-%s", prefix, strings.ToLower(string(a.Code)), strings.ToLower(string(b.Code)))
			cleanup = append(cleanup, command("ip", "-n", a.Namespace, "link", "del", va))
		}
	}
	for i := len(resolved) - 1; i >= 0; i-- {
		region := resolved[i]
		cleanup = append(cleanup,
			command("ip", "netns", "exec", region.Namespace, "nft", "delete", "table", "inet", prefix+"_vmnet"),
			command("ip", "netns", "del", region.Namespace),
		)
	}
	fingerprintInput, _ := json.Marshal(struct {
		Regions  []RegionNetwork
		Commands []Command
	}{resolved, commands})
	hash := sha256.Sum256(fingerprintInput)
	fingerprint := hex.EncodeToString(hash[:])
	cleanupPlan := CleanupPlan{Version: 1, Fingerprint: fingerprint, Commands: cleanup}
	journal := Journal{Version: 1, Fingerprint: fingerprint, Cleanup: cleanupPlan.copy()}
	return NetworkPlan{Version: 1, Prefix: prefix, Fingerprint: fingerprint, Regions: resolved, Faults: append([]FaultSpec(nil), faults...), Commands: commands, Cleanup: cleanupPlan, Journal: journal}, nil
}
