package vmnet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FaultController changes one already-applied NetworkPlan. It owns only the
// dedicated per-link nft chains and root qdiscs created by that plan.
type FaultController struct {
	mu      sync.Mutex
	plan    NetworkPlan
	runner  Runner
	netem   map[string]bool
	regions map[RegionCode]RegionNetwork
}

// NewFaultController validates that plan has the owned links required for
// deterministic live network faults. It does not mutate host networking.
func NewFaultController(plan NetworkPlan, runner Runner) (*FaultController, error) {
	if runner == nil {
		return nil, errors.New("vmnet: fault runner is required")
	}
	if plan.Version != 1 || plan.Prefix == "" || plan.Fingerprint == "" || len(plan.Regions) < 2 {
		return nil, errors.New("vmnet: an applied multi-Region plan is required")
	}
	regions := make(map[RegionCode]RegionNetwork, len(plan.Regions))
	for _, region := range plan.Regions {
		if !validRegion(region.Code) || region.Namespace == "" || region.Bridge == "" {
			return nil, errors.New("vmnet: fault plan contains an invalid Region")
		}
		regions[region.Code] = region
	}
	netem := make(map[string]bool)
	for _, fault := range plan.Faults {
		if fault.Latency != 0 || fault.Jitter != 0 || fault.LossPercent != 0 || fault.BandwidthKbit != 0 {
			netem[string(fault.From)+"\x00"+string(fault.To)] = true
		}
	}
	return &FaultController{plan: plan, runner: runner, netem: netem, regions: regions}, nil
}

// Partition drops forwarded guest traffic in both directions between a pair
// of Regions. Repeating it converges the same dedicated chains.
func (c *FaultController) Partition(ctx context.Context, a, b RegionCode) error {
	if c == nil {
		return errors.New("vmnet: nil fault controller")
	}
	if ctx == nil {
		return errors.New("vmnet: nil partition context")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	commands, err := c.partitionCommands(a, b, true)
	if err != nil {
		return err
	}
	if err := runCommands(ctx, c.runner, commands); err != nil {
		rollback, _ := c.partitionCommands(a, b, false)
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = runCommands(rollbackContext, c.runner, rollback)
		cancel()
		return fmt.Errorf("vmnet: partition %s/%s: %w", a, b, err)
	}
	return nil
}

// Heal removes the bidirectional drop rules for a Region pair. Flushing an
// already-empty owned chain is safe and keeps this operation idempotent.
func (c *FaultController) Heal(ctx context.Context, a, b RegionCode) error {
	if c == nil {
		return errors.New("vmnet: nil fault controller")
	}
	if ctx == nil {
		return errors.New("vmnet: nil heal context")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	commands, err := c.partitionCommands(a, b, false)
	if err != nil {
		return err
	}
	if err := runCommands(ctx, c.runner, commands); err != nil {
		return fmt.Errorf("vmnet: heal %s/%s: %w", a, b, err)
	}
	return nil
}

// SetNetem replaces the directional root qdisc for From to To.
func (c *FaultController) SetNetem(ctx context.Context, fault FaultSpec) error {
	if c == nil {
		return errors.New("vmnet: nil fault controller")
	}
	if ctx == nil {
		return errors.New("vmnet: nil netem context")
	}
	if fault.Partition {
		return errors.New("vmnet: use Partition for bidirectional link cuts")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	command, key, err := c.netemCommand(fault)
	if err != nil {
		return err
	}
	if err := c.runner.Run(ctx, command.Executable, append([]string(nil), command.Args...)); err != nil {
		return fmt.Errorf("vmnet: set netem %s: %w", key, err)
	}
	c.netem[key] = true
	return nil
}

// ClearNetem deletes the directional root qdisc. Repeating it is a no-op in
// one controller lifetime, which avoids turning an absent qdisc into failure.
func (c *FaultController) ClearNetem(ctx context.Context, from, to RegionCode) error {
	if c == nil {
		return errors.New("vmnet: nil fault controller")
	}
	if ctx == nil {
		return errors.New("vmnet: nil netem context")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fromRegion, _, veth, err := c.link(from, to)
	if err != nil {
		return err
	}
	key := string(from) + "\x00" + string(to)
	if !c.netem[key] {
		return nil
	}
	cmd := command("ip", "netns", "exec", fromRegion.Namespace, "tc", "qdisc", "del", "dev", veth, "root")
	if err := c.runner.Run(ctx, cmd.Executable, append([]string(nil), cmd.Args...)); err != nil {
		return fmt.Errorf("vmnet: clear netem %s/%s: %w", from, to, err)
	}
	delete(c.netem, key)
	return nil
}

func (c *FaultController) partitionCommands(a, b RegionCode, blocked bool) ([]Command, error) {
	aRegion, bRegion, _, err := c.link(a, b)
	if err != nil {
		return nil, err
	}
	commands := []Command{
		command("ip", "netns", "exec", aRegion.Namespace, "nft", "flush", "chain", "inet", c.plan.Prefix+"_vmnet", faultChain(c.plan.Prefix, a, b)),
		command("ip", "netns", "exec", bRegion.Namespace, "nft", "flush", "chain", "inet", c.plan.Prefix+"_vmnet", faultChain(c.plan.Prefix, b, a)),
	}
	if blocked {
		commands = append(commands,
			command("ip", "netns", "exec", aRegion.Namespace, "nft", "add", "rule", "inet", c.plan.Prefix+"_vmnet", faultChain(c.plan.Prefix, a, b), "drop"),
			command("ip", "netns", "exec", bRegion.Namespace, "nft", "add", "rule", "inet", c.plan.Prefix+"_vmnet", faultChain(c.plan.Prefix, b, a), "drop"),
		)
	}
	return commands, nil
}

func (c *FaultController) netemCommand(fault FaultSpec) (Command, string, error) {
	from, _, veth, err := c.link(fault.From, fault.To)
	if err != nil {
		return Command{}, "", err
	}
	if fault.Latency < 0 || fault.Jitter < 0 || math.IsNaN(fault.LossPercent) || math.IsInf(fault.LossPercent, 0) || fault.LossPercent < 0 || fault.LossPercent > 100 || (fault.BandwidthKbit == 0 && fault.Latency == 0 && fault.Jitter == 0 && fault.LossPercent == 0) {
		return Command{}, "", fmt.Errorf("vmnet: invalid netem values for %s -> %s", fault.From, fault.To)
	}
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
	return command("ip", args...), string(fault.From) + "\x00" + string(fault.To), nil
}

func (c *FaultController) link(from, to RegionCode) (RegionNetwork, RegionNetwork, string, error) {
	if c == nil {
		return RegionNetwork{}, RegionNetwork{}, "", errors.New("vmnet: nil fault controller")
	}
	if from == to || !validRegion(from) || !validRegion(to) {
		return RegionNetwork{}, RegionNetwork{}, "", fmt.Errorf("vmnet: invalid fault link %s -> %s", from, to)
	}
	fromRegion, fromOK := c.regions[from]
	toRegion, toOK := c.regions[to]
	if !fromOK || !toOK {
		return RegionNetwork{}, RegionNetwork{}, "", errors.New("vmnet: fault link references undeclared Region")
	}
	veth := fmt.Sprintf("%s-v-%s-%s", c.plan.Prefix, strings.ToLower(string(from)), strings.ToLower(string(to)))
	return fromRegion, toRegion, veth, nil
}

func runCommands(ctx context.Context, runner Runner, commands []Command) error {
	for index, command := range commands {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runner.Run(ctx, command.Executable, append([]string(nil), command.Args...)); err != nil {
			return fmt.Errorf("command %d: %w", index, err)
		}
	}
	return nil
}
