package vmnet

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// FaultController changes one already-applied NetworkPlan. It owns only the
// dedicated per-link nft chains and root qdiscs created by that plan.
type FaultController struct {
	plan    NetworkPlan
	runner  Runner
	regions map[RegionCode]RegionNetwork
}

// NewFaultController validates that plan has the owned links required for
// deterministic live network faults. It does not mutate host networking.
func NewFaultController(plan NetworkPlan, runner Runner) (*FaultController, error) {
	if runner == nil {
		return nil, errors.New("vmnet: fault runner is required")
	}
	plan = plan.copy()
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if len(plan.Regions) < 2 {
		return nil, errors.New("vmnet: an applied multi-Region plan is required")
	}
	if err := validateRunnerTools(runner, plan.Tools); err != nil {
		return nil, err
	}
	if err := validateRunnerCoordinationRoot(runner, plan.CoordinationRoot); err != nil {
		return nil, err
	}
	regions := make(map[RegionCode]RegionNetwork, len(plan.Regions))
	for _, region := range plan.Regions {
		if !validRegion(region.Code) || region.Namespace == "" || region.Bridge == "" {
			return nil, errors.New("vmnet: fault plan contains an invalid Region")
		}
		regions[region.Code] = region
	}
	return &FaultController{plan: plan, runner: runner, regions: regions}, nil
}

// Partition is a convenience wrapper for one operation against this plan.
func (p NetworkPlan) Partition(ctx context.Context, runner Runner, a, b RegionCode) error {
	controller, err := NewFaultController(p, runner)
	if err != nil {
		return err
	}
	return controller.Partition(ctx, a, b)
}

// Heal is a convenience wrapper for one operation against this plan.
func (p NetworkPlan) Heal(ctx context.Context, runner Runner, a, b RegionCode) error {
	controller, err := NewFaultController(p, runner)
	if err != nil {
		return err
	}
	return controller.Heal(ctx, a, b)
}

// SetNetem is a convenience wrapper for one directional impairment.
func (p NetworkPlan) SetNetem(ctx context.Context, runner Runner, fault FaultSpec) error {
	controller, err := NewFaultController(p, runner)
	if err != nil {
		return err
	}
	return controller.SetNetem(ctx, fault)
}

// ClearNetem is a convenience wrapper that restores the pre-created no-op
// netem qdisc, so it is idempotent across controller restarts.
func (p NetworkPlan) ClearNetem(ctx context.Context, runner Runner, from, to RegionCode) error {
	controller, err := NewFaultController(p, runner)
	if err != nil {
		return err
	}
	return controller.ClearNetem(ctx, from, to)
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
	if err := ctx.Err(); err != nil {
		return err
	}
	coordinator, unlock := lockRunCoordinator(c.plan.RunID)
	defer unlock()
	if err := coordinator.bind(c.plan.Fingerprint); err != nil {
		return err
	}
	if !coordinator.applied || coordinator.hostLease == nil {
		return errors.New("vmnet: fault operation requires a journaled applied network")
	}

	commands, err := c.partitionCommands(a, b, true)
	if err != nil {
		return err
	}
	if err := runCommands(ctx, c.runner, commands); err != nil {
		wasPartitioned := coordinator.partitions[regionPairKey(a, b)]
		rollback, _ := c.partitionCommands(a, b, wasPartitioned)
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		rollbackErr := runCommandsBestEffort(rollbackContext, c.runner, rollback)
		cancel()
		if rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("rollback heal (prior partition state): %w", rollbackErr))
		}
		return fmt.Errorf("vmnet: partition %s/%s: %w", a, b, err)
	}
	coordinator.partitions[regionPairKey(a, b)] = true
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
	if err := ctx.Err(); err != nil {
		return err
	}
	coordinator, unlock := lockRunCoordinator(c.plan.RunID)
	defer unlock()
	if err := coordinator.bind(c.plan.Fingerprint); err != nil {
		return err
	}
	if !coordinator.applied || coordinator.hostLease == nil {
		return errors.New("vmnet: fault operation requires a journaled applied network")
	}
	commands, err := c.partitionCommands(a, b, false)
	if err != nil {
		return err
	}
	wasPartitioned := coordinator.partitions[regionPairKey(a, b)]
	if err := runCommandsBestEffort(ctx, c.runner, commands); err != nil {
		rollback, _ := c.partitionCommands(a, b, wasPartitioned)
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		rollbackErr := runCommandsBestEffort(rollbackContext, c.runner, rollback)
		cancel()
		if rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("rollback prior partition state: %w", rollbackErr))
		}
		return fmt.Errorf("vmnet: heal %s/%s: %w", a, b, err)
	}
	coordinator.partitions[regionPairKey(a, b)] = false
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if fault.Partition {
		return errors.New("vmnet: use Partition for bidirectional link cuts")
	}
	coordinator, unlock := lockRunCoordinator(c.plan.RunID)
	defer unlock()
	if err := coordinator.bind(c.plan.Fingerprint); err != nil {
		return err
	}
	if !coordinator.applied || coordinator.hostLease == nil {
		return errors.New("vmnet: fault operation requires a journaled applied network")
	}
	command, _, err := c.netemCommand(fault)
	if err != nil {
		return err
	}
	if err := c.runner.Run(ctx, command.Executable, append([]string(nil), command.Args...)); err != nil {
		return fmt.Errorf("vmnet: set netem %s/%s: %w", fault.From, fault.To, err)
	}
	return nil
}

// ClearNetem restores the no-op qdisc created with the link. Repeating this
// operation remains safe after a controller restart.
func (c *FaultController) ClearNetem(ctx context.Context, from, to RegionCode) error {
	if c == nil {
		return errors.New("vmnet: nil fault controller")
	}
	if ctx == nil {
		return errors.New("vmnet: nil netem context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	coordinator, unlock := lockRunCoordinator(c.plan.RunID)
	defer unlock()
	if err := coordinator.bind(c.plan.Fingerprint); err != nil {
		return err
	}
	if !coordinator.applied || coordinator.hostLease == nil {
		return errors.New("vmnet: fault operation requires a journaled applied network")
	}
	fromRegion, _, veth, err := c.link(from, to)
	if err != nil {
		return err
	}
	cmd := command(c.plan.Tools.IP, "netns", "exec", fromRegion.Namespace, c.plan.Tools.TC, "qdisc", "replace", "dev", veth, "root", "netem")
	if err := c.runner.Run(ctx, cmd.Executable, append([]string(nil), cmd.Args...)); err != nil {
		return fmt.Errorf("vmnet: clear netem %s/%s: %w", from, to, err)
	}
	return nil
}

func (c *FaultController) partitionCommands(a, b RegionCode, blocked bool) ([]Command, error) {
	aRegion, bRegion, _, err := c.link(a, b)
	if err != nil {
		return nil, err
	}
	commands := []Command{
		command(c.plan.Tools.IP, "netns", "exec", aRegion.Namespace, c.plan.Tools.NFT, "flush", "chain", "inet", networkTable(c.plan.Prefix, c.plan.RunID), faultChain(a, b)),
		command(c.plan.Tools.IP, "netns", "exec", bRegion.Namespace, c.plan.Tools.NFT, "flush", "chain", "inet", networkTable(c.plan.Prefix, c.plan.RunID), faultChain(b, a)),
	}
	if blocked {
		commands = append(commands,
			command(c.plan.Tools.IP, "netns", "exec", aRegion.Namespace, c.plan.Tools.NFT, "add", "rule", "inet", networkTable(c.plan.Prefix, c.plan.RunID), faultChain(a, b), "drop"),
			command(c.plan.Tools.IP, "netns", "exec", bRegion.Namespace, c.plan.Tools.NFT, "add", "rule", "inet", networkTable(c.plan.Prefix, c.plan.RunID), faultChain(b, a), "drop"),
		)
	}
	return commands, nil
}

func (c *FaultController) netemCommand(fault FaultSpec) (Command, string, error) {
	from, _, veth, err := c.link(fault.From, fault.To)
	if err != nil {
		return Command{}, "", err
	}
	if err := validateFault(fault, false); err != nil {
		return Command{}, "", err
	}
	args := []string{"netns", "exec", from.Namespace, c.plan.Tools.TC, "qdisc", "replace", "dev", veth, "root", "netem"}
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
	return command(c.plan.Tools.IP, args...), string(fault.From) + "\x00" + string(fault.To), nil
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
	veth := linkDevice(c.plan.Prefix, c.plan.RunID, from, to)
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

func runCommandsBestEffort(ctx context.Context, runner Runner, commands []Command) error {
	errs := make([]error, 0, len(commands))
	for index, command := range commands {
		if err := runner.Run(ctx, command.Executable, append([]string(nil), command.Args...)); err != nil {
			errs = append(errs, fmt.Errorf("command %d: %w", index, err))
		}
	}
	return errors.Join(errs...)
}
