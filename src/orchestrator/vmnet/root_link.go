package vmnet

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// RootLinkCleanup binds a deletion command to the ownership MAC installed
// atomically when its veth pair is created. Namespace names can disappear
// while a socket still holds the namespace and its interfaces alive.
type RootLinkCleanup struct {
	Command Command `json:"command"`
	Address string  `json:"address"`
	Owner   string  `json:"owner"`
}

func rootLinkAddress(prefix, runID string, region RegionCode) string {
	digest := sha256.Sum256([]byte("vmnet-root-link\x00" + prefix + "\x00" + runID + "\x00" + string(region)))
	return net.HardwareAddr{0x02, digest[0], digest[1], digest[2], digest[3], digest[4]}.String()
}

func rootLinkCleanup(tools ToolPaths, prefix, runID string, uplink RegionUplink) RootLinkCleanup {
	return RootLinkCleanup{
		Command: command(tools.IP, "link", "del", "dev", uplink.RootDevice, "type", "veth"),
		Address: rootLinkAddress(prefix, runID, uplink.Region),
		Owner:   "vmnet:" + prefix + ":" + runID + ":" + string(uplink.Region) + ":root",
	}
}

type observedRootLink struct {
	Name    string `json:"ifname"`
	Address string `json:"address"`
	Index   int    `json:"ifindex"`
	Info    struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func (r *HostRunner) observeRootLink(ctx context.Context, name string) (*observedRootLink, error) {
	if err := validateHostTool("ip", r.tools.IP); err != nil {
		return nil, err
	}
	process := exec.CommandContext(ctx, r.tools.IP, "-j", "-d", "link", "show", "dev", name)
	var output limitedOutput
	process.Stdout, process.Stderr = &output, &output
	process.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := process.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && output.String() == fmt.Sprintf("Device %q does not exist.", name) {
			return nil, nil
		}
		return nil, fmt.Errorf("vmnet: inspect owned root link: %w: %s", err, output.String())
	}
	var links []observedRootLink
	if err := json.Unmarshal(output.Bytes(), &links); err != nil || len(links) != 1 || links[0].Name != name || links[0].Index <= 0 {
		return nil, errors.New("vmnet: root link identity observation is invalid")
	}
	return &links[0], nil
}

func (r *HostRunner) cleanupRootLink(ctx context.Context, cleanup RootLinkCleanup) error {
	args := cleanup.Command.Args
	if cleanup.Command.Executable != r.tools.IP || len(args) != 6 || args[0] != "link" || args[1] != "del" || args[2] != "dev" || args[4] != "type" || args[5] != "veth" {
		return errors.New("vmnet: root link deletion is not admitted")
	}
	name := args[3]
	owner := strings.Split(cleanup.Owner, ":")
	if len(owner) != 5 || owner[0] != "vmnet" || validIdentifier(owner[1], "prefix", 5) != nil || !runIDPattern.MatchString(owner[2]) || !validRegion(RegionCode(owner[3])) || owner[4] != "root" || name != uplinkDevice(owner[1], owner[2], RegionCode(owner[3]), true) || cleanup.Address != rootLinkAddress(owner[1], owner[2], RegionCode(owner[3])) {
		return errors.New("vmnet: root link cleanup ownership is invalid")
	}
	observed, err := r.observeRootLink(ctx, name)
	if err != nil || observed == nil {
		return err
	}
	if observed.Info.Kind != "veth" || observed.Address != cleanup.Address || cleanup.Address == "" {
		return errors.New("vmnet: root link ownership differs from its cleanup journal")
	}
	if err := r.Run(ctx, cleanup.Command.Executable, args); err != nil {
		// A concurrent namespace release may have already destroyed the peer.
		remaining, observeErr := r.observeRootLink(ctx, name)
		if observeErr == nil && remaining == nil {
			return nil
		}
		return errors.Join(err, observeErr)
	}
	remaining, err := r.observeRootLink(ctx, name)
	if err != nil {
		return err
	}
	if remaining != nil {
		return errors.New("vmnet: owned root link remains after deletion")
	}
	return nil
}

func (r *HostRunner) checkRootLinkCollisions(ctx context.Context, links []RootLinkCleanup) error {
	for _, link := range links {
		observed, err := r.observeRootLink(ctx, link.Command.Args[3])
		if err != nil {
			return err
		}
		if observed != nil {
			return errors.New("vmnet: existing root link requires owned journal cleanup before apply")
		}
	}
	return nil
}

func (r *RecordingRunner) cleanupRootLink(ctx context.Context, cleanup RootLinkCleanup) error {
	return r.RunCleanup(ctx, cleanup.Command.Executable, cleanup.Command.Args)
}
