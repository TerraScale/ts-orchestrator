package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const unservedWait = 15 * time.Second

func (j *journey) everyNodeFromManager(image string) (err error) {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	drop := []string{"INPUT", "!", "-i", "lo", "-p", "tcp", "--dport", "18087", "-j", "DROP"}
	firewall := func(action string) error {
		output, err := exec.CommandContext(j.ctx, "ip", slices.Concat([]string{"netns", "exec", "c18b", "iptables", action}, drop)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %s on c18b: %w: %s", action, err, output)
		}
		return nil
	}
	run := func(mode string) error {
		output, err := exec.CommandContext(j.ctx, "ip", "netns", "exec", "c18a", self, "every-node", j.root, image, mode).CombinedOutput()
		fmt.Print(string(output))
		if err != nil {
			return fmt.Errorf("every-node whoami from the manager (%s worker): %w", mode, err)
		}
		return nil
	}
	if err := firewall("-I"); err != nil {
		return err
	}
	dropped := true
	defer func() {
		if dropped {
			err = errors.Join(err, firewall("-D"))
		}
	}()
	if err := run("unserved"); err != nil {
		return err
	}
	if err := firewall("-D"); err != nil {
		return err
	}
	dropped = false
	return run("served")
}

func everyNode(ctx context.Context, root, image, mode string) error {
	control, conn, err := swarmruntime.DialControl(filepath.Join(root, "c18a"))
	if err != nil {
		return err
	}
	defer conn.Close()
	spec := swarmruntime.ServiceSpec{Name: "whoami", Image: image, Env: map[string]string{"PORT": "18087"},
		Args: []string{"sh", "-c", "wget -q -O /tmp/lifecycle http://127.0.0.1:19090/binary && chmod +x /tmp/lifecycle && exec /tmp/lifecycle serve"},
		Port: 18087, ReadyPath: "/ready", Replicas: 2, Dependencies: &[]string{}, Region: "c18", Node: "c18a",
		WorkerAddresses: map[string]string{"c18b": "10.231.0.3"}}
	before, err := swarmruntime.ApplyServiceSpec(ctx, control, spec)
	if err != nil {
		return err
	}
	if err := swarmruntime.CompleteServiceSpec(ctx, control, spec, before); err != nil {
		return err
	}
	if mode == "unserved" {
		waitCtx, cancel := context.WithTimeout(ctx, unservedWait)
		_, err := swarmruntime.WaitServiceSpecExact(waitCtx, control, spec)
		cancel()
		if err == nil {
			return fmt.Errorf("every-node whoami became ready while the manager could not reach its worker's task")
		}
		for _, want := range []string{"service whoami is not ready: task ", " on c18b (10.231.0.3): task application readiness request failed: ", "dial tcp 10.231.0.3:18087: i/o timeout"} {
			if !strings.Contains(err.Error(), want) {
				return fmt.Errorf("every-node whoami failed without naming the unserved worker task (want %q): %w", want, err)
			}
		}
		fmt.Printf("every-node whoami with a running but unreachable worker task is not ready: %v\n", err)
		return swarmruntime.RemoveServiceSpec(ctx, control, "whoami")
	}
	rollout, err := swarmruntime.WaitServiceSpecExact(ctx, control, spec)
	if err != nil {
		return err
	}
	var machines []string
	for _, task := range rollout.Tasks {
		machines = append(machines, task.Machine)
	}
	slices.Sort(machines)
	if !slices.Equal(machines, []string{"c18a", "c18b"}) {
		return fmt.Errorf("every-node whoami ready on %v, want the manager and its worker", machines)
	}
	fmt.Printf("every-node whoami ready on %v in %s: the manager probed its worker's task at 10.231.0.3:18087\n", machines, rollout.Ready.Round(time.Millisecond))
	return swarmruntime.RemoveServiceSpec(ctx, control, "whoami")
}
