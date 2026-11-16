package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func (j *journey) everyNodeFromManager(image string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	output, err := exec.CommandContext(j.ctx, "ip", "netns", "exec", "c18a", self, "every-node", j.root, image).CombinedOutput()
	fmt.Print(string(output))
	if err != nil {
		return fmt.Errorf("every-node whoami from the manager: %w", err)
	}
	return nil
}

func everyNode(ctx context.Context, root, image string) error {
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
