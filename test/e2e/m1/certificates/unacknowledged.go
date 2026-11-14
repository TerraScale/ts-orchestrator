package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func unacknowledgedLeaseRollout(ctx context.Context, cfg configuration, current, store *process) error {
	pidData, err := os.ReadFile(cfg.Work + "/a.pid")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return err
	}
	stageCtx, stopStage := context.WithTimeout(ctx, 2*time.Minute)
	defer stopStage()
	debugger, err := launch(ctx, cfg.Work+"/lease-debugger", nil, "gdb", "--nx", "--quiet", "--batch",
		"-ex", "handle SIGPIPE nostop noprint pass", "-ex", "handle SIGURG nostop noprint pass", "-ex", "set pagination off", "-ex", "set confirm off", "-ex", "set auto-load off", "-ex", "set print frame-arguments none", "-ex", "set print thread-events off",
		"-ex", fmt.Sprintf("attach %d", pid), "-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*certificateCache).lease'",
		"-ex", "echo READY debugger\\n", "-ex", "continue",
		"-ex", "delete", "-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*certificateCache).write'", "-ex", "continue",
		"-ex", fmt.Sprintf("shell kill -STOP %d", store.cmd.Process.Pid), "-ex", "echo STORE STOPPED\\n", "-ex", "detach")
	if err != nil {
		return err
	}
	defer debugger.stop()
	if err := debugger.wait(stageCtx, "READY debugger", 1); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "rollout", []string{"asymmetric.e2e.test", "urgent.e2e.test"}); err != nil {
		return err
	}
	if err := debugger.wait(stageCtx, "STORE STOPPED", 1); err != nil {
		return err
	}
	written := current.wait(stageCtx, "edge certificate unavailable name=urgent.e2e.test ", 1)
	if err := store.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return err
	}
	if written != nil {
		return fmt.Errorf("lease write outlived the paused store: %w", written)
	}
	if err := current.wait(stageCtx, "edge certificate installed name=urgent.e2e.test ", 2); err != nil {
		return fmt.Errorf("urgent renewal blocked by its own unacknowledged lease: %w", err)
	}
	fmt.Println("PASS lease write acknowledged only after its deadline: the issuer adopts its own unacknowledged lease and renews")
	return nil
}
