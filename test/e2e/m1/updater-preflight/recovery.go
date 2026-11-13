package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/fsnotify/fsnotify"
)

func recoveryInstall(ctx context.Context) {
	h, err := releasepush.NewHandler("/var/lib/ts-orch")
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	asset := "/opt/candidate"
	binary, err := os.Executable()
	must(err)
	writeExecutable(asset, stamped(read(binary), shaB, "early-exit"))
	reply := installAsset(ctx, h, conn, asset, shaB, "2")
	require(reply.State == "installed", fmt.Sprintf("signed candidate must install: %+v", reply))
}

func recoveryCase(ctx context.Context, binary string) {
	state := "/var/lib/ts-orch"
	installed := "/usr/local/bin/terrascale-orchestrator"
	must(os.MkdirAll(filepath.Join(state, "nats"), 0700))
	original := read(binary)
	writeExecutable(installed, original)
	must(os.WriteFile("/etc/systemd/system/recovery-install.service", []byte("[Service]\nType=oneshot\nProtectSystem=full\nReadWritePaths=/usr/local/bin\nExecStart=/usr/local/bin/terrascale-orchestrator recovery-install /var/lib/ts-orch\n"), 0644))
	must(exec.CommandContext(ctx, "systemctl", "daemon-reload").Run())
	command := exec.CommandContext(ctx, "systemctl", "start", "recovery-install.service")
	output, err := command.CombinedOutput()
	require(err == nil, fmt.Sprintf("release must install through the real handler: %v %s", err, output))
	require(bytes.Equal(read(installed+".recovery"), original), "recovery must retain the installing updater independently of the candidate")
	require(bytes.Equal(read(installed+".prev"), original), "previous bytes must be retained by binary staging")
	trialPath := filepath.Join(state, "nats/release-trial")
	trial := record(trialPath)
	require(trial["recover_after"] != nil, "the deadline must be durable before commit")
	before := read(trialPath)
	must(exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service").Run())
	require(bytes.Equal(read(trialPath), before) && record(filepath.Join(state, "nats/release-recovery")) == nil, "a candidate before its deadline must remain untouched")
	trial["installed"] = time.Now().Add(-time.Hour)
	trial["recover_after"] = time.Now().Add(-time.Minute)
	data, err := json.Marshal(trial)
	must(err)
	write(trialPath, string(data))
	command = exec.CommandContext(ctx, "systemctl", "start", "ts-orch.service")
	require(command.Run() != nil, "candidate must fail before Probe")
	require(record(trialPath)["starts"] == float64(0), "the failed candidate must not advance the startup counter")
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(filepath.Join(state, "nats")))
	must(os.MkdirAll("/etc/systemd/system/ts-orch-release-recovery.timer.d", 0755))
	write("/etc/systemd/system/ts-orch-release-recovery.timer.d/lane.conf", "[Timer]\nOnBootSec=\nOnActiveSec=100ms\n")
	must(exec.CommandContext(ctx, "systemctl", "daemon-reload").Run())
	must(exec.CommandContext(ctx, "systemctl", "restart", "ts-orch-release-recovery.timer").Run())
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	finished := false
	for !finished {
		select {
		case event := <-watcher.Events:
			if event.Name != filepath.Join(state, "nats/release-recovery") || event.Op&fsnotify.Remove == 0 {
				continue
			}
			require(bytes.Equal(read(installed), original), "recovery must restore the previous exact bytes")
			require(record(trialPath) == nil && record(filepath.Join(state, "nats/release-rolled-back"))["sha"] == shaB, "recovery must durably reject the candidate and remove its trial")
			must(exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "ts-orch.service").Run())
			fmt.Println("ok recovery: real signed install; candidate exits before Probe; independent timer restores previous bytes and restarts the unit")
			finished = true
		case err := <-watcher.Errors:
			must(err)
		case <-deadline.Done():
			panic("independent recovery timer did not finish: " + deadline.Err().Error())
		}
	}
	invocation, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "InvocationID", "--value").Output()
	must(err)
	must(exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service").Run())
	after, err := exec.CommandContext(ctx, "systemctl", "show", "ts-orch.service", "-p", "InvocationID", "--value").Output()
	must(err)
	require(bytes.Equal(invocation, after), "a confirmed release must not restart")
	fmt.Println("ok recovery: deadline not reached and confirmed release are both no-ops")
	must(exec.CommandContext(ctx, "systemctl", "stop", "ts-orch-release-recovery.timer", "ts-orch.service").Run())
	marker := filepath.Join(state, "nats/release-recovery")
	write(marker, string(data))
	must(exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service").Run())
	require(record(marker) == nil && bytes.Equal(read(installed), original), "recovery interrupted after rename must finish the restart without a previous file")
	must(exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "ts-orch.service").Run())
	fmt.Println("ok recovery: durable restart intent resumes after rollback rename")
	must(exec.CommandContext(ctx, "systemctl", "stop", "ts-orch.service").Run())
	candidate := stamped(original, shaB, "early-exit")
	writeExecutable(installed, candidate)
	writeExecutable(installed+".prev.staged", original)
	must(os.WriteFile(trialPath+".staged", data, 0600))
	must(exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service").Run())
	require(bytes.Equal(read(installed), original) && record(trialPath+".staged") == nil && record(trialPath) == nil, "post-rename staged trial must promote before recovery")
	fmt.Println("ok recovery: committed binary with unpromoted staged records rolls back")
	must(exec.CommandContext(ctx, "systemctl", "stop", "ts-orch.service").Run())
	writeExecutable(installed, candidate)
	write(trialPath, string(data))
	command = exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service")
	require(command.Run() != nil, "missing backup must fail recovery visibly")
	require(record(marker) != nil && record(trialPath)["failure"] != nil && bytes.Equal(read(installed), candidate), "missing backup must retain trial, intent and candidate bytes")
	writeExecutable(installed+".prev", original)
	must(exec.CommandContext(ctx, "systemctl", "start", "ts-orch-release-recovery.service").Run())
	require(record(marker) == nil && record(trialPath) == nil && bytes.Equal(read(installed), original), "retained intent must recover once the recorded backup is available")
	fmt.Println("ok recovery: missing backup fails visibly; durable intent remains until restoration succeeds")

}
