package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

func recoveryInstall(ctx context.Context) {
	h, err := releasepush.NewHandler("/var/lib/ts-orch")
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	asset := "/opt/candidate"
	binary, err := os.Executable()
	must(err)
	writeExecutable(asset, stamped(read(binary), shaC, "early-exit"))
	reply := installAsset(ctx, h, conn, asset, shaC, "20")
	require(reply.State == "installed", fmt.Sprintf("signed repair must install: %+v", reply))
}

func recoveryCase(ctx context.Context, binary string) {
	const installed = "/usr/local/bin/terrascale-orchestrator"
	const state = "/var/lib/ts-orch/nats"
	const trialPath = state + "/release-trial"
	const marker = state + "/release-recovery"
	original := read(binary)
	candidate := stamped(original, shaB, "hold")
	unit := "ts-orch.service"
	recoverUnit := "ts-orch-release-recovery.service"
	run := func(args ...string) error {
		output, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
		if err != nil {
			journal, _ := exec.CommandContext(ctx, "journalctl", "-u", args[len(args)-1], "-n", "16", "--no-pager", "-o", "cat").CombinedOutput()
			return fmt.Errorf("systemctl %s: %w %s %s", strings.Join(args, " "), err, output, journal)
		}
		return nil
	}
	trial := func(data []byte, window time.Duration) []byte {
		installedAt := time.Now().Add(-time.Hour)
		data, err := json.Marshal(map[string]any{"sha": shaB, "sha256": digest(data), "run_id": "2", "installed": installedAt, "recover_after": installedAt.Add(window), "starts": 0, "previous": map[string]string{"sha": releasepush.Revision(), "sha256": digest(original)}})
		must(err)
		return data
	}
	seed := func(data []byte, window time.Duration) []byte {
		writeExecutable(installed, data)
		writeExecutable(installed+".prev", original)
		value := trial(data, window)
		must(os.WriteFile(trialPath, value, 0600))
		return value
	}
	active := func() {
		must(run("is-active", "--quiet", unit))
		conn, err := nats.Connect(strings.TrimSpace(string(read("/run/recovery-listener"))))
		must(err)
		defer conn.Close()
		reply := request(ctx, conn, releasepush.SubjectVersion, nil)
		require(reply.Version != "", "the running agent must answer its NATS version request")
	}
	cases := []struct {
		name  string
		check func()
	}{
		{"R8 sandbox signed install", func() {
			writeExecutable(installed, original)
			write("/etc/systemd/system/recovery-install.service", "[Service]\nType=oneshot\nProtectSystem=full\nReadWritePaths=/usr/local/bin\nExecStart=/usr/local/bin/terrascale-orchestrator recovery-install /var/lib/ts-orch\n")
			must(run("daemon-reload"))
			must(run("start", "recovery-install.service"))
			require(bytes.Equal(read(installed+".recovery"), original), "recovery executable must retain installing updater bytes")
			require(bytes.Equal(read(installed+".prev"), original), "signed install must retain previous bytes")
			require(record(trialPath)["recover_after"] != nil, "signed install must persist its recovery window")
			must(run("is-enabled", "--quiet", "ts-orch-release-recovery.timer"))
		}},
		{"R1 missing backup keeps NATS serving", func() {
			seed(candidate, time.Nanosecond)
			must(run("start", unit))
			active()
			must(os.Remove(installed + ".prev"))
			require(run("start", recoverUnit) != nil, "missing backup must report a recovery error")
			active()
			require(bytes.Equal(read(installed), candidate) && record(trialPath)["failure"] != nil && record(marker) != nil, "missing backup must retain bytes, trial failure and intent")
			must(run("reset-failed", recoverUnit))
			require(run("start", recoverUnit) != nil, "the next tick must still report missing backup")
			active()
			writeExecutable(installed+".prev", original)
			must(run("start", recoverUnit))
			active()
			require(bytes.Equal(read(installed), original) && record(marker) == nil, "restored backup must finish retained intent")
		}},
		{"R2 mismatched backup keeps NATS serving", func() {
			seed(candidate, time.Nanosecond)
			must(run("start", unit))
			writeExecutable(installed+".prev", stamped(original, shaD, "pass"))
			require(run("start", recoverUnit) != nil, "mismatched backup must report a recovery error")
			active()
			require(record(trialPath)["failure"] != nil && bytes.Equal(read(installed), candidate), "mismatched backup must report failure without replacing candidate")
		}},
		{"R3 intent plus confirmation converges", func() {
			data := seed(candidate, time.Nanosecond)
			must(run("start", unit))
			write(marker, string(data))
			must(os.Remove(trialPath))
			must(os.Remove(installed + ".prev"))
			must(run("start", recoverUnit))
			active()
			require(bytes.Equal(read(installed), candidate) && record(marker) == nil, "confirmation after intent must preserve candidate and clear intent")
		}},
		{"R4 unconfirmed updater installs repair without recovery executable", func() {
			seed(candidate, time.Nanosecond)
			value := record(trialPath)
			value["failure"] = "rollback unavailable"
			data, err := json.Marshal(value)
			must(err)
			write(trialPath, string(data))
			must(os.Remove(installed + ".recovery"))
			must(run("start", "recovery-install.service"))
			require(record(trialPath)["sha"] == shaC && bytes.Equal(read(installed+".recovery"), candidate), "repair must install its independent recovery executable")
		}},
		{"R5 boot start receives full monotonic window", func() {
			starting := stamped(original, shaB, "starting")
			seed(starting, 15*time.Minute)
			watcher, err := unix.InotifyInit1(unix.IN_CLOEXEC)
			must(err)
			defer unix.Close(watcher)
			_, err = unix.InotifyAddWatch(watcher, "/run", unix.IN_CLOSE_WRITE)
			must(err)
			must(run("start", "--no-block", unit))
			deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				buffer := make([]byte, 4096)
				for {
					_, err := unix.Read(watcher, buffer)
					if err != nil {
						done <- err
						return
					}
					if _, err := os.Stat("/run/recovery-listener"); err == nil {
						done <- nil
						return
					}
				}
			}()
			select {
			case err := <-done:
				must(err)
			case <-deadline.Done():
				panic("starting candidate did not open its listener")
			}
			must(run("start", recoverUnit))
			require(bytes.Equal(read(installed), starting) && record(marker) == nil, "an old wall-clock deadline must not stop a candidate starting this boot")
			output, err := exec.CommandContext(ctx, "systemctl", "show", unit, "-p", "ActiveState", "--value").Output()
			must(err)
			require(strings.TrimSpace(string(output)) == "activating", "candidate must retain its full startup window")
			value := record(trialPath)
			value["installed"] = time.Now().Add(-48 * time.Hour)
			value["recover_after"] = time.Now().Add(-48*time.Hour + 15*time.Minute)
			shifted, err := json.Marshal(value)
			must(err)
			write(trialPath, string(shifted))
			must(run("start", recoverUnit))
			require(bytes.Equal(read(installed), starting) && record(marker) == nil, "wall-clock jump must not expire a monotonic trial")
		}},
		{"R6 crash after intent and rename resumes", func() {
			data := seed(candidate, time.Nanosecond)
			write(marker, string(data))
			must(run("start", recoverUnit))
			active()
			require(bytes.Equal(read(installed), original) && record(trialPath) == nil && record(marker) == nil, "crash after intent must finish rollback")
			must(run("stop", unit))
			write(marker, string(data))
			must(run("start", recoverUnit))
			active()
			require(bytes.Equal(read(installed), original) && record(marker) == nil, "crash after rename must restart without consumed backup")
		}},
		{"R7 no action before deadline", func() {
			seed(candidate, 15*time.Minute)
			value := record(trialPath)
			value["installed"] = time.Now()
			value["recover_after"] = time.Now().Add(15 * time.Minute)
			data, err := json.Marshal(value)
			must(err)
			write(trialPath, string(data))
			must(run("start", unit))
			must(run("start", recoverUnit))
			active()
			require(bytes.Equal(read(installed), candidate) && record(marker) == nil && record(trialPath)["sha"] == shaB, "candidate before deadline must remain untouched")
		}},
		{"R9 staging error keeps NATS serving", func() {
			seed(candidate, time.Nanosecond)
			must(run("start", unit))
			write(installed+".prev.staged/blocked", "staging failure")
			require(run("start", recoverUnit) != nil, "staging failure must be reported")
			active()
			require(bytes.Equal(read(installed), candidate), "staging error must preserve serving candidate")
		}},
		{"R10 idle tick never opens agent", func() {
			writeExecutable(installed, original)
			watcher, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
			must(err)
			defer unix.Close(watcher)
			_, err = unix.InotifyAddWatch(watcher, installed, unix.IN_OPEN)
			must(err)
			must(run("start", recoverUnit))
			buffer := make([]byte, 4096)
			_, err = unix.Read(watcher, buffer)
			require(err == unix.EAGAIN, "idle recovery must not open or hash the agent binary")
		}},
		{"R11 post-stop failure restarts NATS listener", func() {
			seed(candidate, time.Nanosecond)
			write("/etc/systemd/system/ts-orch.service.d/lane.conf", "[Service]\nExecStopPost=/opt/recovery-e2e recovery-break-previous /var/lib/ts-orch\n")
			must(run("daemon-reload"))
			must(run("start", unit))
			require(run("start", recoverUnit) != nil, "post-stop rollback failure must be reported")
			active()
			require(bytes.Equal(read(installed), candidate), "post-stop failure must retain candidate bytes")
		}},
		{"R12 committed staged trial rolls back", func() {
			seed(stamped(original, shaB, "early-exit"), time.Nanosecond)
			must(os.Rename(trialPath, trialPath+".staged"))
			must(os.Rename(installed+".prev", installed+".prev.staged"))
			require(run("start", unit) != nil, "candidate must exit before Probe")
			require(record(trialPath + ".staged")["starts"] == float64(0), "early exit must not advance startup count")
			watcher, err := fsnotify.NewWatcher()
			must(err)
			defer watcher.Close()
			must(watcher.Add(state))
			write("/etc/systemd/system/ts-orch-release-recovery.timer.d/lane.conf", "[Timer]\\nOnBootSec=\\nOnActiveSec=100ms\\n")
			must(run("daemon-reload"))
			must(run("restart", "ts-orch-release-recovery.timer"))
			deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			finished := false
			for !finished {
				select {
				case event := <-watcher.Events:
					finished = event.Name == marker && event.Op&fsnotify.Remove != 0
				case err := <-watcher.Errors:
					must(err)
				case <-deadline.Done():
					panic("independent recovery timer did not finish")
				}
			}
			active()
			require(bytes.Equal(read(installed), original) && record(trialPath+".staged") == nil && record(trialPath) == nil, "committed staging must promote and roll back")
		}},
	}
	failures := 0
	for _, c := range cases {
		func() {
			defer func() {
				if err := recover(); err != nil {
					failures++
					fmt.Printf("FAIL %s: %v\n", c.name, err)
				}
			}()
			_ = run("stop", "ts-orch-release-recovery.timer", recoverUnit, unit)
			must(os.RemoveAll("/etc/systemd/system/ts-orch.service.d"))
			must(run("daemon-reload"))
			_ = run("reset-failed", unit, recoverUnit, "recovery-install.service")
			must(os.RemoveAll(state))
			must(os.MkdirAll(state, 0700))
			must(os.RemoveAll(installed + ".prev"))
			must(os.RemoveAll(installed + ".prev.staged"))
			writeExecutable(installed+".recovery", original)
			_ = os.Remove("/run/recovery-listener")
			c.check()
			fmt.Println("ok " + c.name)
		}()
	}
	require(failures == 0, fmt.Sprintf("%d recovery cases failed", failures))
}
