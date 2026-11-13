package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type traced struct {
	State  string `json:"state"`
	Leader int    `json:"leader"`
}

type traceSummary struct {
	traced
	Before   int    `json:"group_signals_before_reap"`
	After    int    `json:"group_signals_after_reap"`
	Reaped   bool   `json:"reaped"`
	Unreaped bool   `json:"unreaped_wait"`
	Output   string `json:"output,omitempty"`
}

type syscallEvent struct {
	nr     uint64
	args   [4]uint64
	entry  int
	exit   int
	ret    int64
	waited int32
}

func tracedPreflight(ctx context.Context) {
	work, cleanup := temporary("traced-")
	defer cleanup()
	mark := filepath.Join(work, "leader")
	h := newHost(filepath.Join(work, "host"), false)
	handler := h.handler()
	asset := stamped(helperBytes(), shaB, "pid:"+mark)
	p := newProvider(asset)
	defer p.server.Close()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	conn, closeListener := listener(handler)
	defer closeListener()
	reply := send(ctx, conn, p.release(shaB, "2", "e2e"), p.declaration())
	leaders := marks(mark)
	require(len(leaders) == 1, fmt.Sprintf("the candidate must have run its preflight once: %v %+v", leaders, reply))
	var leader int
	_, err := fmt.Sscan(leaders[0], &leader)
	must(err)
	data, err := json.Marshal(traced{State: reply.State, Leader: leader})
	must(err)
	fmt.Println("TRACED", string(data))
}

func tracePreflight() {
	runtime.LockOSThread()
	self, err := os.Executable()
	must(err)
	var output bytes.Buffer
	command := exec.Command(self, "traced-preflight")
	command.Stdout, command.Stderr = &output, &output
	command.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	must(command.Start())
	pid := command.Process.Pid
	var status unix.WaitStatus
	_, err = unix.Wait4(pid, &status, unix.WALL, nil)
	must(err)
	must(unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_EXITKILL))
	must(unix.PtraceSyscall(pid, 0))
	inside := map[int]*syscallEvent{}
	var calls []*syscallEvent
	sequence := 0
	for {
		tid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		must(err)
		if status.Exited() || status.Signaled() {
			if tid == pid {
				break
			}
			continue
		}
		resume := 0
		switch signal := status.StopSignal(); {
		case signal == unix.SIGTRAP|0x80:
			sequence++
			nr, args, ret, err := syscallRegisters(tid)
			if err != nil {
				break
			}
			if call, ok := inside[tid]; ok {
				delete(inside, tid)
				call.exit, call.ret = sequence, ret
				if call.nr == unix.SYS_WAITID && ret == 0 && call.args[2] != 0 {
					info := make([]byte, 24)
					if _, err := unix.PtracePeekData(tid, uintptr(call.args[2]), info); err == nil {
						call.waited = int32(binary.LittleEndian.Uint32(info[16:]))
					}
				}
				break
			}
			if nr == unix.SYS_KILL || nr == unix.SYS_WAITID || nr == unix.SYS_WAIT4 {
				call := &syscallEvent{nr: nr, args: args, entry: sequence}
				inside[tid] = call
				calls = append(calls, call)
			} else {
				inside[tid] = &syscallEvent{nr: nr, entry: sequence}
			}
		case signal == unix.SIGTRAP && status.TrapCause() > 0, signal == unix.SIGSTOP:
		default:
			resume = int(signal)
		}
		if err := unix.PtraceSyscall(tid, resume); err != nil && !errors.Is(err, unix.ESRCH) {
			panic(err)
		}
	}
	summary := traceSummary{Output: strings.TrimSpace(output.String())}
	for _, line := range strings.Split(output.String(), "\n") {
		if after, ok := strings.CutPrefix(line, "TRACED "); ok {
			must(json.Unmarshal([]byte(after), &summary.traced))
		}
	}
	leader := summary.Leader
	reaped := -1
	for _, call := range calls {
		reaping := call.nr == unix.SYS_WAITID && call.exit > 0 && call.ret == 0 && call.waited == int32(leader) && call.args[3]&unix.WNOWAIT == 0
		reaping = reaping || call.nr == unix.SYS_WAIT4 && call.exit > 0 && call.ret == int64(leader)
		if reaping && reaped < 0 {
			reaped = call.entry
			summary.Reaped = true
		}
		if call.nr == unix.SYS_WAITID && call.args[0] == unix.P_PID && int(call.args[1]) == leader && call.args[3]&unix.WNOWAIT != 0 {
			summary.Unreaped = true
		}
	}
	for _, call := range calls {
		target := int32(call.args[0])
		if call.nr != unix.SYS_KILL || (target != -int32(leader) && target != int32(leader)) {
			continue
		}
		if reaped >= 0 && call.exit > 0 && call.exit < reaped {
			summary.Before++
		} else {
			summary.After++
		}
	}
	data, err := json.Marshal(summary)
	must(err)
	fmt.Println(string(data))
}

func traceCase(ctx context.Context) {
	self, err := os.Executable()
	must(err)
	output, err := exec.CommandContext(ctx, self, "trace-preflight").CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var summary traceSummary
	require(err == nil && json.Unmarshal([]byte(lines[len(lines)-1]), &summary) == nil, fmt.Sprintf("the traced preflight must finish: %v: %s", err, output))
	require(summary.State == "installed" && summary.Leader > 0 && summary.Reaped, fmt.Sprintf("a candidate whose preflight exits at once is installed and collected: %+v", summary))
	require(summary.Before >= 1 && summary.After == 0, fmt.Sprintf("the group is signalled while the exited candidate still holds its id, and never after the candidate is collected: %d signals before the reap, %d after: %+v", summary.Before, summary.After, summary))
	fmt.Println("ok process group kill order: candidate", summary.Leader, "waited for without collecting it:", summary.Unreaped, ";", summary.Before, "group signal(s) before the reap, none after")
}
