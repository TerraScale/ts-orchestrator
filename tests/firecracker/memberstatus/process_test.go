//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

// A live API adapter keeps Python Popen handles, which are required by the
// implementation's waitid-without-reaping contract. Go selects every operation,
// supplies child programs, waits for filesystem evidence, and checks outcomes.
type msProcessSession struct {
	t      *testing.T
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func msNewProcessSession(t *testing.T) *msProcessSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	module := filepath.Join(script.Root(t), "tests/firecracker/memberstatus/qualify.py")
	cmd := exec.CommandContext(ctx, "python3", "-u", "-c", msProcessAdapter, module)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	log, err := os.Create(filepath.Join(t.TempDir(), "adapter-stderr.log"))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = log
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		log.Close()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		log.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		log.Close()
		t.Fatal(err)
	}
	session := &msProcessSession{t, cmd, input, bufio.NewReader(output)}
	t.Cleanup(func() {
		defer cancel()
		defer log.Close()
		// This runs even after a failed native assertion, so owned children are
		// always killed/reaped before the adapter itself exits.
		session.call(map[string]any{"operation": "cleanup_all"})
		input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("process API adapter exit: %v", err)
		}
	})
	return session
}

func (s *msProcessSession) call(request map[string]any) map[string]any {
	s.t.Helper()
	wire, err := json.Marshal(request)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.input.Write(append(wire, '\n')); err != nil {
		s.t.Fatal(err)
	}
	line, err := s.output.ReadBytes('\n')
	if err != nil {
		s.t.Fatalf("process API adapter response: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(line, &result); err != nil {
		s.t.Fatalf("invalid process observation %q: %v", line, err)
	}
	return result
}

func (s *msProcessSession) spawn(id, source, directory string) int {
	s.t.Helper()
	got := s.call(map[string]any{"operation": "spawn", "id": id, "source": source, "log": filepath.Join(directory, id+".log")})
	if got["error"] != nil {
		s.t.Fatalf("spawn fixture: %v", got)
	}
	return int(got["pid"].(float64))
}

func (s *msProcessSession) stop(id string, term, kill float64, forceTimeout bool) map[string]any {
	s.t.Helper()
	return s.call(map[string]any{"operation": "stop", "id": id, "term_timeout": term, "kill_timeout": kill, "force_timeout": forceTimeout})
}

func msWaitFile(t *testing.T, path string, nonempty bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Stat(path)
		if err == nil && (!nonempty || info.Size() > 0) {
			return
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("signal-test child did not produce %s", path)
}

func msSleepingChild(ready string, ignore bool) string {
	handler := "lambda *_: sys.exit(0)"
	if ignore {
		handler = "signal.SIG_IGN"
	}
	return fmt.Sprintf("import signal,time,sys; signal.signal(signal.SIGTERM,%s); open(%q,'w').close(); time.sleep(20)", handler, ready)
}

func TestMemberStatusProcessGroupCleanup(t *testing.T) {
	for _, kind := range []string{"graceful_term", "kill_ignored_term", "timeout_retry", "already_reaped", "idempotent", "surviving_child", "unrelated_group"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			session := msNewProcessSession(t)
			ready := filepath.Join(directory, "ready")
			if kind == "already_reaped" {
				session.spawn("owned", "pass", directory)
				got := session.call(map[string]any{"operation": "wait", "id": "owned", "timeout": 2})
				msEqual(t, got["value"], 0)
				msReject(t, session.stop("owned", .1, .1, false), "QualificationError", "reaped before its process group")
				return
			}
			if kind == "surviving_child" {
				progress := filepath.Join(directory, "child-progress")
				source := fmt.Sprintf(`import os,signal,time
child=os.fork()
if child==0:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    open(%q,'w').close()
    while True:
        with open(%q,'a') as stream: stream.write('x')
        time.sleep(.02)
else:
    os._exit(0)
`, ready, progress)
				session.spawn("owned", source, directory)
				msWaitFile(t, ready, false)
				msWaitFile(t, progress, true)
				got := session.call(map[string]any{"operation": "wait_child_without_reaping", "id": "owned", "timeout": 2})
				msEqual(t, got["value"], true)
				msEqual(t, got["returncode"], nil)
				got = session.stop("owned", .1, 1, false)
				msEqual(t, got["value"], 0)
				if got["returncode"] == nil {
					t.Fatal("leader remained unreaped after group cleanup")
				}
				info, err := os.Stat(progress)
				if err != nil {
					t.Fatal(err)
				}
				size := info.Size()
				time.Sleep(100 * time.Millisecond)
				info, err = os.Stat(progress)
				if err != nil {
					t.Fatal(err)
				}
				msEqual(t, info.Size(), size)
				return
			}
			ignore := kind != "graceful_term" && kind != "unrelated_group"
			ownedPID := session.spawn("owned", msSleepingChild(ready, ignore), directory)
			msWaitFile(t, ready, false)
			switch kind {
			case "graceful_term":
				got := session.stop("owned", 1, 1, false)
				msEqual(t, got["value"], 0)
				msEqual(t, session.call(map[string]any{"operation": "poll", "id": "owned"})["value"], 0)
			case "kill_ignored_term":
				got := session.stop("owned", .1, 1, false)
				msEqual(t, got["value"], -9)
				msEqual(t, session.call(map[string]any{"operation": "poll", "id": "owned"})["value"], -9)
			case "timeout_retry":
				got := session.stop("owned", .1, .1, true)
				msReject(t, got, "QualificationError", "live members")
				msEqual(t, got["returncode"], nil)
				got = session.stop("owned", .1, 1, false)
				msEqual(t, got["value"], -9)
				msEqual(t, got["returncode"], -9)
			case "idempotent":
				first := session.stop("owned", .1, 1, false)
				second := session.stop("owned", .1, 1, false)
				msEqual(t, first["value"], second["value"])
				msEqual(t, second["returncode"], -9)
			case "unrelated_group":
				unrelatedPID := session.spawn("unrelated", "import time; time.sleep(20)", directory)
				if unrelatedPID == ownedPID {
					t.Fatal("owned and unrelated PIDs match")
				}
				got := session.stop("owned", 1, 1, false)
				msEqual(t, got["value"], 0)
				msEqual(t, session.call(map[string]any{"operation": "poll", "id": "unrelated"})["value"], nil)
				got = session.stop("unrelated", 1, 1, false)
				if got["error"] != nil {
					t.Fatal(got)
				}
			}
		})
	}
}

func TestMemberStatusUnquiescedVMMRetainsEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	msQualificationDirectories(t, root)
	script.Write(t, filepath.Join(root, "images/member-status.ext4"), []byte("guest evidence"), 0o600)
	socketDir := filepath.Join(root, "api-socket")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "vmm-ready")
	session := msNewProcessSession(t)
	session.spawn("vmm", msSleepingChild(ready, true), root)
	msWaitFile(t, ready, false)
	got := session.stop("vmm", .1, .1, true)
	msReject(t, got, "QualificationError", "live members")
	msEqual(t, got["returncode"], nil)
	got = session.call(map[string]any{"operation": "qualification_cleanup", "id": "vmm", "root": root, "socket_dir": socketDir})
	if got["error"] != nil {
		t.Fatal(got)
	}
	msEqual(t, got["returncode"], nil)
	if _, err := os.Stat(socketDir); err != nil {
		t.Fatal("API socket not retained:", err)
	}
	if _, err := os.Stat(got["image"].(string)); err != nil {
		t.Fatal("guest image not retained:", err)
	}
}

const msProcessAdapter = `import importlib.util,json,pathlib,sys,subprocess,signal,os
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location("process_subject",sys.argv[1])
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
processes={}
streams=[]
for line in sys.stdin:
    a=json.loads(line)
    operation=a["operation"]
    process=processes.get(a.get("id"))
    try:
        if operation=="spawn":
            stream=open(a["log"],"wb")
            streams.append(stream)
            process=subprocess.Popen([sys.executable,"-c",a["source"]],stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            processes[a["id"]]=process
            result={"pid":process.pid}
        elif operation=="stop":
            wait=m._wait_process_group_quiescent
            try:
                if a.get("force_timeout"):
                    m._wait_process_group_quiescent=lambda *_:False
                result={"value":m.stop_process_group(process,term_timeout=a["term_timeout"],kill_timeout=a["kill_timeout"])}
            finally:
                m._wait_process_group_quiescent=wait
        elif operation=="wait":
            result={"value":process.wait(timeout=a["timeout"])}
        elif operation=="poll":
            result={"value":process.poll()}
        elif operation=="wait_child_without_reaping":
            result={"value":m._wait_child_without_reaping(process,a["timeout"])}
        elif operation=="qualification_cleanup":
            q=m.Qualification({"source_commits":{},"rust_test_name":m.RUST_TEST_NAME},b"{}",{},pathlib.Path(a["root"]))
            q.socket_dir=pathlib.Path(a["socket_dir"])
            q.vm=SimpleNamespace(process=process,process_group_stopped=False,socket_path=q.socket_dir/"api.sock")
            q._cleanup_socket_dir()
            q._cleanup_image()
            result={"image":str(q.image)}
        elif operation=="cleanup_all":
            for owned in processes.values():
                if owned.returncode is None:
                    try:
                        m.stop_process_group(owned,term_timeout=.1,kill_timeout=1)
                    except Exception:
                        try: os.killpg(owned.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                        owned.wait(timeout=2)
            for stream in streams: stream.close()
            result={}
        else:
            raise ValueError("unknown adapter operation")
    except Exception as exc:
        result={"error":str(exc),"error_type":type(exc).__name__}
    if process is not None:
        result["returncode"]=process.returncode
    print(json.dumps(result),flush=True)
`
