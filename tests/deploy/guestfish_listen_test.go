package deploy_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/image"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestOfflineListenerChild(t *testing.T) {
	if os.Getenv("OFFLINE_LISTENER_CHILD") != "1" {
		return
	}
	<-time.After(30 * time.Second)
	os.Exit(0)
}
func TestOfflineListenerCommand(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	args := os.Args[i+1:]
	listen := slices.Contains(args, "--listen")
	if os.Getenv("OFFLINE_LISTENER_FAILURE") == "1" {
		if listen {
			os.Stdout.WriteString("GUESTFISH_PID=999999; export GUESTFISH_PID\n")
			os.Stderr.WriteString("daemon startup failed\n")
			os.Exit(0)
		}
		os.Stderr.WriteString("/tmp/.guestfish-0/socket-999999: No such file or directory\nguestfish: remote: looks like the server is not running\n")
		os.Exit(1)
	}
	if listen {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestOfflineListenerChild$")
		cmd.Env = append(os.Environ(), "OFFLINE_LISTENER_CHILD=1")
		cmd.Stderr = os.Stderr
		null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = null
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		null.Close()
		pid := strconv.Itoa(cmd.Process.Pid)
		if err := os.WriteFile(os.Getenv("GUESTFISH_CHILD_PID_FILE"), []byte(pid), 0600); err != nil {
			t.Fatal(err)
		}
		os.Stdout.WriteString("GUESTFISH_PID=" + pid + "; export GUESTFISH_PID\n")
		cmd.Process.Release()
		os.Exit(0)
	}
	if !slices.Equal(args, []string{"--remote", "exit"}) {
		t.Fatalf("unexpected remote command: %q", args)
	}
	os.Exit(0)
}

func listenerObservation(t *testing.T, failure bool) map[string]any {
	t.Helper()
	root := t.TempDir()
	pidFile := filepath.Join(root, "child.pid")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "guestfish"), []byte("#!/bin/sh\nGOMAXPROCS=2 GORACE=\"${GORACE:+$GORACE }atexit_sleep_ms=0\" exec "+shellQuote(exe)+" -test.run=^TestOfflineListenerCommand$ -- \"$@\"\n"), 0755)
	t.Cleanup(func() {
		b, err := os.ReadFile(pidFile)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(string(b))
		if err != nil {
			t.Fatal(err)
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Kill(); err != nil && !os.IsNotExist(err) && err != os.ErrProcessDone {
			t.Logf("kill child: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	flag := "success"
	env := append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "GUESTFISH_CHILD_PID_FILE="+pidFile)
	if failure {
		flag = "failure"
		env = append(env, "OFFLINE_LISTENER_FAILURE=1")
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNativeListenerObservation$", "--", flag)
	cmd.Env = append(env, "GOMAXPROCS=2", "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("listener did not return within five seconds: %v\n%s", err, stderr.String())
	}
	var r map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("invalid observation: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	return r
}
func TestOfflinePersistentChildStderrDoesNotHoldLaunchOpen(t *testing.T) {
	r := listenerObservation(t, false)
	equal(t, r["closed"], true)
	equal(t, r["error"], nil)
}
func TestOfflineListenerFailureRetainsDaemonStderr(t *testing.T) {
	r := listenerObservation(t, true)
	equal(t, r["closed"], true)
	message, ok := r["error"].(string)
	if !ok {
		t.Fatalf("missing listener error: %#v", r)
	}
	contains(t, message, "/socket-999999: No such file or directory")
	contains(t, message, "listener pid=999999 state=exited")
	contains(t, message, "listener stderr: daemon startup failed")
}

func TestNativeListenerObservation(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 {
		return
	}
	failure := os.Args[i+1] == "failure"
	guest, err := image.NewGuest(t.Context(), "unused.qcow2", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var observation any
	if failure {
		_, err = guest.Kind("/")
		if err != nil {
			observation = err.Error()
		}
	}
	if err := guest.Close(failure); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{"closed": true, "error": observation})
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout.Write(append(b, '\n'))
	os.Exit(0)
}
