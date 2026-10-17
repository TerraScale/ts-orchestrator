//go:build linux && amd64

// This executable is PID 1 in the disposable, networkless qualification VM.
package main

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/tests/source_renewal_vm/protocol"
	"golang.org/x/sys/unix"
)

func main() {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "guest init requires PID 1 and UID 0")
		os.Exit(70)
	}
	code := 70
	var config protocol.Guest
	err := run(&config, &code)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest init:", err)
		if code == 0 {
			code = 70
		}
	}
	fmt.Printf("\n%s%s:%d\n", protocol.ResultPrefix, config.ID, code)
	unix.Sync()
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		fmt.Fprintln(os.Stderr, "guest poweroff:", err)
	}
	for {
		_ = unix.Pause()
	}
}

func run(config *protocol.Guest, code *int) error {
	wire, err := os.ReadFile("/qa/guest.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(wire, config, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if len(config.ID) != 64 {
		return fmt.Errorf("missing sealed guest identity")
	}
	for _, m := range []struct{ source, target, kind string }{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"}, {"devpts", "/dev/pts", "devpts"},
		{"tmpfs", "/run", "tmpfs"}, {"tmpfs", "/tmp", "tmpfs"},
	} {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			return err
		}
		options := ""
		if m.target == "/tmp" {
			options = "mode=1777,size=2G"
		} else if m.target == "/run" {
			options = "mode=0755,size=128M"
		}
		if err := unix.Mount(m.source, m.target, m.kind, unix.MS_NOSUID, options); err != nil {
			return fmt.Errorf("guest mount %s: %w", m.target, err)
		}
	}
	for _, module := range config.Modules {
		if !strings.HasPrefix(module, "/modules/") || strings.Contains(module, "..") {
			return fmt.Errorf("unowned guest module path %q", module)
		}
		command := exec.Command("/sbin/kmod", "insmod", module)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("guest module %s: %w", module, err)
		}
	}
	for _, directory := range []string{"/dev/disk/by-uuid", "/var/lib", "/var/log", "/root", "/sys/fs/cgroup"} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	if err := os.Mkdir("/sys/fs/cgroup/init", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/sys/fs/cgroup/init/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return err
	}
	for _, directory := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/terrascale"} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(directory+"/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0); err != nil {
			return err
		}
	}
	// Let the fixture execute its real sudo/unshare branch and IMDS setup.
	fmt.Printf("%s%s\n", protocol.ReadyPrefix, config.ID)
	command := exec.Command("/bin/nice", "-n", "19", "/qa/app.test", "-test.run=^"+protocol.TestName+"$", "-test.count=1", "-test.parallel=1", "-test.timeout=205s", "-test.v")
	command.Env = []string{"HOME=/root", "PATH=/bin:/sbin:/usr/sbin", "LANG=C.UTF-8", "GOMAXPROCS=2"}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	err = command.Run()
	if command.ProcessState != nil {
		*code = command.ProcessState.ExitCode()
	}
	return err
}
