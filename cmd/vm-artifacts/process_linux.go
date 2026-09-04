//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func configureChildProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func interruptChildProcess(command *exec.Cmd) error {
	return syscall.Kill(-command.Process.Pid, syscall.SIGINT)
}

func killChildProcess(command *exec.Cmd) error {
	return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}
