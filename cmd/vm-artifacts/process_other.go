//go:build !linux

package main

import (
	"os"
	"os/exec"
)

func configureChildProcess(_ *exec.Cmd) {}

func interruptChildProcess(command *exec.Cmd) error {
	return command.Process.Signal(os.Interrupt)
}

func killChildProcess(command *exec.Cmd) error {
	return command.Process.Kill()
}
