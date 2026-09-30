package netbird

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// runCommand deliberately discards stderr and returns no subprocess error text:
// NetBird and OCI errors may contain authentication material.
func runCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	// NetBird accepts NB_/WT_ environment overrides even for explicit flags.
	// A fixed environment prevents redirecting enrollment or injecting keys.
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/root", "LANG=C"}
	command.WaitDelay = time.Second
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.overflow {
		clear(output.Bytes())
		return nil, errors.New("NetBird command failed")
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > 1<<20-output.Len() {
		output.overflow = true
		return len(data), nil
	}
	if output.overflow {
		return len(data), nil
	}
	return output.Buffer.Write(data)
}
