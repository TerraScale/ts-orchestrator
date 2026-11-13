package secretpreflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func Check(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "release", "preflight")
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("release preflight: %w: %s", errors.Join(ctx.Err(), err), output)
	}
	return nil
}
