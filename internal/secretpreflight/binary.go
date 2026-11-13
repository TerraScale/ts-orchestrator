package secretpreflight

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func Check(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "vault", "check-services")
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("release secret preflight: %w: %s", err, output)
	}
	return nil
}
