package client

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func ReconcileService(ctx context.Context, binary, expectedSHA256 string) error {
	command := exec.CommandContext(ctx, "bash", "-s", "--", binary, expectedSHA256)
	command.Stdin = strings.NewReader(serviceScript)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("reconcile NetBird service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
