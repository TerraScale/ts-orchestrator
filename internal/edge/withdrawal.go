package edge

import (
	"context"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nlbhealth"
)

func (e *Edge) GuardWithdrawal(ctx context.Context, read func(context.Context) (time.Duration, error)) {
	e.withdrawal = read
	e.checkWithdrawal(ctx)
}

func (e *Edge) checkWithdrawal(ctx context.Context) time.Duration {
	window := nlbhealth.DrainWindow
	if e.withdrawal != nil {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var err error
		window, err = e.withdrawal(probe)
		if err != nil {
			window = nlbhealth.UnverifiedDrainWindow
			slog.Warn("NLB withdrawal policy unverified; retaining long drain", "error", err)
		}
	}
	e.withdrawalWindow.Store(int64(window))
	slog.Info("edge withdrawal policy checked", "window", window)
	return window
}
