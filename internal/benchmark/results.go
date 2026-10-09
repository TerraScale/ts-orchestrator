package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const resultQueueSize = 256
const resultDrainTimeout = 30 * time.Second

func (r Runner) persistResults(ctx context.Context, runID string, stage int, pending <-chan Sample, out io.Writer) error {
	encoder := json.NewEncoder(out)
	for sample := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		saveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := r.Repository.SaveResult(saveCtx, runID, stage, sample)
		cancel()
		if err != nil {
			return fmt.Errorf("save benchmark result: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := encoder.Encode(sample); err != nil {
			return fmt.Errorf("stream benchmark result: %w", err)
		}
	}
	return nil
}
