package swarmruntime

import "context"

// canceledAsRetry returns the bare context error when the agent canceled the
// operation (it does on every task update). SwarmKit retries only an unwrapped
// context.Canceled; a wrapped one failed every long image pull as fatal.
func canceledAsRetry(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
