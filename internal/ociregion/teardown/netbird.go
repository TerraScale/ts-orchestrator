package teardown

import (
	"context"
	"errors"
	"io"
)

func (p *SDKProvider) teardown(ctx context.Context, plan Plan, apply bool, out io.Writer) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Region == "sa-saopaulo-1" {
		return errors.New("GRU teardown has no verified manager retirement and protected-backup destructive authority")
	}
	return Teardown(ctx, plan, p, apply, out)
}
