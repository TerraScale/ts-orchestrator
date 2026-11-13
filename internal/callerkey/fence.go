package callerkey

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type dispatchKey struct{}

func checkDispatch(ctx context.Context) error {
	intent, ok := ctx.Value(dispatchKey{}).(*Intent)
	if !ok {
		return errors.New("private write requires a dispatch fence")
	}
	if intent.acknowledged.IsZero() || monotonicNow().Sub(intent.acknowledged) >= dispatchBound {
		return errors.New("private dispatch bound elapsed; run caller-key recover")
	}
	if intent.Operation == "activate" && !operatorNow().Before(intent.validUntil) {
		return errors.New("pending key no longer has more than 30 days remaining; run caller-key recover")
	}
	return ctx.Err()
}

func privateWrite(ctx context.Context, intent *Intent, write func(context.Context) error) error {
	ctx = context.WithValue(ctx, dispatchKey{}, intent)
	if err := checkDispatch(ctx); err != nil {
		return err
	}
	ctx = ociclient.WithRequestGuard(ctx, checkDispatch)
	writeCtx, cancel := context.WithTimeout(ctx, privateRequestTimeout)
	defer cancel()
	return write(writeCtx)
}
