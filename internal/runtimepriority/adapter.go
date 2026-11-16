package runtimepriority

import (
	"context"
)

// Adapter transports immutable requests; all evidence is checked by Runner.
type Adapter struct {
	SSH           func(context.Context, Object, string, string, Object) (Object, error)
	HTTPS         func(context.Context, Object, string, string, string, []byte) ([]byte, error)
	OperatorHosts func(context.Context, Object) (string, error)
}
