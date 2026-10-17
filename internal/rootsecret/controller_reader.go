package rootsecret

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/controllercredential"
	"github.com/nats-io/nats.go"
)

type ControllerReader = controllercredential.ControllerReader

func OpenControllerReader(ctx context.Context) (*ControllerReader, error) {
	return controllercredential.OpenControllerReader(ctx)
}

func ConnectControllerReader(ctx context.Context) (*nats.Conn, error) {
	return controllercredential.ConnectControllerReader(ctx)
}

func ConnectControllerReaderLease(ctx context.Context) (*nats.Conn, context.Context, error) {
	return controllercredential.ConnectControllerReaderLease(ctx)
}
