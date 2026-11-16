package rootsecret

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
)

// ControllerReader retains the actual connection, original lifetime and signed
// credential snapshot together. Its private fields cannot admit caller sources.
type ControllerReader struct {
	conn     *nats.Conn
	lease    context.Context
	snapshot controllerReaderSnapshot
}

type controllerReaderSnapshot struct {
	accepted bootstrapstart.AcceptedIdentity
	chain    []byte
	config   []byte
	refs     map[string]bootstrap.SecretReference
	nats     natscell.Config
	expires  time.Time
}
