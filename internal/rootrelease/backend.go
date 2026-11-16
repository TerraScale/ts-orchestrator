// Package rootrelease publishes release telemetry from root-observed admission
// and current upstream runtime state. Socket callers supply selectors only.
package rootrelease

import (
	"context"
	"errors"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
)

var ErrPending = errors.New("root container status observation is pending")

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	sources *Sources
}

// Sources are actual root-created regional readers, never child pointers or
// child-provided callbacks. Bind is called once after the root broker opens.
type Sources struct {
	JS        jetstream.JetStream
	Fleet     oci.FleetObserver
	Node      *swarmruntime.Node
	Intents   *delivery.Service
	Specs     jetstream.KeyValue
	Roots     jetstream.KeyValue
	Leases    *authority.Reader
	Hosts     *host.Reader
	Authority *bootstrapstart.CurrentFounderAuthorityReader
	Accepted  bootstrapstart.AcceptedIdentity

	ContainerProfiles interface {
		ReadContainerProfile(context.Context, string) ([]byte, error)
	}
}
