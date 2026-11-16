// Package rootnetbird rederives public NET proposals from root-owned sources.
// The dedicated manager separately authenticates its broker reads before effects.
package rootnetbird

import (
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/nats.go/jetstream"
)

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	sources *Sources
}

// Sources retain the original root-created reader and accepted installation.
// A successor connection or credential generation requires a new runtime.
type Sources struct {
	JS           jetstream.JetStream
	Specs, Roots jetstream.KeyValue
	Leases       *authority.Reader
	Authority    *bootstrapstart.CurrentFounderAuthorityReader
	Accepted     bootstrapstart.AcceptedIdentity
	Credentials  *rootsecret.ControllerReader
}
