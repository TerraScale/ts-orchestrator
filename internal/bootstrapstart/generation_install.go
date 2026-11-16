package bootstrapstart

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
)

// A controller installs a published material generation (TS-668) in two
// halves. Its unprivileged process stages the chain, its slot's config and
// the files its slot holds in GenerationSpoolDirectory, and writes
// GenerationArmedFile there while the cell arms the slot. selfupdate prepare,
// root before every start of the controller unit, installs an armed stage.
// It trusts only root-signed content and the digests it pins, never the
// spool's owner.
const (
	// GenerationSpoolDirectory is the stager's directory, inside the
	// controller's state directory. selfupdate prepare mounts it in memory:
	// the staged files are secrets (TS-745).
	GenerationSpoolDirectory = "/var/lib/terrascale-orchestrator-controller/material-generation"
	// GenerationArmedFile holds the fingerprint of the spooled generation
	// the cell armed this slot for.
	GenerationArmedFile  = "armed"
	controllerConfigFile = "/etc/terrascale-orchestrator/controller.json"
)

// GenerationTarget is what a material generation must match on this
// controller: its accepted slot, material baseline, broker and deployment.
type GenerationTarget struct {
	Slot                     string
	AcceptanceSHA256         string
	Expected                 bootstrap.MaterialGenerationExpectation
	Broker                   identityrekey.BrokerIdentity
	MaterialGenerationSHA256 string
	ControllerConfigSHA256   string
}
