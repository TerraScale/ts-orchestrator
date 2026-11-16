package bootstrapstart

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

const MaxIdentityRekeyJournalBytes = 4 << 20

var ErrIdentityRekeyJournal = errors.New("root-owned identity rekey journal is invalid")
var ErrIdentityRekeyLocalPending = errors.New("identity rekey local installation is incomplete")

// IdentityRekeyJournal is immutable public recovery input. Local commit is
// established by exact accepted bytes; shared completion lives in the control log.
type IdentityRekeyJournal struct {
	Version                  int                                `json:"version"`
	AcceptedWire             []byte                             `json:"accepted_wire"`
	PreviousAcceptanceSHA256 string                             `json:"previous_acceptance_sha256"`
	PreviousMaterialSHA256   map[string]string                  `json:"previous_material_sha256"`
	CheckpointWire           []byte                             `json:"checkpoint_wire"`
	ResetWire                []byte                             `json:"reset_wire"`
	HostPlanWire             []byte                             `json:"host_plan_wire"`
	HostObservation          identityrekey.HostStateObservation `json:"host_observation"`
	RootChainWire            []byte                             `json:"root_chain_wire"`
	GenesisSHA256            string                             `json:"genesis_sha256"`
	RootSequence             uint64                             `json:"root_sequence"`
	RootHead                 string                             `json:"root_head"`
	Replicas                 int                                `json:"replicas"`
	Values                   [][]byte                           `json:"values"`
}

// VerifiedIdentityRekey separates historical installation evidence from current
// mutation authority. VerifyCurrent is required before replaying pending effects.
type VerifiedIdentityRekey struct {
	journal          IdentityRekeyJournal
	accepted         AcceptedIdentity
	checkpoint       identityrekey.VerifiedIdentityCheckpoint
	reset            authority.IdentityReset
	hostPlan         identityrekey.VerifiedHostStateHandoffPlan
	roots            trust.VerifiedRoots
	verified         bool
	wire             []byte
	committedJS      jetstream.JetStream
	committedContext context.Context
	committedMarkers MarkerStore
}
