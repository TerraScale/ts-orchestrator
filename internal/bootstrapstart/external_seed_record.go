package bootstrapstart

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var (
	ErrExternalSeedRecord = errors.New("external seed signed record authority is invalid")
)

type ExternalSeedReservationRequest struct {
	Identity           BakedIdentity
	Anchor             bootstrap.VerifiedBootstrapAnchor
	Manifest           bootstrap.StartupAuthority
	ReviewedPlanSHA256 string
	CreateIdentity     string
	LedgerPrivate      ed25519.PrivateKey
	Now                time.Time
	ExpiresAt          time.Time
}

type ExternalSeedReservationRecords struct {
	IntentWire      []byte
	InitialHeadWire []byte
}

type ExternalSeedCompletionRequest struct {
	Identity          BakedIdentity
	Anchor            bootstrap.VerifiedBootstrapAnchor
	Manifest          bootstrap.StartupAuthority
	Roots             trust.Keyring
	State             bootstrap.SlotState
	Observation       InstanceObservation
	ObservedAt        time.Time
	ExpectedPrivateIP string
	RootPrivate       ed25519.PrivateKey
	LedgerPrivate     ed25519.PrivateKey
	ReuseReceiptWire  []byte
	Now               time.Time
	ExpiresAt         time.Time
}

type ExternalSeedCompletionRecords struct {
	ReceiptWire       []byte
	ResultWire        []byte
	CompletedHeadWire []byte
}
