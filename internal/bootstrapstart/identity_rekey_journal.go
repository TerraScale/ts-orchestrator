package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

const identityRekeyJournalName = "identity-rekey.json"
const MaxIdentityRekeyJournalBytes = 4 << 20

var ErrIdentityRekeyJournal = errors.New("root-owned identity rekey journal is invalid")
var ErrIdentityRekeyLocalPending = errors.New("identity rekey local installation is incomplete")

// IdentityRekeyJournalPresent is only a routing check. Every object requires
// verification; damaged recovery state cannot authorize fresh installation.
func IdentityRekeyJournalPresent() (bool, error) {
	_, err := NewMarkerStore().readIdentityRekeyJournal()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, nil
}

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

func (verified VerifiedIdentityRekey) ResetTarget() authority.IdentityResetTarget {
	if !verified.verified {
		return authority.IdentityResetTarget{}
	}
	a := verified.accepted
	return authority.IdentityResetTarget{OperationID: a.OperationID, DeploymentID: a.DeploymentID,
		ClusterID: a.ClusterID, Scope: strings.ToLower(a.Cell), Environment: a.Environment,
		CheckpointSHA256: verified.checkpoint.Fingerprint(), HostStatePlanSHA256: verified.hostPlan.Fingerprint(),
		Replicas: verified.journal.Replicas}
}

func identityRekeyExpectation(journal IdentityRekeyJournal, accepted AcceptedIdentity) identityrekey.CheckpointExpectation {
	return identityrekey.CheckpointExpectation{OperationID: accepted.OperationID, DeploymentID: accepted.DeploymentID,
		ClusterID: accepted.ClusterID, Cell: accepted.Cell, Environment: accepted.Environment, SeedSlot: accepted.SeedSlot,
		ManagedMaterial: accepted.ManagedMaterial, MaterialGenerationSHA256: accepted.MaterialGenerationSHA256,
		Broker: accepted.Broker, Slot: identityrekey.SlotBinding{Slot: accepted.Slot, InstanceOCID: accepted.InstanceOCID,
			ImageOCID: accepted.ImageOCID, PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: accepted.PrimaryPrivateIP,
			Binary: accepted.Binary, Store: accepted.Store, ConfigSHA256: accepted.ConfigSHA256,
			MaterialReferences: accepted.MaterialReferences, LaunchMaterialSHA256: accepted.LaunchMaterialSHA256,
			PreviousMaterialSHA256:   journal.PreviousMaterialSHA256,
			PreviousAcceptanceSHA256: journal.PreviousAcceptanceSHA256}}
}

func verifyIdentityRekeyJournal(journal IdentityRekeyJournal, inputs TrustInputs, now time.Time, historical bool) (VerifiedIdentityRekey, error) {
	if journal.Version != 1 || !markerDigestRE.MatchString(journal.PreviousAcceptanceSHA256) ||
		identityrekey.ValidatePreviousMaterialPins(journal.PreviousMaterialSHA256) != nil ||
		journal.GenesisSHA256 != trust.RootSetDigest(inputs.Genesis) || !markerDigestRE.MatchString(journal.RootHead) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	accepted, err := DecodeAcceptedIdentity(journal.AcceptedWire)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	identity := trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Cell: strings.ToLower(accepted.Cell), Environment: accepted.Environment}
	if inputs.ChainIdentity != identity {
		return VerifiedIdentityRekey{}, trust.ErrScopeMismatch
	}
	currentRoots, err := trust.VerifyRootChain(inputs.Genesis, identity, inputs.Chain)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	chain, err := trust.DecodeRootChain(journal.RootChainWire)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	roots, err := trust.VerifyRootChain(inputs.Genesis, identity, chain)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	for _, keys := range []trust.Keyring{roots.Current, roots.Historical} {
		for id, key := range keys {
			keys[id] = bytes.Clone(key)
		}
	}
	if roots.Sequence != journal.RootSequence || roots.Head != journal.RootHead || currentRoots.Sequence < roots.Sequence ||
		len(inputs.Chain.Rotations) < len(chain.Rotations) {
		return VerifiedIdentityRekey{}, fmt.Errorf("%w: root rollback floor", ErrIdentityRekeyJournal)
	}
	prefix := trust.RootChain{Version: 1, Rotations: inputs.Chain.Rotations[:len(chain.Rotations)]}
	prefixWire, err := trust.EncodeRootChain(prefix)
	if err != nil || !bytes.Equal(prefixWire, journal.RootChainWire) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	// Current replay uses the currently adopted chain; historical acceptance uses
	// the exact chain independently retained by root at the accepted timestamp.
	verificationChain := chain
	verificationRoots := roots
	if !historical {
		verificationChain, verificationRoots = inputs.Chain, currentRoots
	}
	checkpoint, err := identityrekey.VerifyAcceptedIdentityCheckpoint(journal.CheckpointWire, inputs.Genesis,
		verificationChain, identityRekeyExpectation(journal, accepted), now)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	projected, err := AcceptedIdentityFromCheckpoint(checkpoint, accepted.Slot, accepted.AcceptedAt)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	projectedWire, err := EncodeAcceptedIdentity(projected)
	if err != nil || !bytes.Equal(projectedWire, journal.AcceptedWire) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	hostEnvelope, err := trust.DecodeEnvelope(journal.HostPlanWire)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, verificationRoots.Current, journal.HostObservation, now)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	envelope, err := trust.DecodeEnvelope(journal.ResetWire)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	verified := VerifiedIdentityRekey{journal: journal, accepted: accepted, checkpoint: checkpoint, hostPlan: hostPlan, roots: roots, verified: true}
	reset, err := authority.VerifyIdentityReset(envelope, verificationRoots.Current, verified.ResetTarget(), now)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	if err := hostPlan.MatchIdentityReset(reset); err != nil {
		return VerifiedIdentityRekey{}, err
	}
	if len(journal.Values) != len(reset.Records) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	for i, record := range reset.Records {
		value := journal.Values[i]
		if record.Action == authority.IdentityResetDeleteKV {
			if len(value) != 0 {
				return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
			}
		} else if len(value) == 0 || digest(value) != record.SHA256 {
			return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
		}
	}
	for i, record := range hostPlan.Records() {
		if !bytes.Equal(record.Value, journal.Values[i+3]) {
			return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
		}
	}
	verified.reset = reset
	// No accessor shares caller-editable byte slices with its verification result.
	wire, err := encodeIdentityRekeyJournal(journal)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	verified.wire = bytes.Clone(wire)
	verified.journal = IdentityRekeyJournal{}
	if err := protocol.DecodeStrict(wire, &verified.journal, MaxIdentityRekeyJournalBytes); err != nil {
		return VerifiedIdentityRekey{}, err
	}
	return verified, nil
}

func encodeIdentityRekeyJournal(journal IdentityRekeyJournal) ([]byte, error) {
	wire, err := protocol.EncodeJSON(journal)
	if err != nil || len(wire) == 0 || len(wire) > MaxIdentityRekeyJournalBytes {
		return nil, ErrIdentityRekeyJournal
	}
	return wire, nil
}

func (store MarkerStore) readIdentityRekeyJournal() (IdentityRekeyJournal, error) {
	return store.readIdentityRekeyJournalFile(identityRekeyJournalName)
}

func (store MarkerStore) readIdentityRekeyJournalFile(name string) (IdentityRekeyJournal, error) {
	dir, err := store.openDirectory()
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != store.ownerUID ||
		store.ownerUID == 0 && stat.Gid != 0 || stat.Mode&0o7777 != 0o644 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > MaxIdentityRekeyJournalBytes {
		return IdentityRekeyJournal{}, ErrIdentityRekeyJournal
	}
	wire, err := io.ReadAll(io.LimitReader(file, MaxIdentityRekeyJournalBytes+1))
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	var journal IdentityRekeyJournal
	if err := protocol.DecodeStrict(wire, &journal, MaxIdentityRekeyJournalBytes); err != nil {
		return IdentityRekeyJournal{}, err
	}
	canonical, err := encodeIdentityRekeyJournal(journal)
	if err != nil || !bytes.Equal(wire, canonical) {
		return IdentityRekeyJournal{}, ErrIdentityRekeyJournal
	}
	return journal, nil
}

func (store MarkerStore) verifiedIdentityRekey(accepted AcceptedIdentity, inputs TrustInputs) (VerifiedIdentityRekey, error) {
	if err := accepted.Validate(); err != nil {
		return VerifiedIdentityRekey{}, err
	}
	journal, err := store.readAcceptedIdentityRekeyJournal(accepted)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	if err != nil {
		return VerifiedIdentityRekey{}, err
	}
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil || !bytes.Equal(wire, journal.AcceptedWire) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyLocalPending
	}
	dir, err := store.openDirectory()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifiedIdentityRekey{}, ErrIdentityRekeyLocalPending
		}
		return VerifiedIdentityRekey{}, err
	}
	defer unix.Close(dir)
	installed, err := store.readIdentityBytes(dir, markerName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifiedIdentityRekey{}, ErrIdentityRekeyLocalPending
		}
		return VerifiedIdentityRekey{}, err
	}
	if !bytes.Equal(installed, journal.AcceptedWire) {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyLocalPending
	}
	return verified, nil
}

func (store MarkerStore) readAcceptedIdentityRekeyJournal(accepted AcceptedIdentity) (IdentityRekeyJournal, error) {
	journal, err := store.readIdentityRekeyJournal()
	if accepted.Origin == identityrekey.AcceptanceOriginRekey && errors.Is(err, os.ErrNotExist) {
		wire, encodeErr := EncodeAcceptedIdentity(accepted)
		if encodeErr != nil {
			return IdentityRekeyJournal{}, encodeErr
		}
		journal, err = store.readIdentityRekeyJournalFile(identityRekeyAcceptedJournalName(wire))
		if errors.Is(err, os.ErrNotExist) {
			return IdentityRekeyJournal{}, fmt.Errorf("%w: accepted rekey requires its journal", ErrIdentityRekeyJournal)
		}
	}
	return journal, err
}

func identityRekeyAcceptedJournalName(wire []byte) string {
	return "identity-rekey.accepted." + digest(wire) + ".json"
}

// CheckIdentityRekeyPrestart verifies root recovery input before material/config
// effects. Ordinary runtime also requires immutable shared reset completion.
func CheckIdentityRekeyPrestart(accepted AcceptedIdentity) error {
	if err := accepted.Validate(); err != nil {
		return err
	}
	store := NewMarkerStore()
	_, err := store.readAcceptedIdentityRekeyJournal(accepted)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	inputs, err := LoadTrustInputs(accepted)
	if err != nil {
		return err
	}
	_, err = store.verifiedIdentityRekey(accepted, inputs)
	return err
}
