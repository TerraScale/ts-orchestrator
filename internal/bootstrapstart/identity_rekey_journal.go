package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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

func (verified VerifiedIdentityRekey) IsVerified() bool { return verified.verified }
func (verified VerifiedIdentityRekey) Wire() []byte     { return bytes.Clone(verified.wire) }
func (verified VerifiedIdentityRekey) AcceptedRoots() trust.Keyring {
	roots := maps.Clone(verified.roots.Current)
	for key, value := range roots {
		roots[key] = bytes.Clone(value)
	}
	return roots
}
func (verified VerifiedIdentityRekey) Accepted() AcceptedIdentity { return verified.accepted.Clone() }
func (verified VerifiedIdentityRekey) Checkpoint() identityrekey.VerifiedIdentityCheckpoint {
	return verified.checkpoint
}
func (verified VerifiedIdentityRekey) HostPlan() identityrekey.VerifiedHostStateHandoffPlan {
	return verified.hostPlan
}
func (verified VerifiedIdentityRekey) Reset() authority.IdentityReset {
	reset := verified.reset
	reset.Records = slices.Clone(reset.Records)
	if reset.GlobalLease != nil {
		pin := *reset.GlobalLease
		reset.GlobalLease = &pin
	}
	return reset
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
func (verified VerifiedIdentityRekey) ResetEnvelope() (trust.Envelope, error) {
	if !verified.verified {
		return trust.Envelope{}, ErrIdentityRekeyJournal
	}
	return trust.DecodeEnvelope(verified.journal.ResetWire)
}
func (verified VerifiedIdentityRekey) Values() [][]byte {
	if !verified.verified {
		return nil
	}
	values := slices.Clone(verified.journal.Values)
	for i := range values {
		values[i] = bytes.Clone(values[i])
	}
	return values
}

// VerifyCurrent requires current proposal authority or independently rechecks
// the durable journal and authenticated commitment for exact installation replay.
func (verified VerifiedIdentityRekey) VerifyCurrent(inputs TrustInputs, now time.Time) (VerifiedIdentityRekey, error) {
	if !verified.verified {
		return VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	if verified.committedJS != nil {
		current, err := verifyIdentityRekeyJournal(verified.journal, inputs, verified.accepted.AcceptedAt, true)
		if err != nil {
			return VerifiedIdentityRekey{}, err
		}
		if _, _, err := verifyIdentityRekeyInstallPredecessor(verified.committedMarkers, current.journal, current, inputs, true); err != nil {
			return VerifiedIdentityRekey{}, err
		}
		envelope, err := current.ResetEnvelope()
		if err != nil {
			return VerifiedIdentityRekey{}, err
		}
		if _, err := authority.VerifyCommittedIdentityReset(verified.committedContext, verified.committedJS, envelope, inputs.Roots.Historical, current.ResetTarget()); err != nil {
			return VerifiedIdentityRekey{}, err
		}
		current.committedJS, current.committedContext, current.committedMarkers = verified.committedJS, verified.committedContext, verified.committedMarkers
		return current, nil
	}
	return verifyIdentityRekeyJournal(verified.journal, inputs, now, false)
}

// InstallationTime binds replayed material authorization to the independently
// committed transaction; uncommitted installation still needs current grants.
func (verified VerifiedIdentityRekey) InstallationTime(now time.Time) time.Time {
	if verified.verified && verified.committedJS != nil {
		return verified.accepted.AcceptedAt
	}
	return now
}

func (verified VerifiedIdentityRekey) InstallationRoots(inputs TrustInputs) trust.Keyring {
	if verified.verified && verified.committedJS != nil {
		return verified.AcceptedRoots()
	}
	return inputs.Roots.Current
}

// FinalizeIdentityRekeyJournal changes only the opaque lease predecessor and
// acceptance time after preparation. It never extends the reviewed authority.
func FinalizeIdentityRekeyJournal(verified VerifiedIdentityRekey, inputs TrustInputs, floor authority.IdentityResetFloor,
	key ed25519.PrivateKey, now time.Time,
) (IdentityRekeyJournal, error) {
	now = now.Round(0).UTC()
	current, err := verified.VerifyCurrent(inputs, now)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	if current.committedJS != nil || len(key) != ed25519.PrivateKeySize {
		return IdentityRekeyJournal{}, trust.ErrUntrustedKey
	}
	public := key.Public().(ed25519.PublicKey)
	id, err := trust.KeyID(public)
	if err != nil || !bytes.Equal(inputs.Roots.Current[id], public) {
		return IdentityRekeyJournal{}, trust.ErrUntrustedKey
	}
	reset := current.Reset()
	reset.LastSequence, reset.PreviousSequence, reset.PreviousSHA256 = floor.LastSequence, floor.PreviousSequence, floor.PreviousSHA256
	envelope, err := current.ResetEnvelope()
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	envelope, err = authority.SignIdentityReset(reset, now, envelope.ExpiresAt, key)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	journal := current.journal
	journal.ResetWire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	accepted, err := AcceptedIdentityFromCheckpoint(current.Checkpoint(), current.Accepted().Slot, now)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	journal.AcceptedWire, err = EncodeAcceptedIdentity(accepted)
	if err != nil {
		return IdentityRekeyJournal{}, err
	}
	if _, err := verifyIdentityRekeyJournal(journal, inputs, now, false); err != nil {
		return IdentityRekeyJournal{}, err
	}
	// Historical restart/completion must verify the new signature at acceptance.
	if _, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true); err != nil {
		return IdentityRekeyJournal{}, err
	}
	return journal, nil
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

// ReadIdentityRekeyJournal reports absence only for initial acceptance; a rekey
// requires its immutable journal even after shared completion.
func ReadIdentityRekeyJournal(accepted AcceptedIdentity) (VerifiedIdentityRekey, error) {
	if err := accepted.Validate(); err != nil {
		return VerifiedIdentityRekey{}, err
	}
	store := NewMarkerStore()
	if _, err := store.readAcceptedIdentityRekeyJournal(accepted); err != nil {
		return VerifiedIdentityRekey{}, err
	}
	inputs, err := LoadTrustInputs(accepted)
	if err != nil {
		return VerifiedIdentityRekey{}, fmt.Errorf("%w: load rekey trust inputs: %v", ErrIdentityRekeyJournal, err)
	}
	return store.verifiedIdentityRekey(accepted, inputs)
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

// WriteIdentityRekeyJournal publishes a verified, create-only recovery plan
// before installation. An exact retry succeeds; a different plan never replaces it.
func (store MarkerStore) WriteIdentityRekeyJournal(journal IdentityRekeyJournal, inputs TrustInputs,
	observe IdentityObservation, now time.Time,
) error {
	verified, err := verifyIdentityRekeyJournal(journal, inputs, now, false)
	if err != nil {
		return err
	}
	if _, err := verifyIdentityRekeyJournal(journal, inputs, verified.Accepted().AcceptedAt, true); err != nil {
		return err
	}
	if err := VerifyIdentityRekeyStagingLocalIdentity(verified, observe); err != nil {
		return err
	}
	wire, err := encodeIdentityRekeyJournal(journal)
	if err != nil {
		return err
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	old, err := store.readIdentityBytes(dir, markerName)
	if err != nil {
		return err
	}
	if digest(old) != journal.PreviousAcceptanceSHA256 && !bytes.Equal(old, journal.AcceptedWire) {
		return ErrAcceptancePredecessor
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".identity-rekey." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := unix.Fchmod(fd, 0o644); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != store.ownerUID ||
		store.ownerUID == 0 && stat.Gid != 0 || stat.Nlink != 1 {
		return ErrIdentityRekeyJournal
	}
	if count, err := file.Write(wire); err != nil {
		return err
	} else if count != len(wire) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := VerifyIdentityRekeyStagingLocalIdentity(verified, observe); err != nil {
		return err
	}
	old, err = store.readIdentityBytes(dir, markerName)
	if err != nil {
		return err
	}
	if digest(old) != journal.PreviousAcceptanceSHA256 && !bytes.Equal(old, journal.AcceptedWire) {
		return ErrAcceptancePredecessor
	}
	if err := unix.Renameat2(dir, temporary, dir, identityRekeyJournalName, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		existing, err := store.readIdentityRekeyJournal()
		if err != nil {
			return err
		}
		existingWire, err := encodeIdentityRekeyJournal(existing)
		if err != nil || !bytes.Equal(existingWire, wire) {
			return ErrIdentityRekeyJournal
		}
	}
	return unix.Fsync(dir)
}

// VerifyIdentityRekeyStagingLocalIdentity permits an absent node pin only while
// independently observing the store authorized by a verified root checkpoint.
func VerifyIdentityRekeyStagingLocalIdentity(verified VerifiedIdentityRekey, observe IdentityObservation) error {
	if !verified.IsVerified() || observe == nil {
		return ErrIdentityRekeyJournal
	}
	accepted := verified.Accepted()
	check := func() error {
		if err := verifyAcceptedStorePins(accepted.Store, map[string]string{"server-name": accepted.Store.ServerNameSHA256}); err != nil {
			return err
		}
		err := verifyAcceptedStorePins(accepted.Store, map[string]string{"node-identity.json": accepted.Store.NodeIdentitySHA256})
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := check(); err != nil {
		return err
	}
	broker, store, err := observe(accepted)
	if err != nil {
		return err
	}
	if broker != accepted.Broker || store != accepted.Store {
		return ErrAcceptedIdentity
	}
	return check()
}
