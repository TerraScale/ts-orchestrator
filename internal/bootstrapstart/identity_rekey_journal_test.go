package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func identityRekeyJournalFixture(t *testing.T) (IdentityRekeyJournal, TrustInputs, AcceptedIdentity) {
	t.Helper()
	journal, inputs, accepted, _ := identityRekeyJournalFixtureWithKey(t)
	return journal, inputs, accepted
}

func identityRekeyJournalFixtureWithKey(t *testing.T) (IdentityRekeyJournal, TrustInputs, AcceptedIdentity, ed25519.PrivateKey) {
	t.Helper()
	identity := acceptedIdentityFixture(t)
	previous := []byte("obsolete identity bytes are opaque")
	checkpoint, key, genesis := acceptedCheckpoint(t, identity, previous)
	journal, inputs, accepted := identityRekeyJournalForCheckpoint(t, identity, previous, checkpoint, key, genesis)
	return journal, inputs, accepted, key
}

func identityRekeyJournalForCheckpoint(t *testing.T, identity AcceptedIdentity, previous []byte, checkpoint identityrekey.AcceptedIdentityCheckpoint, key ed25519.PrivateKey, genesis trust.Keyring) (IdentityRekeyJournal, TrustInputs, AcceptedIdentity) {
	t.Helper()
	verified := verifyAcceptedCheckpoint(t, checkpoint, key, genesis, identity.AcceptedAt)
	accepted, err := AcceptedIdentityFromCheckpoint(verified, identity.Slot, identity.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	acceptedWire, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		t.Fatal(err)
	}
	responseKey := func() string {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(public)
	}
	observed := identityrekey.HostStateObservation{OperationID: accepted.OperationID, DeploymentID: accepted.DeploymentID,
		ClusterID: accepted.ClusterID, Cell: accepted.Cell, Environment: accepted.Environment, CheckpointSHA256: verified.Fingerprint(),
		EpochFloor: 2, Epoch: 3, PreviousResponseKey: responseKey(), ResponseKey: responseKey(),
		AgentsStoppedAt: accepted.AcceptedAt.Add(-time.Minute), ObservedAt: accepted.AcceptedAt.Add(-time.Second)}
	observed.Preconditions = []identityrekey.HostStatePrecondition{{Bucket: "TS_HOST_STATE", Key: "retirement-cutover." + strings.ToLower(accepted.Cell)}}
	plan, err := identityrekey.BuildHostStateHandoffPlan(observed, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	hostEnvelope, err := identityrekey.SignHostStateHandoffPlan(plan, accepted.AcceptedAt, accepted.AcceptedAt.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, genesis, observed, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{[]byte("root-pinned service set"), []byte(`{"version":1,"rotations":[]}`), []byte("root-pinned material chain")}
	reset := authority.IdentityReset{Version: 1, OperationID: accepted.OperationID, DeploymentID: accepted.DeploymentID,
		ClusterID: accepted.ClusterID, Scope: "gru", Environment: accepted.Environment, CheckpointSHA256: verified.Fingerprint(),
		HostStatePlanSHA256: hostPlan.Fingerprint(), LastSequence: 10, PreviousSequence: 9, PreviousSHA256: digest(previous), EpochFloor: 2, Epoch: 3}
	for i, pin := range [][2]string{{"TS_SERVICE_SET", "current"}, {"TS_TRUST_ROOTS", "chain"}, {"TS_TRUST_ROOTS", "material-generations"}} {
		reset.Records = append(reset.Records, authority.IdentityResetRecord{Action: authority.IdentityResetReplaceKV,
			Bucket: pin[0], Key: pin[1], SHA256: digest(values[i])})
	}
	reset.Records = append(reset.Records, hostPlan.IdentityResetRecords()...)
	values = append(values, hostPlan.Values()...)
	resetEnvelope, err := authority.SignIdentityReset(reset, accepted.AcceptedAt, accepted.AcceptedAt.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	resetWire, err := trust.EncodeEnvelope(resetEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	hostWire, err := trust.EncodeEnvelope(hostEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	chain := trust.RootChain{Version: 1}
	chainWire, err := trust.EncodeRootChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	chainIdentity := trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Cell: "gru", Environment: accepted.Environment}
	roots, err := trust.VerifyRootChain(genesis, chainIdentity, chain)
	if err != nil {
		t.Fatal(err)
	}
	inputs := TrustInputs{ChainIdentity: chainIdentity, Genesis: genesis, Chain: chain, Roots: roots}
	journal := IdentityRekeyJournal{Version: 1, AcceptedWire: acceptedWire, PreviousMaterialSHA256: maps.Clone(checkpoint.Slots[0].PreviousMaterialSHA256), PreviousAcceptanceSHA256: digest(previous),
		CheckpointWire: verified.Wire(), ResetWire: resetWire, HostPlanWire: hostWire, HostObservation: observed,
		RootChainWire: chainWire, GenesisSHA256: trust.RootSetDigest(genesis), RootSequence: roots.Sequence, RootHead: roots.Head,
		Replicas: 3, Values: values}
	return journal, inputs, accepted
}

func TestIdentityRekeyJournalSeparatesHistoricalEvidenceAndMutation(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.IsVerified() || verified.Checkpoint().Slot() != accepted.Slot || verified.ResetTarget().DeploymentID != accepted.DeploymentID {
		t.Fatal("lost verified binding")
	}
	if _, err := verified.VerifyCurrent(inputs, accepted.AcceptedAt.Add(2*time.Hour)); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired mutation proof: %v", err)
	}
	if _, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true); err != nil {
		t.Fatalf("historical completed install cannot reboot: %v", err)
	}
	values := verified.Values()
	values[0][0] ^= 1
	journal.Values[0][0] ^= 1
	if bytes.Equal(values[0], verified.Values()[0]) || bytes.Equal(journal.Values[0], verified.Values()[0]) {
		t.Fatal("verification retained caller-owned bytes")
	}
}

func TestIdentityRekeyVerifiedWireDistinguishesChangedReset(t *testing.T) {
	journal, inputs, accepted, key := identityRekeyJournalFixtureWithKey(t)
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := protocol.EncodeJSON(journal)
	if !bytes.Equal(verified.Wire(), expected) {
		t.Fatal("verified journal did not preserve its exact canonical bytes")
	}
	copy := verified.Wire()
	copy[0] = '['
	if !bytes.Equal(verified.Wire(), expected) || len((VerifiedIdentityRekey{}).Wire()) != 0 {
		t.Fatal("verified bytes were mutable or present without verification")
	}
	reset := verified.Reset()
	reset.LastSequence++
	envelope, _ := verified.ResetEnvelope()
	replacement, err := authority.SignIdentityReset(reset, envelope.IssuedAt, envelope.ExpiresAt, key)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetWire, err = trust.EncodeEnvelope(replacement)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(changed.Wire(), verified.Wire()) || !bytes.Equal(changed.journal.AcceptedWire, verified.journal.AcceptedWire) {
		t.Fatal("changed reset was not distinguished under the same accepted identity")
	}
}

func TestIdentityRekeyFinalizationPreservesReviewedPinsAndHistoricalRecovery(t *testing.T) {
	journal, inputs, accepted, key := identityRekeyJournalFixtureWithKey(t)
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	floor := authority.IdentityResetFloor{LastSequence: 25, PreviousSequence: 24, PreviousSHA256: digest([]byte("opaque latest renewal"))}
	now := accepted.AcceptedAt.Add(3 * time.Minute)
	final, err := FinalizeIdentityRekeyJournal(verified, inputs, floor, key, now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := verifyIdentityRekeyJournal(final, inputs, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Accepted().AcceptedAt.Equal(now) || current.Reset().LastSequence != floor.LastSequence ||
		current.Reset().PreviousSequence != floor.PreviousSequence || current.Reset().PreviousSHA256 != floor.PreviousSHA256 {
		t.Fatal("final floor/time were not bound")
	}
	originalEnvelope, _ := verified.ResetEnvelope()
	finalEnvelope, _ := current.ResetEnvelope()
	if !finalEnvelope.IssuedAt.Equal(now) || !finalEnvelope.ExpiresAt.Equal(originalEnvelope.ExpiresAt) {
		t.Fatal("final signing extended reviewed authority")
	}
	before, _ := accepted.AcceptanceSHA256()
	after, _ := current.Accepted().AcceptanceSHA256()
	if before != after || bytes.Equal(final.AcceptedWire, journal.AcceptedWire) {
		t.Fatal("timestamp changed the acyclic pins or failed to change exact acceptance")
	}
	if _, err := verifyIdentityRekeyJournal(final, inputs, current.Accepted().AcceptedAt, true); err != nil {
		t.Fatalf("final historical recovery failed: %v", err)
	}
	if _, err := verifyIdentityRekeyJournal(final, inputs, accepted.AcceptedAt, true); err == nil {
		t.Fatal("early review time admitted a later signature")
	}
	normalized := final
	normalized.ResetWire, normalized.AcceptedWire = journal.ResetWire, journal.AcceptedWire
	want, _ := protocol.EncodeJSON(journal)
	got, _ := protocol.EncodeJSON(normalized)
	if !bytes.Equal(got, want) {
		t.Fatal("finalizer changed independently reviewed checkpoint, host plan or values")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		name  string
		key   ed25519.PrivateKey
		now   time.Time
		floor authority.IdentityResetFloor
	}{{"wrong root", other, now, floor}, {"expired", key, now.Add(2 * time.Hour), floor},
		{"invalid floor", key, now, authority.IdentityResetFloor{LastSequence: 1, PreviousSequence: 2, PreviousSHA256: floor.PreviousSHA256}}} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := FinalizeIdentityRekeyJournal(verified, inputs, test.floor, test.key, test.now); err == nil {
				t.Fatal("invalid late authorization admitted")
			}
		})
	}
}

func TestIdentityRekeyJournalRejectsChangedRootedInputs(t *testing.T) {
	for _, name := range []string{"version", "checkpoint", "reset", "host facts", "target", "value", "genesis", "root floor", "replicas"} {
		t.Run(name, func(t *testing.T) {
			journal, inputs, accepted := identityRekeyJournalFixture(t)
			switch name {
			case "version":
				journal.Version = 2
			case "checkpoint":
				journal.CheckpointWire[0] = ' '
			case "reset":
				journal.ResetWire[0] = ' '
			case "host facts":
				journal.HostObservation.Epoch++
			case "target":
				accepted.PrimaryPrivateIP = "10.251.0.19"
				accepted.ControllerBindings[0].PrimaryPrivateIP = accepted.PrimaryPrivateIP
				journal.AcceptedWire, _ = EncodeAcceptedIdentity(accepted)
			case "value":
				journal.Values[0][0] ^= 1
			case "genesis":
				journal.GenesisSHA256 = digest([]byte("other genesis"))
			case "root floor":
				journal.RootSequence++
			case "replicas":
				journal.Replicas = 2
			}
			if _, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true); err == nil {
				t.Fatal("accepted a changed root-bound transaction")
			}
		})
	}
}

func TestIdentityRekeyJournalRetainsIndependentRootKeys(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range []trust.Keyring{inputs.Genesis, verified.AcceptedRoots()} {
		for _, key := range keys {
			key[0] ^= 1
		}
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.VerifyIdentityReset(envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
		t.Fatalf("caller mutation changed retained trust: %v", err)
	}
}

func TestIdentityRekeyJournalPublicationAndLocalCommit(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	store := testMarkerStore(t)
	path := filepath.Join(store.directory, markerName)
	if err := os.WriteFile(path, []byte("obsolete identity bytes are opaque"), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
			t.Fatal(err)
		}
	}
	wrong := accepted.Clone()
	wrong.AcceptedAt = wrong.AcceptedAt.Add(time.Second)
	if _, err := store.verifiedIdentityRekey(wrong, inputs); !errors.Is(err, ErrIdentityRekeyLocalPending) {
		t.Fatalf("uncommitted local target: %v", err)
	}
	if _, err := store.verifiedIdentityRekey(accepted, inputs); !errors.Is(err, ErrIdentityRekeyLocalPending) {
		t.Fatalf("old on-disk acceptance authorized local startup: %v", err)
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceIdentity(verified.Checkpoint(), accepted.Slot, accepted.AcceptedAt, acceptedObservation); err != nil {
		t.Fatal(err)
	}
	installed, err := store.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.verifiedIdentityRekey(installed, inputs); err != nil {
		t.Fatalf("committed recovery plan: %v", err)
	}
	// The local file records no shared completion; a process must still read the
	// immutable authority completion before acquiring or exposing normal effects.
	wire, err := os.ReadFile(filepath.Join(store.directory, identityRekeyJournalName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("completed")) || bytes.Contains(wire, []byte(`"phase"`)) {
		t.Fatal("journal invented local shared-completion authority")
	}
}

func TestIdentityRekeyJournalRejectsResetIssuedAfterAcceptanceBeforeEffects(t *testing.T) {
	journal, inputs, accepted, key := identityRekeyJournalFixtureWithKey(t)
	envelope, err := trust.DecodeEnvelope(journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	var candidate authority.IdentityReset
	if err := protocol.DecodeStrict(envelope.Payload, &candidate, 512<<10); err != nil {
		t.Fatal(err)
	}
	envelope, err = authority.SignIdentityReset(candidate, accepted.AcceptedAt.Add(time.Second), envelope.ExpiresAt, key)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetWire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	store := testMarkerStore(t)
	observed := false
	observe := func(a AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		observed = true
		return acceptedObservation(a)
	}
	if err := store.WriteIdentityRekeyJournal(journal, inputs, observe, accepted.AcceptedAt.Add(2*time.Second)); err == nil || observed {
		t.Fatalf("unusable historical journal reached observation: observed=%t, error=%v", observed, err)
	}
	if _, err := store.readIdentityRekeyJournal(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unusable journal was published: %v", err)
	}
}

func TestIdentityRekeyJournalRefusesIndirectAndNoncanonicalFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "whitespace", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			journal, _, _ := identityRekeyJournalFixture(t)
			store := testMarkerStore(t)
			wire, err := protocol.EncodeJSON(journal)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.directory, identityRekeyJournalName)
			if err := os.WriteFile(path, wire, 0o644); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Rename(path, path+".other"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".other", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".other"); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "whitespace":
				if err := os.WriteFile(path, append([]byte(" "), wire...), 0o644); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(path, bytes.Replace(wire, []byte(`{"version":`), []byte(`{"phase":"complete","version":`), 1), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.readIdentityRekeyJournal(); err == nil {
				t.Fatal("accepted unsafe journal file")
			}
		})
	}
}

func TestIdentityRekeyStagingMissingNodePinCannotAuthorizeRestart(t *testing.T) {
	journal, inputs, accepted := identityRekeyJournalFixture(t)
	store := testMarkerStore(t)
	if err := os.WriteFile(filepath.Join(store.directory, markerName), []byte("obsolete identity bytes are opaque"), 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(accepted.Store.Directory, "node-identity.json")
	if err := os.Remove(nodePath); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(nodePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging created a node pin: %v", err)
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAcceptedLocalIdentity(accepted, acceptedObservation); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary admission accepted missing pin: %v", err)
	}
	if err := store.ReplaceIdentity(verified.Checkpoint(), accepted.Slot, accepted.AcceptedAt, acceptedObservation); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accepted publication accepted missing pin: %v", err)
	}
	wire, err := os.ReadFile(filepath.Join(store.directory, markerName))
	if err != nil || string(wire) != "obsolete identity bytes are opaque" {
		t.Fatalf("failed publication changed predecessor: %q, %v", wire, err)
	}
}

func TestIdentityRekeyStagingRefusesUnprovenOrChangedNode(t *testing.T) {
	for _, kind := range []string{"unverified proof", "foreign observation", "missing server", "symlink node", "wrong node", "late wrong node", "late predecessor"} {
		t.Run(kind, func(t *testing.T) {
			journal, inputs, accepted := identityRekeyJournalFixture(t)
			store := testMarkerStore(t)
			previousPath := filepath.Join(store.directory, markerName)
			if err := os.WriteFile(previousPath, []byte("obsolete identity bytes are opaque"), 0o644); err != nil {
				t.Fatal(err)
			}
			nodePath := filepath.Join(accepted.Store.Directory, "node-identity.json")
			if err := os.Remove(nodePath); err != nil {
				t.Fatal(err)
			}
			observe := acceptedObservation
			switch kind {
			case "unverified proof":
				if err := VerifyIdentityRekeyStagingLocalIdentity(VerifiedIdentityRekey{}, observe); err == nil {
					t.Fatal("unverified proof authorized staging")
				}
				return
			case "foreign observation":
				observe = func(identity AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					identity.Store.RaftNodeID = "foreign1"
					return identity.Broker, identity.Store, nil
				}
			case "missing server":
				if err := os.Remove(filepath.Join(accepted.Store.Directory, "server-name")); err != nil {
					t.Fatal(err)
				}
			case "symlink node":
				if err := os.Symlink(nodePath+"-missing", nodePath); err != nil {
					t.Fatal(err)
				}
			case "wrong node":
				if err := os.WriteFile(nodePath, []byte("foreign pin"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "late wrong node", "late predecessor":
				calls := 0
				observe = func(identity AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					calls++
					if calls == 2 {
						path, mode := nodePath, os.FileMode(0o600)
						if kind == "late predecessor" {
							path, mode = previousPath, 0o644
						}
						if err := os.WriteFile(path, []byte("foreign pin"), mode); err != nil {
							t.Fatal(err)
						}
					}
					return acceptedObservation(identity)
				}
			}
			if err := store.WriteIdentityRekeyJournal(journal, inputs, observe, accepted.AcceptedAt); err == nil {
				t.Fatal("unproven or changed store authorized staging")
			}
			if _, err := os.Lstat(filepath.Join(store.directory, identityRekeyJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed staging published journal: %v", err)
			}
		})
	}
}
