package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
