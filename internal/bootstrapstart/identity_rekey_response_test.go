package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

func responseInstallFixture(t *testing.T) (MaterialStore, VerifiedIdentityRekey, TrustInputs, []byte, []byte) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("response-key publication requires root:root")
	}
	root, err := os.MkdirTemp("/dev/shm", "ts774-response-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	store := MaterialStore{installedDirectory: filepath.Join(root, "installed"), stagingDirectory: filepath.Join(root, "staging"),
		serviceUID: 65534, serviceGID: 65534, allowUnsafeAncestors: true}
	for _, path := range []string{store.installedDirectory, store.stagingDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(store.installedDirectory, int(store.serviceUID), int(store.serviceGID)); err != nil {
		t.Fatal(err)
	}
	newKey := func() (string, []byte) {
		t.Helper()
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		return base64.StdEncoding.EncodeToString(public), []byte(base64.StdEncoding.EncodeToString(key))
	}
	previousPublic, previous := newKey()
	public, wire := newKey()
	identity := acceptedIdentityFixture(t)
	checkpoint, key, genesis := acceptedCheckpoint(t, identity, []byte("obsolete identity bytes are opaque"))
	for i := range checkpoint.Slots[0].MaterialReferences {
		ref := &checkpoint.Slots[0].MaterialReferences[i]
		if ref.TargetFile == identity.Slot+"-response.key" {
			ref.VersionNumber++
			ref.SHA256 = digest(wire)
		}
	}
	journal, inputs, accepted := identityRekeyJournalForCheckpoint(t, identity, []byte("obsolete identity bytes are opaque"), checkpoint, key, genesis)
	journal.HostObservation.PreviousResponseKey, journal.HostObservation.ResponseKey = previousPublic, public
	plan, err := identityrekey.BuildHostStateHandoffPlan(journal.HostObservation, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := identityrekey.SignHostStateHandoffPlan(plan, accepted.AcceptedAt, accepted.AcceptedAt.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	journal.HostPlanWire = envelopeWire(t, envelope)
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(envelope, inputs.Roots.Current, journal.HostObservation, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	resetEnvelope, err := trust.DecodeEnvelope(journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	var reset authority.IdentityReset
	if err := protocol.DecodeStrict(resetEnvelope.Payload, &reset, 512<<10); err != nil {
		t.Fatal(err)
	}
	reset.HostStatePlanSHA256 = hostPlan.Fingerprint()
	resetEnvelope, err = authority.SignIdentityReset(reset, accepted.AcceptedAt, accepted.AcceptedAt.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetWire = envelopeWire(t, resetEnvelope)
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.installedDirectory, identity.Slot+"-response.key")
	if err := os.WriteFile(path, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, int(store.serviceUID), int(store.serviceGID)); err != nil {
		t.Fatal(err)
	}
	return store, verified, inputs, wire, previous
}

func TestIdentityRekeyResponseKeyPublishesServiceOwnedExactReplacementAndRetries(t *testing.T) {
	store, verified, inputs, wire, previous := responseInstallFixture(t)
	defer clear(wire)
	defer clear(previous)
	path := filepath.Join(store.installedDirectory, verified.Accepted().Slot+"-response.key")
	if err := store.VerifyIdentityRekeyResponseKey(t.Context(), verified, inputs, wire, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, previous) {
		t.Fatal("preflight changed the installed signer")
	}
	clear(before)
	for range 2 {
		if err := store.InstallIdentityRekeyResponseKey(t.Context(), verified, inputs, wire, func(context.Context) error { return nil }, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	defer clear(actual)
	if err != nil || !bytes.Equal(actual, wire) {
		t.Fatal("exact root-authorized response signer was not published")
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil || stat.Uid != store.serviceUID || stat.Gid != store.serviceGID || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
		t.Fatal("response signer lost private service ownership")
	}
}
