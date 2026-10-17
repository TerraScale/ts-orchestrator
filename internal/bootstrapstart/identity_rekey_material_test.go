package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func identityRekeyMaterialFixture(t *testing.T) (*generationInstall, MaterialStore, VerifiedIdentityRekey, TrustInputs, []byte, map[string][]byte, MarkerStore) {
	t.Helper()
	return identityRekeyMaterialFixtureWithPredecessor(t, "", true)
}

func identityRekeyMaterialFixtureWithPredecessor(t *testing.T, predecessor string, rotateBaseline bool) (*generationInstall, MaterialStore, VerifiedIdentityRekey, TrustInputs, []byte, map[string][]byte, MarkerStore) {
	t.Helper()
	install := newGenerationInstall(t)
	membership := func() []byte {
		user, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := user.PublicKey()
		seed, _ := user.Seed()
		defer clear(seed)
		claim := jwt.NewUserClaims(id)
		claim.Expires = time.Now().Add(time.Hour).Unix()
		raw, err := claim.Encode(install.material.System)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := jwt.FormatUserConfig(raw, seed)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	oldMembership := membership()
	install.write("membership.creds", oldMembership)
	install.accepted.MaterialReferences = append(install.accepted.MaterialReferences, bootstrap.SecretReference{
		Purpose: bootstrap.SecretRegionalShared, TargetFile: "membership.creds", SHA256: digest(oldMembership),
		SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.membership", VersionNumber: 1, MaxBytes: bootstrap.MaxSecretBytes})
	response := func() (string, []byte) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(private)
		return base64.StdEncoding.EncodeToString(public), []byte(base64.StdEncoding.EncodeToString(private))
	}
	oldResponsePublic, oldResponse := response()
	newResponsePublic, newResponse := response()
	install.write(install.accepted.Slot+"-response.key", oldResponse)
	for i := range install.accepted.MaterialReferences {
		if install.accepted.MaterialReferences[i].TargetFile == install.accepted.Slot+"-response.key" {
			install.accepted.MaterialReferences[i].SHA256 = digest(oldResponse)
		}
	}
	wire, files := install.signedGeneration()
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("old material chain")
	if predecessor != "" && predecessor != "opaque" {
		oldGeneration := generation
		install.accepted.Broker.AccountSigner = oldGeneration.AccountSigner
		for name, content := range files {
			install.write(name, content)
		}
		if predecessor == "foreign deployment" {
			oldGeneration.DeploymentID = "00000000006GRRF84JEVN9TX7M"
		}
		if predecessor == "broken link" {
			oldGeneration.Generation = 2
			oldGeneration.Previous = digest([]byte("missing generation"))
		}
		_, foreignKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		oldEnvelope, err := bootstrap.SignMaterialGeneration(oldGeneration, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), foreignKey)
		clear(foreignKey)
		if err != nil {
			t.Fatal(err)
		}
		old, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{oldEnvelope})
		if err != nil {
			t.Fatal(err)
		}
		install.accepted.MaterialGenerationSHA256, err = trust.Fingerprint(oldEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		if predecessor == "missing baseline" {
			install.accepted.MaterialGenerationSHA256 = digest([]byte("absent old baseline"))
		}
	}
	previous, err := EncodeAcceptedIdentity(install.accepted)
	if err != nil {
		t.Fatal(err)
	}
	if predecessor == "opaque" {
		previous = []byte("exact root-pinned obsolete identity")
	}
	accepted := install.accepted.Clone()
	accepted.MaterialGenerationSHA256, err = trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted.Broker.AccountSigner = generation.AccountSigner
	refs := materialReferences(accepted, nil)
	for name := range refs {
		if files[name] == nil {
			files[name] = install.read(name)
		}
	}
	for _, reference := range generation.Secrets {
		refs[reference.TargetFile] = reference
	}
	rotated := []string{accepted.Slot + "-response.key"}
	files[accepted.Slot+"-response.key"] = newResponse
	if rotateBaseline {
		files["route-password"] = []byte("fresh-checkpoint-route-password")
		files["membership.creds"] = membership()
		rotated = append(rotated, "route-password", "membership.creds")
	}
	for _, name := range rotated {
		ref := refs[name]
		ref.VersionNumber++
		ref.SHA256 = digest(files[name])
		refs[name] = ref
	}
	accepted.MaterialReferences = nil
	for reference := range maps.Values(refs) {
		accepted.MaterialReferences = append(accepted.MaterialReferences, reference)
	}
	checkpoint, _, _ := acceptedCheckpoint(t, accepted, previous)
	checkpoint.Slots[0].PreviousMaterialSHA256 = map[string]string{"installed": digest(old), "durable": digest(old)}
	checkpoint.MaterialGenerationSHA256 = accepted.MaterialGenerationSHA256
	checkpoint.Slots[0].MaterialReferences = accepted.MaterialReferences
	journal, inputs, accepted := identityRekeyJournalForCheckpoint(t, accepted, previous, checkpoint, install.rootKey, install.roots)
	journal.HostObservation.PreviousResponseKey, journal.HostObservation.ResponseKey = oldResponsePublic, newResponsePublic
	plan, err := identityrekey.BuildHostStateHandoffPlan(journal.HostObservation, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	hostEnvelope, err := identityrekey.SignHostStateHandoffPlan(plan, accepted.AcceptedAt, accepted.AcceptedAt.Add(time.Hour), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	journal.HostPlanWire = envelopeWire(t, hostEnvelope)
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, inputs.Roots.Current, journal.HostObservation, accepted.AcceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	journal.Values[2] = wire
	envelope, err := trust.DecodeEnvelope(journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	var reset authority.IdentityReset
	if err := protocol.DecodeStrict(envelope.Payload, &reset, 512<<10); err != nil {
		t.Fatal(err)
	}
	reset.HostStatePlanSHA256 = hostPlan.Fingerprint()
	reset.Records[2].SHA256 = digest(wire)
	envelope, err = authority.SignIdentityReset(reset, envelope.IssuedAt, envelope.ExpiresAt, install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	journal.ResetWire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	store := install.store()
	copyDir := t.TempDir()
	if err := os.Chmod(copyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store.chainCopy = filepath.Join(copyDir, MaterialGenerationsFile)
	install.write(MaterialGenerationsFile, old)
	if err := os.WriteFile(store.chainCopy, old, 0o644); err != nil {
		t.Fatal(err)
	}
	markers := testMarkerStore(t)
	if err := os.WriteFile(filepath.Join(markers.directory, markerName), previous, 0o644); err != nil {
		t.Fatal(err)
	}
	return install, store, verified, inputs, wire, files, markers
}

func TestIdentityRekeyMaterialReplacesOnlyExactOpaquePredecessors(t *testing.T) {
	for _, fault := range []string{"none", "installed", "durable", "symlink", "hardlink", "unverified", "expired", "missing baseline", "extra target", "source expiry", "canceled"} {
		t.Run(fault, func(t *testing.T) {
			install, store, verified, inputs, wire, files, markers := identityRekeyMaterialFixture(t)
			now := time.Now().UTC()
			before := install.read("ca.pem")
			if err := store.AdoptGeneration(install.target(), install.roots, wire, files, nil, now); err == nil {
				t.Fatal("ordinary adoption admitted opaque predecessor")
			}
			switch fault {
			case "installed":
				install.write(MaterialGenerationsFile, []byte("foreign installed bytes"))
			case "durable":
				if err := os.WriteFile(store.chainCopy, []byte("foreign durable bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(store.chainCopy); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(install.dir, MaterialGenerationsFile), store.chainCopy); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(store.chainCopy, store.chainCopy+".link"); err != nil {
					t.Fatal(err)
				}
			case "unverified":
				verified = VerifiedIdentityRekey{}
			case "expired":
				now = now.Add(2 * time.Hour)
			case "missing baseline":
				delete(files, "membership.creds")
			case "extra target":
				files["unknown.key"] = []byte("not checkpoint-authorized")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			expired := false
			beforeEffect := func(context.Context) error {
				if fault == "source expiry" {
					expired = true
				}
				if fault == "canceled" {
					cancel()
				}
				return nil
			}
			sourceLive := func() error {
				if expired {
					return ErrMaterial
				}
				return nil
			}
			err := store.adoptIdentityRekeyGeneration(ctx, markers, verified, inputs, files, nil, beforeEffect, sourceLive, now)
			if (err == nil) != (fault == "none") {
				t.Fatalf("opaque predecessor %s: %v", fault, err)
			}
			if fault == "none" {
				for name, want := range files {
					if !bytes.Equal(install.read(name), want) {
						t.Fatalf("full target baseline %s was not published", name)
					}
				}
				for _, path := range []string{filepath.Join(install.dir, MaterialGenerationsFile), store.chainCopy} {
					actual, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(actual, wire) {
						t.Fatal("exact rooted target did not replace both copies")
					}
				}
			} else if !bytes.Equal(before, install.read("ca.pem")) || install.staged() {
				t.Fatal("refused predecessor changed material or created a stage")
			}
		})
	}
}

func TestIdentityRekeyMaterialRecoversAfterDurableCopyAndPartialRename(t *testing.T) {
	install, store, verified, inputs, wire, files, markers := identityRekeyMaterialFixture(t)
	stagePath := filepath.Join(install.dir, generationStaging)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := unix.Open(stagePath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stage)
	for name, content := range files {
		if err := store.writeStaged(stage, name, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.writeStaged(stage, MaterialGenerationsFile, wire); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.chainCopy, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "route-password", "membership.creds", verified.Accepted().Slot + "-response.key"} {
		if err := os.Rename(filepath.Join(stagePath, name), filepath.Join(install.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := store.finishIdentityRekeyMaterialAdoption(t.Context(), markers, verified, inputs, install.configPath, func(context.Context) error { return nil }, func() error { return nil }, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if install.staged() || !bytes.Equal(install.read(MaterialGenerationsFile), wire) {
		t.Fatal("recovery did not finish the exact rooted target")
	}
	for name, want := range files {
		if !bytes.Equal(install.read(name), want) {
			t.Fatalf("recovery omitted full target baseline %s", name)
		}
	}
}
