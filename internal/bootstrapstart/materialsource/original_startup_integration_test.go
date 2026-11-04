package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// These SDK/CAS/crypto scenarios qualify append mechanics only. They neither
// manufacture sealed actors/templates nor qualify the public serving path.
func TestOriginalStartupSDKAtomicAppend(t *testing.T) {
	f, clients, state, etag, archive := originalMaterialMechanicalFixture(t)
	publication, err := originalMaterialMechanicalProvision(t, f, clients, &state, &etag, archive)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	p := *state.Publication
	p.Result = new(publication)
	next.Publication = &p
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, next, etag)
	if err != nil {
		t.Fatal(err)
	}
	state = next
	reservation := originalReservationSHA(state)
	inventory := bytes.Clone(state.OriginalAdmissionInventory)
	completePublication := marshalOriginalPublication(state.Publication)
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	source, err := bootstrap.OriginalSourceBindingFor(wire)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PrivateKey(archive.Files["founder-ledger.key"])
	record, _, err := originalPublicationRecord(state, f.in)
	if err != nil {
		t.Fatal(err)
	}
	launch := bootstrap.OriginalLaunchIdentity{ActorOperationID: f.in.scope.InstallationID, InstanceOCID: f.in.scope.InstanceID, Create: foundation.CreateIdentity{Key: "controller-a", Region: f.in.config.Region, RequestDigest: f.in.scope.ActorRequestSHA256, RetryToken: strings.Repeat("c", 64)}, EvidenceSHA256: f.in.scope.ActorReadbackSHA256}
	// The launch and Link are signed DATA here. Full constructor and consumer
	// verification belongs to the independently sealed authority integration.
	link := bootstrap.RegionalLinkEvidence{SourceObjectKey: f.in.intent.SourceObject, SourceSHA256: state.Reference.SHA256, MaterialRecord: bytes.Clone(archive.Files["material.json"]), Journal: bytes.Clone(state.Publication.Journal), References: originalMechanicalReferences(publication)}
	next = state
	next.Startup = map[string][]byte{}
	for _, slot := range f.in.config.Slots {
		config := []byte("{\"controller\":\"" + slot.Name + "\"}")
		manifest := bootstrap.Manifest{SchemaVersion: 1, DeploymentID: record.Config.DeploymentID, Environment: record.Config.Environment, ClusterID: record.Config.ClusterID, Cell: oci.Region(f.in.scope.Cell), OCIRegion: record.Config.Region, Slot: slot.Name, SeedSlot: "controller-a", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}, ControllerConfig: config, ControllerConfigSHA256: digestWire(config)}
		binding := bootstrap.DerivedStartupBinding{SchemaVersion: 2, GrantSHA256: f.in.scope.GrantSHA256, TemplateSHA256: strings.Repeat("b", 64), SourceSHA256: state.Reference.SHA256, MaterialRecord: bytes.Clone(archive.Files["material.json"]), Manifest: manifest, Link: new(link), OriginalLaunch: new(launch), OriginalSource: new(source)}
		payload, err := trust.EncodePayload(binding)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, bootstrap.DerivedStartupScope(manifest), record.IssuedAt, record.IssuedAt.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		next.Startup[slot.Name], err = trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	before := bytes.Clone(f.state)
	partial := next
	partial.Startup = map[string][]byte{"controller-a": bytes.Clone(next.Startup["controller-a"])}
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, partial, etag); err == nil || !bytes.Equal(before, f.state) {
		t.Fatal("partial sibling set changed protected source")
	}
	combined := next
	combined.SeedCompletion, err = json.Marshal(seedCheckpoint{StartupSHA256: digestWire(next.Startup["controller-a"]), SourceSHA256: state.Reference.SHA256, GrantSHA256: f.in.scope.GrantSHA256, TemplateSHA256: strings.Repeat("b", 64), InstanceID: f.in.scope.InstanceID, Records: bootstrapstart.ExternalSeedCompletionRecords{ReceiptWire: []byte("receipt"), ResultWire: []byte("result"), CompletedHeadWire: []byte("head")}}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, combined, etag); err == nil || !bytes.Equal(before, f.state) {
		t.Fatal("seed completion shared its first startup CAS")
	}
	observed, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, next, etag)
	if err != nil {
		t.Fatal(err)
	}
	state = next
	recovered, recoveredETag, err := readOriginalState(t.Context(), clients.objects, f.in)
	if err != nil || recoveredETag != observed || len(recovered.Startup) != 3 || originalReservationSHA(recovered) != reservation || !bytes.Equal(recovered.OriginalAdmissionInventory, inventory) || !bytes.Equal(marshalOriginalPublication(recovered.Publication), completePublication) {
		t.Fatal("startup append changed completed33 custody or failed CAS readback", err)
	}
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, state, etag); err == nil {
		t.Fatal("stale CAS revised startup")
	}
	etag = observed
	before = bytes.Clone(f.state)
	for _, fault := range []string{
		"rollback",
	} {
		encoded, err := json.Marshal(state, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		var changed originalSourceState
		if err := json.Unmarshal(encoded, &changed); err != nil {
			t.Fatal(err)
		}
		switch fault {
		case "rollback":
			changed.Startup = nil
		case "changed signature":
			changed.Startup["controller-b"][len(changed.Startup["controller-b"])-2] ^= 1
		case "changed config":
			changed.Startup["controller-c"] = changed.Startup["controller-b"]
		case "seed before startup":
			changed.Startup = nil
			changed.SeedCompletion = []byte("{}")
		}
		if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, changed, etag); err == nil || !bytes.Equal(before, f.state) {
			t.Fatal("startup mutation accepted", fault)
		}
	}
	// Opaque completion bytes test only source retention, never ledger acceptance.
	checkpoint := seedCheckpoint{StartupSHA256: digestWire(state.Startup["controller-a"]), SourceSHA256: state.Reference.SHA256, GrantSHA256: f.in.scope.GrantSHA256, TemplateSHA256: strings.Repeat("b", 64), InstanceID: f.in.scope.InstanceID, Records: bootstrapstart.ExternalSeedCompletionRecords{ReceiptWire: []byte("receipt"), ResultWire: []byte("result"), CompletedHeadWire: []byte("head")}}
	state.SeedCompletion, err = json.Marshal(checkpoint, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	final, _, err := readOriginalState(t.Context(), clients.objects, f.in)
	if err != nil || originalReservationSHA(final) != reservation || !bytes.Equal(final.SeedCompletion, state.SeedCompletion) {
		t.Fatal("seed append changed custody", err)
	}
	before = bytes.Clone(f.state)
	final.SeedCompletion = nil
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, final, etag); err == nil || !bytes.Equal(before, f.state) {
		t.Fatal("seed completion rollback accepted")
	}
	replacement := state
	checkpoint.Records.ResultWire = []byte("another result")
	replacement.SeedCompletion, err = json.Marshal(checkpoint, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, replacement, etag); err == nil || !bytes.Equal(before, f.state) {
		t.Fatal("seed completion replacement accepted")
	}
	recoveredArchive, _, err := decodeOriginalCandidate(t.TempDir(), f.in, state, f.secret)
	clearArchive(recoveredArchive)
	if err != nil || f.creates != 1 || f.material.creates != 33 {
		t.Fatal("append changed original archive or rotated completed33", err)
	}
}

func originalMechanicalReferences(publication bootstrapmaterial.Publication) []bootstrap.SecretReference {
	var refs []bootstrap.SecretReference
	for _, ref := range publication.References {
		refs = append(refs, ref.Reference)
	}
	return refs
}
