package materialsource

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// These real SDK/CAS scenarios qualify publication mechanics. They never
// manufacture a sealed actor or qualify the fixed public actor constructor.
type originalMaterialSDK struct {
	target             bootstrapmaterial.VaultTarget
	record             bootstrapmaterial.Record
	files              map[string][]byte
	secrets            map[string]originalMaterialSecret
	creates            int
	fault              string
	faulted            bool
	sourceReadEntered  chan struct{}
	sourceReadCanceled chan struct{}
	sourceMutations    int
}

type originalMaterialSecret struct {
	id, name string
	body     []byte
}

func (f *originalMechanicalSDK) serveMaterial(w http.ResponseWriter, r *http.Request) bool {
	m := f.material
	if r.URL.Path == "/n/ns/b/gru-1-head/o/"+f.in.intent.SourceObject {
		if r.Method != http.MethodGet {
			m.sourceMutations++
		}
		if r.Method == http.MethodGet && m.sourceReadEntered != nil {
			m.sourceReadEntered <- struct{}{}
			<-r.Context().Done()
			m.sourceReadCanceled <- struct{}{}
			return true
		}
	}
	if r.URL.Path == "/20180608/secrets" && r.Method == http.MethodGet {
		name := r.URL.Query().Get("name")
		names, _ := bootstrapmaterial.OriginalPublicationSecretNames(f.in.config)
		found := false
		for _, allowed := range names {
			found = found || name == allowed
		}
		if r.Host != "vaults.sa-saopaulo-1.oci.oraclecloud.com" || !found || r.URL.Query().Get("vaultId") != m.target.VaultOCID || r.URL.Query().Get("compartmentId") != m.target.CompartmentOCID {
			f.t.Error("material LIST escaped exact query target")
		}
		items := []ocivault.SecretSummary{}
		if secret, ok := m.secrets[name]; ok {
			items = append(items, ocivault.SecretSummary{Id: new(secret.id), SecretName: new(name), CompartmentId: new(m.target.CompartmentOCID), VaultId: new(m.target.VaultOCID), LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
		}
		json.MarshalWrite(w, items)
		return true
	}
	if r.URL.Path == "/20180608/secrets" && r.Method == http.MethodPost {
		wire, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var request struct {
			CompartmentID string `json:"compartmentId"`
			VaultID       string `json:"vaultId"`
			KeyID         string `json:"keyId"`
			SecretName    string `json:"secretName"`
			SecretContent struct {
				Content string `json:"content"`
				Stage   string `json:"stage"`
			} `json:"secretContent"`
		}
		if err != nil || json.Unmarshal(wire, &request) != nil {
			f.t.Error("invalid SDK material create body", err)
			f.fail(w, 400)
			return true
		}
		if request.SecretName == f.in.intent.SourceSecretName {
			r.Body = io.NopCloser(bytes.NewReader(wire))
			return false
		}
		if r.Host != "vaults.sa-saopaulo-1.oci.oraclecloud.com" || request.CompartmentID != m.target.CompartmentOCID || request.VaultID != m.target.VaultOCID || request.KeyID != m.target.KMSKeyOCID || request.SecretContent.Stage != "CURRENT" {
			f.t.Error("material create used archive escrow or another target")
		}
		var state originalSourceState
		if json.Unmarshal(f.state, &state) != nil {
			f.t.Error("protected source unavailable")
			f.fail(w, 400)
			return true
		}
		journal, ok := originalPublicationJournalFor(state, f.in)
		if !ok {
			f.t.Error("material create preceded protected initial journal CAS")
			f.fail(w, 400)
			return true
		}
		var file bootstrapmaterial.File
		var matched bool
		for _, entry := range journal.Entries {
			if entry.Name != request.SecretName {
				continue
			}
			file, matched = originalPublicationFile(m.record, entry.FileName)
			if entry.SentAt.IsZero() || entry.Verified || entry.SecretOCID != "" || entry.RetryToken != r.Header.Get("opc-retry-token") {
				f.t.Error("material create preceded its exact durable retry/sent checkpoint")
			}
		}
		body, err := base64.StdEncoding.Strict().DecodeString(request.SecretContent.Content)
		if !matched || err != nil || !bytes.Equal(body, m.files[file.Name]) || digestWire(body) != file.SHA256 || int64(len(body)) != file.MaxBytes {
			f.t.Error("material create replaced authenticated archive bytes")
		}
		if _, exists := m.secrets[request.SecretName]; exists {
			f.t.Error("recovery recreated an existing material secret")
		}
		m.creates++
		id := fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.material%d", m.creates)
		m.secrets[request.SecretName] = originalMaterialSecret{id: id, name: request.SecretName, body: body}
		if m.fault == "lost material create" && !m.faulted {
			m.faulted = true
			f.fail(w, 503)
			return true
		}
		json.MarshalWrite(w, ocivault.Secret{Id: new(id)})
		return true
	}
	for _, secret := range m.secrets {
		if r.Method == http.MethodGet && r.URL.Path == "/20180608/secrets/"+secret.id {
			if r.Host != "vaults.sa-saopaulo-1.oci.oraclecloud.com" {
				f.t.Error("material metadata used another region")
			}
			json.MarshalWrite(w, ocivault.Secret{Id: new(secret.id), CompartmentId: new(m.target.CompartmentOCID), VaultId: new(m.target.VaultOCID), KeyId: new(m.target.KMSKeyOCID), SecretName: new(secret.name), CurrentVersionNumber: new(int64(1)), LifecycleState: ocivault.SecretLifecycleStateActive})
			return true
		}
		if r.Method == http.MethodGet && r.URL.Path == "/20190301/secretbundles/"+secret.id {
			if r.Host != "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com" || r.URL.Query().Get("versionNumber") != "1" || r.URL.Query().Get("stage") != "" {
				f.t.Error("material bundle escaped version1")
			}
			json.MarshalWrite(w, ocisecrets.SecretBundle{SecretId: new(secret.id), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(secret.body))}})
			return true
		}
	}
	return false
}

func originalMaterialMechanicalFixture(t *testing.T) (*originalMechanicalSDK, originalSourceClients, originalSourceState, string, materialSourceArchive) {
	t.Helper()
	in := originalMechanicalInputs(t)
	f, clients := newOriginalMechanicalSDK(t, in, "")
	directory := filepath.Join(t.TempDir(), "original")
	state, etag, body := pinMechanicalCandidate(t, in, clients, directory)
	defer clear(body)
	if _, err := clients.management.CreateSecret(ociclient.RequestContext(t.Context()), originalCreateRequest(state, body)); err != nil {
		t.Fatal(err)
	}
	recovered, id, err := readOriginalVault(t.Context(), clients, state)
	if err != nil || !bytes.Equal(recovered, body) {
		t.Fatal("actual archive readback", err)
	}
	clear(recovered)
	state.Reference = materialSourceReference{SecretOCID: id, SHA256: state.Candidate.SHA256, MaxBytes: state.Candidate.MaxBytes}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	archive, record, err := decodeOriginalCandidate(directory, in, state, body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearArchive(archive) })
	state.OriginalAdmissionInventory, err = originalInventory(in, state, archive, record)
	if err != nil {
		t.Fatal(err)
	}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..regional", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.regional", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.regional"}
	state.Publication = &originalMaterialPublicationState{Scope: region.OriginalMaterialPublicationScope{Target: target, PolicyID: "ocid1.policy.oc1..material", PolicyETag: "material-revision", PolicySHA256: strings.Repeat("a", 64), ReadbackSHA256: strings.Repeat("b", 64)}}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	f.material = &originalMaterialSDK{target: target, record: record, files: archive.Files, secrets: map[string]originalMaterialSecret{}}
	return f, clients, state, etag, archive
}

func originalMaterialMechanicalProvision(t *testing.T, f *originalMechanicalSDK, clients originalSourceClients, state *originalSourceState, etag *string, archive materialSourceArchive) (bootstrapmaterial.Publication, error) {
	t.Helper()
	directory := t.TempDir()
	// t.TempDir creates with 0777 & umask; material directories must be exactly 0700.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range archive.Files {
		if err := writeSourceFile(filepath.Join(directory, name), body); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.Publication.Journal) > 0 {
		if err := writeSourceFile(filepath.Join(directory, "publication.json"), state.Publication.Journal); err != nil {
			t.Fatal(err)
		}
	}
	publication, err := bootstrapmaterial.ProvisionDurable(t.Context(), directory, f.material.target, clients.management, clients.bundles, time.Now().UTC(), func(journal []byte) error {
		next := *state
		p := *state.Publication
		p.Journal = bytes.Clone(journal)
		next.Publication = &p
		observed, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, next, *etag)
		if err == nil {
			*state, *etag = next, observed
		}
		return err
	})
	if err == nil {
		if err := bootstrapmaterial.ValidatePublication(directory, publication, state.Publication.Journal); err != nil {
			t.Fatal("actual publication readback", err)
		}
	}
	return publication, err
}

func TestOriginalMaterialPublicationSDKDurableRecovery(t *testing.T) {
	for _, fault := range []string{
		"lost material create",
	} {
		t.Run(fault, func(t *testing.T) {
			f, clients, state, etag, archive := originalMaterialMechanicalFixture(t)
			originalInventoryWire := bytes.Clone(state.OriginalAdmissionInventory)
			originalBinding := originalReservationSHA(state)
			f.material.fault = fault
			publication, err := originalMaterialMechanicalProvision(t, f, clients, &state, &etag, archive)
			if fault != "" {
				if err == nil || !f.material.faulted || f.material.creates != 1 {
					t.Fatal("lost create did not retain exact uncertain send", err)
				}
				state, etag, err = readOriginalState(t.Context(), clients.objects, f.in)
				if err != nil {
					t.Fatal(err)
				}
				publication, err = originalMaterialMechanicalProvision(t, f, clients, &state, &etag, archive)
			}
			if err != nil || f.material.creates != 33 || len(publication.References) != 33 {
				t.Fatal("material publication did not recover all33 exact files", f.material.creates, err)
			}
			next := state
			p := *state.Publication
			p.Result = &publication
			next.Publication = &p
			etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, next, etag)
			if err != nil {
				t.Fatal(err)
			}
			state, observed, err := readOriginalState(t.Context(), clients.objects, f.in)
			if err != nil || observed != etag || !validOriginalPublication(state, f.in) || originalReservationSHA(state) != originalBinding || !bytes.Equal(state.OriginalAdmissionInventory, originalInventoryWire) {
				t.Fatal("publication changed archive custody/inventory or lacked independent CAS readback", err)
			}
			if _, err := originalMaterialMechanicalProvision(t, f, clients, &state, &etag, archive); err != nil || f.material.creates != 33 {
				t.Fatal("completed publication recovery rotated material", err)
			}
			recoveredArchive, _, err := decodeOriginalCandidate(t.TempDir(), f.in, state, f.secret)
			clearArchive(recoveredArchive)
			if err != nil || f.creates != 1 {
				t.Fatal("publication invalidated authentic archive candidate or replaced escrow", err)
			}
			before := bytes.Clone(f.state)
			for _, fault := range []string{
				"retry identity",
			} {
				wire, err := json.Marshal(state, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				var changed originalSourceState
				if err := json.Unmarshal(wire, &changed); err != nil {
					t.Fatal(err)
				}
				var journal originalPublicationJournal
				if err := json.Unmarshal(changed.Publication.Journal, &journal); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "drop publication":
					changed.Publication = nil
				case "drop journal":
					changed.Publication.Journal = nil
				case "retry identity":
					journal.Entries[0].RetryToken = "00000000-0000-4000-8000-000000000000"
				case "file name permutation":
					journal.Entries[0].Name, journal.Entries[1].Name = journal.Entries[1].Name, journal.Entries[0].Name
				case "version2":
					changed.Publication.Result.References[0].Reference.VersionNumber = 2
				case "wrong target":
					changed.Publication.Scope.Target.KMSKeyOCID = f.in.intent.Escrow.KMSKeyOCID
				case "duplicate secret":
					journal.Entries[1].SecretOCID = journal.Entries[0].SecretOCID
				}
				if changed.Publication != nil && fault != "drop journal" {
					changed.Publication.Journal, err = json.Marshal(journal)
				}
				if err != nil {
					t.Fatal(err)
				}
				if (fault == "file name permutation" || fault == "version2" || fault == "duplicate secret") && validOriginalPublication(changed, f.in) {
					t.Fatal("invalid per-file publication binding passed", fault)
				}
				if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, f.in, changed, etag); err == nil || !bytes.Equal(f.state, before) {
					t.Fatal("protected publication accepted retained-state mutation", fault)
				}
			}
		})
	}
}
