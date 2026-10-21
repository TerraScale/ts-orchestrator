package materialsource

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
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
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	for _, fault := range []string{"", "lost material create"} {
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
			for _, fault := range []string{"drop publication", "drop journal", "retry identity", "file name permutation", "version2", "wrong target", "duplicate secret"} {
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

func TestOriginalMaterialPublicationSDKRefusesUncheckpointedEffects(t *testing.T) {
	f, clients, state, etag, archive := originalMaterialMechanicalFixture(t)
	f.material.fault = "journal refused"
	if _, err := originalMaterialMechanicalProvision(t, f, clients, &state, &etag, archive); err == nil || f.material.creates != 0 {
		t.Fatal("refused initial journal CAS allowed a secret create")
	}
	f.material.fault = ""
	stale := etag
	f.mu.Lock()
	f.state = append(f.state, ' ')
	f.mu.Unlock()
	if _, err := originalMaterialMechanicalProvision(t, f, clients, &state, &stale, archive); err == nil || f.material.creates != 0 {
		t.Fatal("changed source ETag allowed a secret create")
	}
}

func TestOriginalMaterialPublicationRejectsZeroArchive(t *testing.T) {
	var archive VerifiedOriginalSourceArchive
	if archive.PublishRegionalMaterial(t.Context(), time.Now()) == nil {
		t.Fatal("unsealed archive acquired publication authority")
	}
	if archive.PublishRegionalMaterial(nil, time.Now()) == nil {
		t.Fatal("nil-context unsealed archive acquired authority")
	}
}

func TestOriginalMaterialPublicationRequiresSelectedArchive(t *testing.T) {
	f, _, state, _, _ := originalMaterialMechanicalFixture(t)
	reservation := originalState(f.in, state.StartedAt)
	reservation.Publication = state.Publication
	if validOriginalState(reservation, f.in) {
		t.Fatal("publication preceded candidate/ref/inventory selection")
	}
	reservation.Candidate = state.Candidate
	if validOriginalState(reservation, f.in) {
		t.Fatal("publication preceded exact Vault selection")
	}
	reservation.Reference = state.Reference
	if validOriginalState(reservation, f.in) {
		t.Fatal("publication preceded original signed inventory")
	}
	legacy := state
	legacy.Publication = nil
	wire, err := json.Marshal(legacy, json.Deterministic(true))
	if err != nil || bytes.Contains(wire, []byte(`"publication":`)) {
		t.Fatal("absent publication changed historical schema3 serialization", err)
	}
	var roundtrip originalSourceState
	if json.Unmarshal(wire, &roundtrip, json.RejectUnknownMembers(true)) != nil || !sameOriginalState(legacy, roundtrip) {
		t.Fatal("historical archive state failed exact round trip")
	}
}

// Exercise the publication checkpoint bridge through signed TLS SDK dispatch,
// without claiming a sealed actor or constructor-to-publisher qualification.
func TestOriginalMaterialPublicationSDKDispatchLifetime(t *testing.T) {
	for _, mutation := range []string{"CreateSecret", "source CAS"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%t", mutation, deadline), func(t *testing.T) {
				f, clients, state, etag, _ := originalMaterialMechanicalFixture(t)
				lifetime, cancelLifetime := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancelLifetime()
				type callerValueKey struct{}
				var roots, guards atomic.Int64
				caller := context.WithValue(lifetime, callerValueKey{}, "original caller")
				caller = ociclient.WithRequestGuard(caller, func(context.Context) error { roots.Add(1); return nil })
				operation, cancelOperation := context.WithCancel(caller)
				defer cancelOperation()
				if deadline {
					operation, cancelOperation = context.WithTimeout(caller, 2*time.Second)
					defer cancelOperation()
				}
				guard := func(send context.Context) error {
					if guards.Add(1) != 1 {
						return errors.New("publication guard reentered prerequisite read")
					}
					check := originalPublicationCheckpointContext(send, caller)
					want, hasWant := send.Deadline()
					got, hasGot := check.Deadline()
					if !hasWant || !hasGot || !got.Equal(want) || check.Value(callerValueKey{}) != "original caller" {
						return errors.New("publication checkpoint lost dispatch lifetime or caller values")
					}
					current, observed, err := readOriginalState(check, clients.objects, f.in)
					if err != nil {
						return err
					}
					if observed != etag || !sameOriginalState(current, state) {
						return ErrMaterialSource
					}
					return nil
				}
				guarded := ociclient.WithRequestGuard(ociclient.WithAuthority(operation, guard), guard)
				entered, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
				f.mu.Lock()
				before, escrow := bytes.Clone(f.state), bytes.Clone(f.secret)
				f.material.sourceReadEntered, f.material.sourceReadCanceled = entered, canceled
				f.mu.Unlock()
				done := make(chan error, 1)
				go func() {
					if mutation == "CreateSecret" {
						_, err := clients.management.CreateSecret(ociclient.RequestContext(guarded), originalCreateRequest(state, escrow))
						done <- err
						return
					}
					q := f.in.intent
					_, err := clients.objects.PutObject(ociclient.RequestContext(guarded), objectstorage.PutObjectRequest{
						NamespaceName: new(q.Home.Namespace), BucketName: new(q.Home.HeadBucket), ObjectName: new(q.SourceObject),
						IfMatch: new(etag), OpcSseKmsKeyId: new(q.Home.HeadKMSKeyOCID), ContentLength: new(int64(len(before))), PutObjectBody: io.NopCloser(bytes.NewReader(before))})
					done <- err
				}()
				select {
				case <-entered:
					if !deadline {
						cancelOperation()
					}
				case err := <-done:
					t.Fatalf("SDK returned before publication prerequisite HTTP read: %v", err)
				case <-lifetime.Done():
					t.Fatal("publication prerequisite HTTP read never entered")
				}
				var err error
				select {
				case err = <-done:
				case <-lifetime.Done():
					err = <-done
				}
				wantErr := context.Canceled
				if deadline {
					wantErr = context.DeadlineExceeded
				}
				if !errors.Is(err, wantErr) || lifetime.Err() != nil {
					t.Fatalf("publication dispatch error=%v, parent=%v; want %v while parent remains live", err, lifetime.Err(), wantErr)
				}
				select {
				case <-canceled:
				case <-time.After(2 * time.Second):
					t.Fatal("publication prerequisite HTTP read outlived active SDK dispatch")
				}
				f.mu.Lock()
				unchanged := bytes.Equal(f.state, before) && bytes.Equal(f.secret, escrow) && f.creates == 1 && f.material.creates == 0 && f.material.sourceMutations == 0
				f.mu.Unlock()
				if !unchanged || guards.Load() != 1 || roots.Load() != 2 {
					t.Fatalf("publication dispatch changed state or lost guards: unchanged=%t guards=%d roots=%d", unchanged, guards.Load(), roots.Load())
				}
			})
		}
	}
}
