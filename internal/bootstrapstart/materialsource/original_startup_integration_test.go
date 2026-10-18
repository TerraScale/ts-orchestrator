package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
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
	for _, fault := range []string{"rollback", "changed signature", "changed config", "seed before startup"} {
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

func TestOriginalStartupRejectsUnsealedArchive(t *testing.T) {
	var archive VerifiedOriginalSourceArchive
	if _, _, _, err := archive.OriginalStartup(t.Context(), time.Now()); !errors.Is(err, ErrMaterialSource) {
		t.Fatal("unsealed startup accepted", err)
	}
	if _, err := archive.OriginalStartupReferences(t.Context()); !errors.Is(err, ErrMaterialSource) {
		t.Fatal("unsealed references accepted", err)
	}
	if _, err := archive.BindOriginalStartup(t.Context(), bootstrap.VerifiedStartupTemplate{}, bootstrap.VerifiedStartupLink{}, map[string][]byte{}, time.Now()); !errors.Is(err, ErrMaterialSource) {
		t.Fatal("unsealed startup binding accepted", err)
	}
	if _, err := archive.PrepareOriginalSeed(t.Context(), bootstrap.DerivedStartupAuthority{}); !errors.Is(err, ErrMaterialSource) {
		t.Fatal("unsealed seed accepted", err)
	}
	if _, err := bootstrapmaterial.GenerateOriginalLink(t.Context(), bootstrap.VerifiedStartupTemplate{}, "", "", "", filepath.Join(t.TempDir(), "link"), time.Now()); err == nil {
		t.Fatal("unsealed original Link generator accepted")
	}
	if _, err := bootstrapmaterial.GenerateOriginalSpokeLink(t.Context(), bootstrap.VerifiedStartupTemplate{}, "", "", bootstrapmaterial.Record{}, "", filepath.Join(t.TempDir(), "spoke"), time.Now()); err == nil {
		t.Fatal("unsealed original spoke generator accepted")
	}
}

func TestOrdinaryLinkPreservesDeploymentBoundary(t *testing.T) {
	in := originalMechanicalInputs(t)
	now := time.Now().UTC().Add(-2 * time.Second)
	root := t.TempDir()
	home, spoke := filepath.Join(root, "home"), filepath.Join(root, "spoke")
	if _, err := bootstrapmaterial.Generate(home, in.config, now); err != nil {
		t.Fatal(err)
	}
	cfg := in.config
	cfg.Cell, cfg.Region, cfg.ClusterID, cfg.DeploymentID = "sfo", "us-sanjose-1", "00000000000000000000000002", "00000000000000000000000003"
	recipient, err := bootstrapmaterial.Generate(spoke, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	homeLink := filepath.Join(root, "home-link")
	if _, err := bootstrapmaterial.GenerateLink(home, home, homeLink, homeLink, now.Add(time.Second)); err != nil {
		t.Fatal("ordinary home positive control", err)
	}
	if _, err := bootstrapmaterial.GenerateLink(spoke, home, homeLink, filepath.Join(root, "spoke-link"), now.Add(time.Second)); err == nil {
		t.Fatal("ordinary Link admitted distinct deployments")
	}
	metadata, err := json.Marshal(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapmaterial.GenerateSpokeLink(home, homeLink, recipient, digestWire(metadata), filepath.Join(root, "spoke-public"), now.Add(time.Second)); err == nil {
		t.Fatal("ordinary public-recipient generator admitted distinct deployments")
	}
	names, err := bootstrapmaterial.OriginalLinkPublicationSecretNames(in.config)
	if err != nil || len(names) != 8 {
		t.Fatal("home exact leaf roster", err)
	}
	for _, name := range names {
		if strings.Contains(name, "issuer-link") {
			t.Fatal("home signer leaked into leaf scope")
		}
	}
}

func originalMechanicalReferences(publication bootstrapmaterial.Publication) []bootstrap.SecretReference {
	var refs []bootstrap.SecretReference
	for _, ref := range publication.References {
		refs = append(refs, ref.Reference)
	}
	return refs
}

func TestOriginalLinkEightLeafSDKJournalRecovery(t *testing.T) {
	in := originalMechanicalInputs(t)
	_, clients := newOriginalMechanicalSDK(t, in, "")
	root := t.TempDir()
	home, linkDirectory := filepath.Join(root, "home"), filepath.Join(root, "link")
	now := time.Now().UTC().Add(-2 * time.Second)
	if _, err := bootstrapmaterial.Generate(home, in.config, now); err != nil {
		t.Fatal(err)
	}
	record, err := bootstrapmaterial.GenerateLink(home, home, linkDirectory, linkDirectory, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	names, err := bootstrapmaterial.OriginalLinkPublicationSecretNames(record.Config)
	if err != nil {
		t.Fatal(err)
	}
	target := in.intent.Escrow
	var mu sync.Mutex
	secrets := map[string]originalMaterialSecret{}
	var journal []byte
	revision, creates := 0, 0
	lost := false
	fail := func(w http.ResponseWriter, status int) {
		w.WriteHeader(status)
		io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"native Link primitive fixture"}`)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Error("Link SDK request was not signed")
		}
		objectPath := "/n/ns/b/gru-1-head/o/link-journal"
		if r.URL.Path == objectPath {
			switch r.Method {
			case http.MethodGet:
				if revision == 0 {
					fail(w, 404)
					return
				}
				w.Header().Set("ETag", fmt.Sprintf("link-%d", revision))
				w.Write(journal)
			case http.MethodPut:
				if revision == 0 && r.Header.Get("If-None-Match") != "*" || revision != 0 && r.Header.Get("If-Match") != fmt.Sprintf("link-%d", revision) {
					fail(w, 412)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				var next originalPublicationJournal
				if err != nil || json.Unmarshal(body, &next, json.RejectUnknownMembers(true)) != nil || next.Target != target || len(next.Entries) != 8 {
					t.Error("invalid protected Link journal")
					fail(w, 400)
					return
				}
				for i, entry := range next.Entries {
					if entry.Name != names[i] || entry.FileName == "issuer-link.seed" {
						t.Error("Link journal escaped finite leaf roster")
					}
				}
				journal = bytes.Clone(body)
				revision++
				w.Header().Set("ETag", fmt.Sprintf("link-%d", revision))
			default:
				fail(w, 400)
			}
			return
		}
		if r.URL.Path == "/20180608/secrets" && r.Method == http.MethodGet {
			name := r.URL.Query().Get("name")
			allowed := false
			for _, want := range names {
				allowed = allowed || name == want
			}
			if !allowed || r.URL.Query().Get("vaultId") != target.VaultOCID || r.URL.Query().Get("compartmentId") != target.CompartmentOCID {
				t.Error("Link LIST escaped scope")
				fail(w, 400)
				return
			}
			items := []ocivault.SecretSummary{}
			if secret, ok := secrets[name]; ok {
				items = append(items, ocivault.SecretSummary{Id: new(secret.id), SecretName: new(secret.name), CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
			}
			json.MarshalWrite(w, items)
			return
		}
		if r.URL.Path == "/20180608/secrets" && r.Method == http.MethodPost {
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
			wire, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var saved originalPublicationJournal
			if err != nil || json.Unmarshal(wire, &request) != nil || json.Unmarshal(journal, &saved) != nil || request.CompartmentID != target.CompartmentOCID || request.VaultID != target.VaultOCID || request.KeyID != target.KMSKeyOCID {
				t.Error("Link create lacks exact durable journal target")
				fail(w, 400)
				return
			}
			matched := false
			for _, entry := range saved.Entries {
				if entry.Name != request.SecretName {
					continue
				}
				expected, err := os.ReadFile(filepath.Join(linkDirectory, entry.FileName))
				if err != nil {
					t.Error(err)
				}
				body, err := base64.StdEncoding.Strict().DecodeString(request.SecretContent.Content)
				if err != nil || !bytes.Equal(body, expected) || entry.SentAt.IsZero() || entry.RetryToken != r.Header.Get("opc-retry-token") {
					t.Error("Link create preceded exact sent checkpoint or changed bytes")
				}
				clear(expected)
				matched = true
				if _, exists := secrets[entry.Name]; exists {
					t.Error("Link recovery recreated an existing leaf")
				}
				creates++
				secrets[entry.Name] = originalMaterialSecret{id: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.link%d", creates), name: entry.Name, body: body}
			}
			if !matched {
				t.Error("Link create escaped finite leaf roster")
				fail(w, 400)
				return
			}
			if !lost {
				lost = true
				fail(w, 503)
				return
			}
			json.MarshalWrite(w, ocivault.Secret{Id: new(secrets[request.SecretName].id)})
			return
		}
		for _, secret := range secrets {
			if r.Method == http.MethodGet && r.URL.Path == "/20180608/secrets/"+secret.id {
				json.MarshalWrite(w, ocivault.Secret{Id: new(secret.id), CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), KeyId: new(target.KMSKeyOCID), SecretName: new(secret.name), CurrentVersionNumber: new(int64(1)), LifecycleState: ocivault.SecretLifecycleStateActive})
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/20190301/secretbundles/"+secret.id {
				if r.URL.Query().Get("versionNumber") != "1" {
					t.Error("Link recovery read other than version one")
				}
				json.MarshalWrite(w, ocisecrets.SecretBundle{SecretId: new(secret.id), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(secret.body))}})
				return
			}
		}
		fail(w, 404)
	}))
	defer server.Close()
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() {
		t.Fatal("native Link SDK fixture needs loopback TLS")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("Link fixture denies plaintext")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, listener.String())
	}
	defer transport.CloseIdleConnections()
	for _, client := range []*common.BaseClient{&clients.objects.BaseClient, &clients.management.BaseClient, &clients.bundles.BaseClient} {
		client.HTTPClient = &http.Client{Transport: transport}
	}
	etag := ""
	persist := func(wire []byte) error {
		request := objectstorage.PutObjectRequest{NamespaceName: new("ns"), BucketName: new("gru-1-head"), ObjectName: new("link-journal"), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire))}
		if etag == "" {
			request.IfNoneMatch = new("*")
		} else {
			request.IfMatch = new(etag)
		}
		if _, err := clients.objects.PutObject(ociclient.RequestContext(t.Context()), request); err != nil {
			return err
		}
		response, err := clients.objects.GetObject(ociclient.RequestContext(t.Context()), objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("gru-1-head"), ObjectName: new("link-journal")})
		if err != nil {
			return err
		}
		defer response.Content.Close()
		readback, err := io.ReadAll(io.LimitReader(response.Content, 1<<20))
		if err != nil || !bytes.Equal(readback, wire) {
			return ErrMaterialSource
		}
		etag = derefOriginal(response.ETag)
		return nil
	}
	if _, err := bootstrapmaterial.ProvisionLinkDurable(t.Context(), linkDirectory, target, clients.management, clients.bundles, time.Now(), persist); err == nil || !lost || creates != 1 {
		t.Fatal("lost Link create not retained", err)
	}
	publication, err := bootstrapmaterial.ProvisionLinkDurable(t.Context(), linkDirectory, target, clients.management, clients.bundles, time.Now(), persist)
	if err != nil || creates != 8 || len(publication.References) != 8 {
		t.Fatal("eight-leaf recovery", creates, err)
	}
	if err := bootstrapmaterial.ValidateLinkPublication(linkDirectory, publication, journal, time.Now()); err != nil {
		t.Fatal(err)
	}
	state := originalStartupLinkState{StartedAt: now, Journal: journal, Publication: new(publication)}
	if !originalLinkJournalValid(state, target, record.Config) {
		t.Fatal("native eight-leaf journal rejected")
	}
	changed := state
	p := publication
	p.References = slices.Clone(publication.References)
	p.References[0].Reference.VersionNumber = 2
	changed.Publication = &p
	if originalLinkJournalValid(changed, target, record.Config) {
		t.Fatal("Link version two accepted")
	}
	if _, err := bootstrapmaterial.ProvisionLinkDurable(t.Context(), linkDirectory, target, clients.management, clients.bundles, time.Now(), persist); err != nil || creates != 8 {
		t.Fatal("completed Link retry rotated leaves", err)
	}
}
