package materialsource

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
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
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// NATS Encode stamps the wall clock even when material generation is backdated.
func waitForLinkHomeClaimSecond(t *testing.T, directory string) {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join(directory, "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeAccountClaims(string(wire))
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now()
	if claim.IssuedAt <= 0 || claim.IssuedAt > observed.Unix() {
		t.Fatal("home cell claim has an invalid or future issuance time")
	}
	timer := time.NewTimer(time.Unix(claim.IssuedAt, 0).Add(time.Second).Sub(observed))
	defer timer.Stop()
	select {
	case <-t.Context().Done():
	case <-timer.C:
	}
	if err := t.Context().Err(); err != nil {
		t.Fatal("wait for home cell claim issuance second:", err)
	}
	if time.Now().Unix() <= claim.IssuedAt {
		t.Fatal("wall clock has not passed the home cell claim issuance second")
	}
}

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
	waitForLinkHomeClaimSecond(t, home)
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
	waitForLinkHomeClaimSecond(t, home)
	record, err := bootstrapmaterial.GenerateLink(home, home, linkDirectory, linkDirectory, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	names, err := bootstrapmaterial.OriginalLinkPublicationSecretNames(record.Config)
	if err != nil {
		t.Fatal(err)
	}
	target := in.intent.Escrow
	_, escrowName, err := bootstrap.OriginalStartupLinkLocator(in.intent.Home, in.scope.InstallationID, oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	escrowBody, err := os.ReadFile(filepath.Join(linkDirectory, "material.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(escrowBody)
	escrowToken := uuid.New().String()
	escrowSHA, err := originalEscrowSHA(target, escrowName, escrowToken, escrowBody)
	if err != nil {
		t.Fatal(err)
	}
	provider := *clients.management.ConfigurationProvider()
	private, err := provider.PrivateRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := provider.KeyID()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	secrets := map[string]originalMaterialSecret{}
	var journal []byte
	revision, creates := 0, 0
	lost := false
	escrowCreates, escrowLists, escrowBundles, byNameDenied := 0, 0, 0, 0
	escrowFault := ""
	fail := func(w http.ResponseWriter, status int) {
		w.WriteHeader(status)
		io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"native Link primitive fixture"}`)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := verifyOriginalLinkSignature(r, &private.PublicKey, keyID); err != nil {
			t.Error("Link SDK provider signature rejected", err)
			fail(w, 403)
			return
		}
		host := ""
		switch {
		case strings.HasPrefix(r.URL.Path, "/n/"):
			host = "objectstorage.sa-saopaulo-1.oraclecloud.com"
		case strings.HasPrefix(r.URL.Path, "/20180608/secrets"):
			host = "vaults.sa-saopaulo-1.oci.oraclecloud.com"
		case strings.HasPrefix(r.URL.Path, "/20190301/secretbundles/"):
			host = "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com"
		}
		if host == "" || r.Host != host {
			t.Error("Link SDK request escaped fixed regional endpoints")
			fail(w, 403)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/20190301/secretbundles/actions/getByName" {
			if r.URL.Query().Get("secretName") != escrowName || r.URL.Query().Get("vaultId") != target.VaultOCID || r.URL.Query().Get("versionNumber") != "1" || r.URL.Query().Get("stage") != "" {
				t.Error("Link ByName escaped its exact denial boundary")
			}
			byNameDenied++
			fail(w, 403)
			return
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
			allowed := name == escrowName
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
			if name == escrowName {
				escrowLists++
				switch escrowFault {
				case "foreign summary":
					items[0].SecretName = new("foreign")
				case "ambiguous summary":
					items = append(items, items[0])
				case "cycle":
					items = nil
					w.Header().Set("opc-next-page", "same")
				case "too many pages":
					items = nil
					w.Header().Set("opc-next-page", fmt.Sprintf("page-%d", escrowLists))
				case "paged":
					if r.URL.Query().Get("page") == "" {
						items = nil
						w.Header().Set("opc-next-page", "last")
					} else if r.URL.Query().Get("page") != "last" {
						t.Error("Link discovery changed continuation token")
					}
				}
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
			if err != nil || json.Unmarshal(wire, &request) != nil || request.CompartmentID != target.CompartmentOCID || request.VaultID != target.VaultOCID || request.KeyID != target.KMSKeyOCID {
				t.Error("Link create lacks exact durable journal target")
				fail(w, 400)
				return
			}
			if request.SecretName == escrowName {
				body, err := base64.StdEncoding.Strict().DecodeString(request.SecretContent.Content)
				if err != nil || !bytes.Equal(body, escrowBody) || request.SecretContent.Stage != "CURRENT" || r.Header.Get("opc-retry-token") != escrowToken || escrowCreates != 0 {
					clear(body)
					t.Error("Link escrow create changed exact candidate or retry identity")
					fail(w, 400)
					return
				}
				escrowCreates++
				secrets[escrowName] = originalMaterialSecret{id: "ocid1.vaultsecret.oc1.sa-saopaulo-1.linkescrow", name: escrowName, body: body}
				fail(w, 503)
				return
			}
			if json.Unmarshal(journal, &saved) != nil {
				t.Error("Link leaf create lacks durable journal")
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
				metadata := ocivault.Secret{Id: new(secret.id), CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), KeyId: new(target.KMSKeyOCID), SecretName: new(secret.name), CurrentVersionNumber: new(int64(1)), LifecycleState: ocivault.SecretLifecycleStateActive}
				if secret.name == escrowName && escrowFault == "wrong metadata" {
					metadata.KeyId = new("ocid1.key.oc1.sa-saopaulo-1.foreign")
				}
				json.MarshalWrite(w, metadata)
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/20190301/secretbundles/"+secret.id {
				if r.URL.Query().Get("versionNumber") != "1" {
					t.Error("Link recovery read other than version one")
				}
				bundle := ocisecrets.SecretBundle{SecretId: new(secret.id), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(secret.body))}}
				if secret.name == escrowName {
					escrowBundles++
					switch escrowFault {
					case "wrong bundle ID":
						bundle.SecretId = new("ocid1.vaultsecret.oc1.sa-saopaulo-1.foreign")
					case "wrong version":
						bundle.VersionNumber = new(int64(2))
					case "wrong digest":
						bundle.SecretBundleContent = ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString([]byte("foreign")))}
					}
				}
				json.MarshalWrite(w, bundle)
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
	// This extends SDK mechanics; it does not qualify the sealed startup actor.
	link := originalStartupLinkSource{clients: clients, state: originalStartupLinkState{Target: target, SecretName: escrowName, RetryToken: escrowToken,
		Candidate: originalSourceCandidate{SHA256: digestWire(escrowBody), MaxBytes: int64(len(escrowBody)), CreateSHA256: escrowSHA}}}
	policy := common.NoRetryPolicy()
	_, err = clients.bundles.GetSecretBundleByName(ociclient.RequestContext(t.Context()), ocisecrets.GetSecretBundleByNameRequest{SecretName: new(escrowName), VaultId: new(target.VaultOCID), VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if service, ok := common.IsServiceError(err); !ok || service.GetHTTPStatusCode() != 403 {
		t.Fatal("Link ByName was not denied", err)
	}
	if body, _, err := link.readEscrow(t.Context()); !errors.Is(err, os.ErrNotExist) || len(body) != 0 {
		clear(body)
		t.Fatal("absent Link escrow did not permit generation", err)
	}
	if _, err := clients.management.CreateSecret(ociclient.RequestContext(t.Context()), originalEscrowRequest(target, escrowName, escrowToken, escrowBody)); err == nil {
		t.Fatal("Link escrow lost create response was not exercised")
	}
	body, escrowID, err := link.readEscrow(t.Context())
	if err != nil || !bytes.Equal(body, escrowBody) || escrowID != "ocid1.vaultsecret.oc1.sa-saopaulo-1.linkescrow" {
		clear(body)
		t.Fatal("Link escrow did not recover actual created ID", err)
	}
	clear(body)
	reference := materialSourceReference{SecretOCID: escrowID, SHA256: digestWire(escrowBody), MaxBytes: int64(len(escrowBody))}
	link.state.Reference = reference
	mu.Lock()
	beforeLists := escrowLists
	mu.Unlock()
	body, resumedID, err := link.readEscrow(t.Context())
	clear(body)
	mu.Lock()
	resumedDirectly := escrowLists == beforeLists && escrowCreates == 1 && byNameDenied == 1
	mu.Unlock()
	if err != nil || resumedID != escrowID || !resumedDirectly {
		t.Fatal("retained Link reference did not resume directly without creation", err)
	}
	for _, fault := range []string{"wrong metadata", "wrong bundle ID", "wrong version", "wrong digest", "foreign summary", "ambiguous summary", "cycle", "too many pages", "paged"} {
		mu.Lock()
		escrowFault = fault
		beforeBundles := escrowBundles
		mu.Unlock()
		link.state.Reference = materialSourceReference{}
		body, id, err := link.readEscrow(t.Context())
		if fault == "paged" {
			if err != nil || id != escrowID || !bytes.Equal(body, escrowBody) {
				t.Error("complete paginated Link discovery failed", err)
			}
		} else if err == nil || len(body) != 0 || id != "" {
			t.Error("Link escrow accepted invalid service response", fault, err)
		}
		clear(body)
		mu.Lock()
		if fault == "wrong metadata" && escrowBundles != beforeBundles {
			t.Error("Link escrow read bundle before validating exact metadata")
		}
		mu.Unlock()
	}
	mu.Lock()
	escrowFault = ""
	mu.Unlock()
	for _, fault := range []string{"reference ID", "reference digest", "reference size", "candidate digest", "candidate size", "create SHA"} {
		changed := link
		changed.state.Reference = reference
		switch fault {
		case "reference ID":
			changed.state.Reference.SecretOCID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.foreign"
		case "reference digest":
			changed.state.Reference.SHA256 = strings.Repeat("a", 64)
		case "reference size":
			changed.state.Reference.MaxBytes++
		case "candidate digest":
			changed.state.Candidate.SHA256 = strings.Repeat("a", 64)
		case "candidate size":
			changed.state.Candidate.MaxBytes++
		case "create SHA":
			changed.state.Candidate.CreateSHA256 = strings.Repeat("a", 64)
		}
		body, id, err := changed.readEscrow(t.Context())
		if err == nil || len(body) != 0 || id != "" {
			t.Error("Link escrow accepted changed protected identity", fault, err)
		}
		clear(body)
	}
	link.state.Reference = reference
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

func verifyOriginalLinkSignature(request *http.Request, public *rsa.PublicKey, keyID string) error {
	value, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		return errors.New("missing OCI SDK signature")
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(value, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || fields[key] != "" {
			return errors.New("invalid OCI signature fields")
		}
		fields[key] = strings.Trim(value, `"`)
	}
	headers := "date (request-target) host"
	if request.Method == http.MethodPost {
		headers += " content-length content-type x-content-sha256"
	}
	if fields["keyId"] != keyID || fields["algorithm"] != "rsa-sha256" || fields["headers"] != headers {
		return errors.New("unexpected OCI signing identity, algorithm or headers")
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return err
	}
	signed := "date: " + request.Header.Get("Date") + "\n(request-target): " + strings.ToLower(request.Method) + " " + request.URL.RequestURI() + "\nhost: " + request.Host
	if request.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || len(body) >= 1<<20 {
			return errors.New("invalid signed OCI body")
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		digest := sha256.Sum256(body)
		if request.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) || request.ContentLength != int64(len(body)) {
			return errors.New("OCI body differs from signed digest or length")
		}
		signed += fmt.Sprintf("\ncontent-length: %d\ncontent-type: %s\nx-content-sha256: %s", request.ContentLength, request.Header.Get("Content-Type"), request.Header.Get("X-Content-Sha256"))
	}
	digest := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
}
