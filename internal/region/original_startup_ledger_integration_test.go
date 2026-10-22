package region

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const originalStartupTestUUID = "5f0d2d4c-a098-4cd1-882b-7854fba34b07"

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

type originalStartupLedgerFixture struct {
	producer  *originalMaterialIAMSDKFixture
	template  bootstrap.VerifiedStartupTemplate
	client    *objectstorage.ObjectStorageClient
	authority bootstrap.DerivedStartupAuthority
	key       ed25519.PrivateKey
	source    map[string]any
	sourceKey string
	wire      []byte
}

func originalStartupJSON(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func originalStartupSign(t *testing.T, value any, scope trust.Scope, key ed25519.PrivateKey, issued, expires time.Time) []byte {
	t.Helper()
	envelope, err := trust.Sign(originalStartupJSON(t, value), scope, issued, expires, key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// The wrapper reports actual disk modification and HTTP server times. Every
// object operation still traverses the real signed SDK and conditional store.
func originalStartupLedgerSDK(t *testing.T, f *originalMaterialIAMSDKFixture, onRequest func(*http.Request)) *objectstorage.ObjectStorageClient {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onRequest != nil {
			onRequest(r)
		}
		if r.Method == http.MethodGet {
			if rest, ok := strings.CutPrefix(r.URL.Path, "/n/ns/b/"); ok {
				bucket, key, found := strings.Cut(rest, "/o/")
				if found {
					if info, err := os.Stat(f.cloud.objectPath(bucket + "/" + key)); err == nil {
						w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
						w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
						w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
					}
				}
			}
		}
		f.serveHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("ledger requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("ledger fixture refuses plaintext and proxies")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("ledger fixture requires TCP")
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	objects, err := f.factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	return &objects
}

func originalStartupArchive(t *testing.T, directory string, record bootstrapmaterial.Record) []byte {
	t.Helper()
	files := map[string][]byte{}
	names := []string{"material.json", "READY"}
	for _, file := range record.Files {
		names = append(names, file.Name)
	}
	for _, name := range names {
		wire, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = wire
	}
	defer func() {
		for _, wire := range files {
			clear(wire)
		}
	}()
	wire := originalStartupJSON(t, map[string]any{"schemaVersion": 3, "kind": "original-source-archive/v1", "files": files})
	defer clear(wire)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if compressed.Len() == 0 || compressed.Len() > 25<<10 {
		t.Fatal("generated source exceeds OCI secret limit")
	}
	return compressed.Bytes()
}

func originalStartupPublication(t *testing.T, record bootstrapmaterial.Record, metadata []byte, target bootstrap.StartupVaultTarget, link bool, now time.Time) (bootstrapmaterial.Publication, []byte) {
	t.Helper()
	result := bootstrapmaterial.Publication{SchemaVersion: 1, Target: bootstrapmaterial.VaultTarget(target), MaterialSHA256: digestSource(metadata)}
	entries := []map[string]any{}
	files := slices.Clone(record.Files)
	slices.SortFunc(files, func(a, b bootstrapmaterial.File) int { return strings.Compare(a.Name, b.Name) })
	for _, file := range files {
		if file.Purpose == "owner-only" {
			continue
		}
		name := ""
		var err error
		if link {
			suffix := digestSource([]byte(record.Config.DeploymentID + "\x00" + record.Config.ClusterID))[:16]
			slot := file.Slot
			if slot == "" {
				slot = "shared"
			}
			name = "ts-" + record.Config.Environment + "-" + record.Config.Region + "-" + strings.ReplaceAll(record.Config.DeploymentID, ":", "-") + "-" + suffix + "-" + string(file.Purpose) + "-" + slot + "-" + strings.ReplaceAll(file.Name, ".", "-")
		} else {
			name, err = bootstrapmaterial.OriginalPublicationSecretName(record.Config, file)
		}
		if err != nil {
			t.Fatal(err)
		}
		id := "ocid1.vaultsecret.oc1." + record.Config.Region + ".fixture" + digestSource([]byte(name))[:24]
		reference := bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot, TargetFile: file.Name, SecretOCID: id, SHA256: file.SHA256, MaxBytes: file.MaxBytes, VersionNumber: 1}
		result.References = append(result.References, bootstrapmaterial.PublicReference{SecretName: name, Reference: reference})
		entries = append(entries, map[string]any{"name": name, "fileName": file.Name, "retryToken": originalStartupTestUUID, "sentAt": now, "secretOcid": id, "verified": true})
	}
	journal := originalStartupJSON(t, map[string]any{"schemaVersion": 1, "target": target, "materialSha256": digestSource(metadata), "entries": entries})
	return result, journal
}

func newOriginalStartupLedgerFixture(t *testing.T) *originalStartupLedgerFixture {
	t.Helper()
	f, anchor := originalStartupTrustFixture(t, false)
	template := originalStartupTemplate(t, f, anchor, oci.RegionGRU)
	client := originalStartupLedgerSDK(t, f, nil)
	directory := filepath.Join(t.TempDir(), "material")
	material := f.prepared.Grant.Regions[0].BootstrapMaterial
	// Keep generated material within the signed template's validity interval.
	issued := template.IssuedAt()
	record, err := bootstrapmaterial.GenerateAdmissionCandidate(directory, material.Config, *material.AdmissionAttestor, issued)
	if err != nil {
		t.Fatalf("generate actual admission material: %v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(directory, "material.json"))
	if err != nil {
		t.Fatal(err)
	}
	keyWire, err := os.ReadFile(filepath.Join(directory, "founder-ledger.key"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PrivateKey(bytes.Clone(keyWire))
	clear(keyWire)
	if len(key) != ed25519.PrivateKeySize {
		t.Fatal("generated ledger key invalid")
	}
	t.Cleanup(func() { clear(key) })
	launch, err := template.OriginalLaunch()
	if err != nil {
		t.Fatal(err)
	}
	retained := f.record(t)
	scope, err := originalSourceActorScope(retained, 0, launch.InstanceOCID, template.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	archive := originalStartupArchive(t, directory, record)
	defer clear(archive)
	sourceSHA := digestSource(archive)
	intent := material.OriginalSourceProducer
	authSHA, err := material.AdmissionAttestor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	inventory := bootstrap.RegionalSourceInventory{SchemaVersion: 1, Actor: bootstrap.SourceInventoryActor{InstanceID: launch.InstanceOCID, GrantDigest: template.GrantDigest(), TemplateDigest: template.TemplateDigest()}, GrantSHA256: template.GrantDigest(), PlanSHA256: template.PlanDigest(), SourceSHA256: sourceSHA, MaterialRecord: metadata}
	inventoryWire := originalStartupSign(t, inventory, bootstrap.RegionalSourceInventoryScope(template), key, f.now, template.ExpiresAt())
	publication, journal := originalStartupPublication(t, record, metadata, template.VaultTarget(), false, f.now)
	if len(publication.References) != 33 {
		t.Fatalf("source publication has %d leaves", len(publication.References))
	}
	publicationScope, err := originalMaterialPublicationScope(*retained.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"schemaVersion": 3, "kind": "original-source-archive/v1", "scope": scope, "intentSha256": digestSource(originalStartupJSON(t, intent)), "admissionAuthorizationSha256": authSHA, "target": intent.Escrow, "secretName": intent.SourceSecretName, "retryToken": originalStartupTestUUID, "startedAt": f.now, "candidate": map[string]any{"sha256": sourceSHA, "maxBytes": len(archive), "createSha256": digestSource(originalStartupJSON(t, scope))}, "reference": map[string]any{"secretOcid": "ocid1.vaultsecret.oc1.sa-saopaulo-1.originalarchive", "sha256": sourceSHA, "maxBytes": len(archive)}, "originalAdmissionInventory": inventoryWire, "publication": map[string]any{"scope": publicationScope, "journal": journal, "result": publication}}
	domain, sourceKey, err := bootstrap.OriginalSourceObject(template)
	if err != nil {
		t.Fatal(err)
	}
	stateWire := originalStartupJSON(t, state)
	f.cloud.writeObject(domain.HeadBucket+"/"+sourceKey, stateWire)
	proof, err := bootstrap.LoadRegionalSource(t.Context(), template, client, f.now)
	if err != nil || !proof.IsVerified() {
		t.Fatalf("verify real signed original inventory: %v", err)
	}
	recipient, err := bootstrap.VerifyLinkRecipient(t.Context(), proof, proof, f.now)
	if err != nil || !recipient.IsVerified() {
		t.Fatalf("verify original HOME recipient: %v", err)
	}
	linkDirectory := filepath.Join(t.TempDir(), "link")
	waitForLinkHomeClaimSecond(t, directory)
	linkRecord, err := bootstrapmaterial.GenerateOriginalLink(t.Context(), template, directory, directory, linkDirectory, linkDirectory, f.now)
	if err != nil {
		t.Fatalf("generate real original Link: %v", err)
	}
	linkMetadata, err := os.ReadFile(filepath.Join(linkDirectory, "material.json"))
	if err != nil {
		t.Fatal(err)
	}
	linkPublication, linkJournal := originalStartupPublication(t, linkRecord.Record, linkMetadata, template.VaultTarget(), true, f.now)
	if len(linkPublication.References) != 8 {
		t.Fatal("Link publication must contain exactly eight leaves")
	}
	linkArchive := originalStartupArchive(t, linkDirectory, linkRecord.Record)
	defer clear(linkArchive)
	linkSHA := digestSource(linkArchive)
	evidence := bootstrap.RegionalLinkEvidence{Actor: proof.OriginalActor(), SourceObjectKey: recipient.LinkObjectKey(), SourceSHA256: linkSHA, MaterialRecord: linkMetadata, Journal: linkJournal, References: linkPublication.LinkGenerationReferences()}
	payload, err := bootstrap.LinkDeliveryPayload(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Delivery, err = bootstrap.SignLinkDelivery(recipient, payload, key, f.now, template.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	sourceBinding, err := bootstrap.OriginalSourceBindingFor(stateWire)
	if err != nil {
		t.Fatal(err)
	}
	_, secretName, err := bootstrap.OriginalStartupLinkLocator(domain, template.InstallationID(), oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	linkState := map[string]any{"schemaVersion": 3, "kind": "original-startup-link/v1", "installationId": template.InstallationID(), "generation": template.Generation(), "cell": "gru", "grantSha256": template.GrantDigest(), "bindingSha256": recipient.BindingSHA256(), "regionalSource": sourceBinding, "homeSource": sourceBinding, "target": intent.Escrow, "secretName": secretName, "retryToken": originalStartupTestUUID, "startedAt": f.now, "candidate": map[string]any{"sha256": linkSHA, "maxBytes": len(linkArchive), "createSha256": digestSource(payload)}, "reference": map[string]any{"secretOcid": "ocid1.vaultsecret.oc1.sa-saopaulo-1.originallinkarchive", "sha256": linkSHA, "maxBytes": len(linkArchive)}, "journal": linkJournal, "publication": linkPublication, "delivery": evidence.Delivery}
	f.cloud.writeObject(domain.HeadBucket+"/"+recipient.LinkObjectKey(), originalStartupJSON(t, linkState))
	verifiedLink, err := bootstrap.VerifyStartupLink(t.Context(), template, client, evidence, f.now)
	if err != nil || !verifiedLink.IsVerified() {
		t.Fatalf("verify actual signed original Link: %v", err)
	}
	byFile := map[string]bootstrap.SecretReference{}
	for _, ref := range publication.References {
		byFile[ref.Reference.TargetFile] = ref.Reference
	}
	for _, ref := range evidence.References {
		byFile[ref.TargetFile] = ref
	}
	refs := make([]bootstrap.SecretReference, 0, len(byFile))
	for _, ref := range byFile {
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b bootstrap.SecretReference) int { return strings.Compare(a.TargetFile, b.TargetFile) })
	startup := map[string][]byte{}
	for _, slot := range template.StartupIdentity().ControllerSlots {
		manifest, err := template.ManifestFor(slot, refs)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerConfig = []byte(`{"nats":{},"controller":{}}`)
		manifest.ControllerConfigSHA256 = digestSource(manifest.ControllerConfig)
		if err := template.ValidateProjection(manifest); err != nil {
			t.Fatal("fixture projection", err)
		}
		binding := bootstrap.DerivedStartupBinding{SchemaVersion: 2, GrantSHA256: template.GrantDigest(), TemplateSHA256: template.TemplateDigest(), SourceSHA256: sourceSHA, MaterialRecord: metadata, Manifest: manifest, Link: &evidence, OriginalLaunch: &launch, OriginalSource: &sourceBinding}
		startup[slot] = originalStartupSign(t, binding, bootstrap.DerivedStartupScope(manifest), key, f.now, template.ExpiresAt())
	}
	state["startup"] = startup
	f.cloud.writeObject(domain.HeadBucket+"/"+sourceKey, originalStartupJSON(t, state))
	wire := startup[template.Template().SeedSlot]
	authority, err := bootstrap.VerifyDerivedStartupAuthority(t.Context(), template, client, wire, f.now)
	if err != nil || !authority.IsVerified() {
		t.Fatalf("mint authority from actual original source, signed Link and all3 siblings: %v", err)
	}
	return &originalStartupLedgerFixture{producer: f, template: template, client: client, authority: authority, key: key, source: state, sourceKey: domain.HeadBucket + "/" + sourceKey, wire: wire}
}

func (f *originalStartupLedgerFixture) ledger(t *testing.T) *bootstrap.Ledger {
	t.Helper()
	config, err := f.authority.LedgerConfig(f.producer.roots)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := bootstrap.NewLedger(f.client, config)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func (f *originalStartupLedgerFixture) intent(t *testing.T) bootstrap.Intent {
	t.Helper()
	manifest := f.authority.Manifest()
	profile, ok := f.authority.Profile(manifest.SeedSlot)
	if !ok {
		t.Fatal("seed profile unavailable")
	}
	profileDigest, err := bootstrap.ControllerBootstrapProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := f.authority.OriginalLaunch()
	if err != nil {
		t.Fatal(err)
	}
	key, err := bootstrap.OriginalLaunchCreateKey(launch)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap.Intent{SchemaVersion: 2, Mode: bootstrap.IntentModeExternalSeed, DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: manifest.ControllerRole, Slot: manifest.SeedSlot, Attempt: 1, Generation: 1, ManifestDigest: f.authority.Digest(), ReleaseReceiptDigest: manifest.ReleaseReceiptSHA256, RegionIntentGeneration: manifest.IntentGeneration, ImageOCID: manifest.ImageOCID, RegionIntentDigest: manifest.IntentSHA256, LaunchRequestDigest: profileDigest, ReviewedPlanDigest: launch.Create.RequestDigest, CreateKey: key, CreatedAt: time.Now().UTC().Truncate(time.Second), OCIRegion: manifest.OCIRegion, CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID, NetworkSecurityGroupIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), Shape: profile.Shape, Node: manifest.SeedSlot, OriginalLaunch: &launch}
}

func (f *originalStartupLedgerFixture) signRecord(t *testing.T, intent bootstrap.Intent, domain string, value any) []byte {
	return originalStartupSign(t, value, trust.Scope{Domain: domain, DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot}, f.key, intent.CreatedAt, f.authority.ExpiresAt())
}

func TestOriginalStartupLedgerSDKExactExternalSeedAndRestart(t *testing.T) {
	f := newOriginalStartupLedgerFixture(t)
	intent := f.intent(t)
	scope := bootstrap.BootstrapScope{DeploymentID: intent.DeploymentID, Cell: intent.Cell, Slot: intent.Slot}
	intentWire := f.signRecord(t, intent, "bootstrap-intent", intent)
	head := bootstrap.SlotHead{SchemaVersion: 1, DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: 1, Generation: 1, IntentDigest: digestSource(intentWire)}
	ledger := f.ledger(t)
	state, err := ledger.ReserveSlot(t.Context(), scope, intentWire, f.signRecord(t, intent, "bootstrap-slot-head", head))
	if err != nil || state.Intent.OriginalLaunch == nil || *state.Intent.OriginalLaunch != *intent.OriginalLaunch {
		t.Fatal("reserve exact schema2 retained original", err)
	}
	if _, err := ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, bootstrap.ErrExternalSeedMode) {
		t.Fatal("original external seed authorized a second OCI create", err)
	}
	profile, _ := f.authority.Profile(intent.Slot)
	facts := bootstrap.InstanceFacts{DeploymentID: intent.DeploymentID, Environment: intent.Environment, ClusterID: f.authority.Manifest().ClusterID, Cell: oci.Region(intent.Cell), OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot, InstanceOCID: intent.OriginalLaunch.InstanceOCID, CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey, IntentSHA256: digestSource(intentWire), Profile: profile}
	envelope, err := bootstrap.SignDerivedReceipt(f.authority, facts, intent.CreatedAt, f.authority.ExpiresAt(), f.key)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	result := bootstrap.Result{SchemaVersion: 1, Mode: intent.Mode, DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: 1, Generation: 1, RegionIntentGeneration: intent.RegionIntentGeneration, IntentDigest: digestSource(intentWire), InstanceOCID: facts.InstanceOCID, ProviderRequestID: "retained-original-provider-read", ETag: "retained-original-etag", OCIRegion: intent.OCIRegion, CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, Shape: intent.Shape, ObservedProfileDigest: intent.LaunchRequestDigest, CreateKey: intent.CreateKey, ObservedAt: intent.CreatedAt, SeedReceiptDigest: digestSource(receiptWire)}
	resultWire := f.signRecord(t, intent, "bootstrap-result", result)
	head.ResultDigest = digestSource(resultWire)
	headWire := f.signRecord(t, intent, "bootstrap-slot-head", head)
	wrongFacts := facts
	wrongFacts.InstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
	if _, err := ledger.RecordExternalSeed(t.Context(), scope, f.wire, receiptWire, wrongFacts, resultWire, headWire); err == nil {
		t.Fatal("foreign original instance completed seed")
	}
	completed, err := ledger.RecordExternalSeed(t.Context(), scope, f.wire, receiptWire, facts, resultWire, headWire)
	if err != nil || completed.SeedReceiptRecord == nil || completed.ResultRecord == nil || completed.SeedReceiptRecord.SHA256 != digestSource(receiptWire) || completed.ResultRecord.SHA256 != digestSource(resultWire) {
		t.Fatal("complete actual schema2 external seed", err)
	}
	if _, err := ledger.RecordExternalSeed(t.Context(), scope, f.wire, receiptWire, facts, resultWire, headWire); err != nil {
		t.Fatal("exact seed replay", err)
	}
	restored, err := bootstrap.RestoreBoundOriginalDerivedStartupAuthority(t.Context(), f.producer.factoryFor(), f.producer.bundle.GrantWire, f.producer.roots, f.template.OriginAnchor(), oci.RegionGRU, f.client, f.wire, time.Now())
	if err != nil || !restored.IsVerified() {
		t.Fatal("restore actual source authority", err)
	}
	restarted, err := restored.OpenLedgerWithClient(t.Context(), f.producer.roots, f.client)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.ReadSlot(t.Context(), scope)
	if err != nil || recovered.SeedReceiptRecord == nil || recovered.ResultRecord == nil || recovered.SeedReceiptRecord.SHA256 != digestSource(receiptWire) || recovered.ResultRecord.SHA256 != digestSource(resultWire) {
		t.Fatal("restart lost exact seed receipt/result", err)
	}
	if _, err := restarted.ReadForLaunch(t.Context(), scope); !errors.Is(err, bootstrap.ErrSlotAlreadyComplete) {
		t.Fatal("completed seed authorized another create", err)
	}
}

func TestOriginalStartupLedgerSDKRejectsSchemaAndBirthChanges(t *testing.T) {
	f := newOriginalStartupLedgerFixture(t)
	cases := []struct {
		name   string
		mutate func(*bootstrap.Intent)
	}{
		{"original-schema1", func(intent *bootstrap.Intent) { intent.SchemaVersion = 1; intent.OriginalLaunch = nil }},
		{"schema1-injected-original", func(intent *bootstrap.Intent) { intent.SchemaVersion = 1 }},
		{"wrong-actor", func(intent *bootstrap.Intent) {
			launch := *intent.OriginalLaunch
			launch.ActorOperationID = "0000000000F9PR1WNVDTEXS31Z"
			intent.OriginalLaunch = &launch
			intent.CreateKey, _ = bootstrap.OriginalLaunchCreateKey(launch)
		}},
		{"wrong-create", func(intent *bootstrap.Intent) {
			launch := *intent.OriginalLaunch
			launch.Create.RequestDigest = digestSource([]byte("foreign create"))
			intent.OriginalLaunch = &launch
			intent.CreateKey, _ = bootstrap.OriginalLaunchCreateKey(launch)
		}},
		{"wrong-evidence", func(intent *bootstrap.Intent) {
			launch := *intent.OriginalLaunch
			launch.EvidenceSHA256 = digestSource([]byte("foreign evidence"))
			intent.OriginalLaunch = &launch
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			intent := f.intent(t)
			test.mutate(&intent)
			scope := bootstrap.BootstrapScope{DeploymentID: intent.DeploymentID, Cell: intent.Cell, Slot: intent.Slot}
			wire := f.signRecord(t, intent, "bootstrap-intent", intent)
			head := bootstrap.SlotHead{SchemaVersion: 1, DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: 1, Generation: 1, IntentDigest: digestSource(wire)}
			if _, err := f.ledger(t).ReserveSlot(t.Context(), scope, wire, f.signRecord(t, intent, "bootstrap-slot-head", head)); err == nil {
				t.Fatal("changed schema or retained birth reserved original seed")
			}
		})
	}
	startup := f.source["startup"].(map[string][]byte)
	original := startup["controller-c"]
	delete(startup, "controller-c")
	f.producer.cloud.writeObject(f.sourceKey, originalStartupJSON(t, f.source))
	if _, err := bootstrap.VerifyDerivedStartupAuthority(t.Context(), f.template, f.client, f.wire, time.Now()); err == nil {
		t.Fatal("missing sibling retained derived authority")
	}
	startup["controller-c"] = original
	f.producer.cloud.writeObject(f.sourceKey, originalStartupJSON(t, f.source))
	f.producer.fault = "readback ETag changed"
	if err := f.authority.VerifyCurrent(t.Context(), time.Now()); err == nil {
		t.Fatal("changed current IAM retained derived authority")
	}
}

func TestOriginalStartupLedgerSDKPreservesOrdinarySchema1(t *testing.T) {
	f := newOriginalStartupLedgerFixture(t)
	config, err := f.authority.LedgerConfig(f.producer.roots)
	if err != nil {
		t.Fatal(err)
	}
	config.DerivedStartup = nil
	public := f.key.Public().(ed25519.PublicKey)
	subject, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []trust.Capability{}
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment, Role: "controller", Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}})
	}
	envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: subject, Capabilities: capabilities}, f.producer.now, f.authority.ExpiresAt(), f.producer.root)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.VerifyDelegationCurrent(envelope, f.producer.roots, time.Now(), config.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config.Delegations = []trust.VerifiedDelegation{delegation}
	ledger, err := bootstrap.NewLedger(f.client, config)
	if err != nil {
		t.Fatal(err)
	}
	intent := f.intent(t)
	intent.SchemaVersion = 1
	intent.CreateKey = "ordinary-bootstrap-create-key"
	scope := bootstrap.BootstrapScope{DeploymentID: intent.DeploymentID, Cell: intent.Cell, Slot: intent.Slot}
	headFor := func(wire []byte) []byte {
		return f.signRecord(t, intent, "bootstrap-slot-head", bootstrap.SlotHead{SchemaVersion: 1, DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: 1, Generation: 1, IntentDigest: digestSource(wire)})
	}
	injected := f.signRecord(t, intent, "bootstrap-intent", intent)
	if _, err := ledger.ReserveSlot(t.Context(), scope, injected, headFor(injected)); err == nil {
		t.Fatal("ordinary schema1 accepted injected original-launch field")
	}
	intent.OriginalLaunch = nil
	wire := f.signRecord(t, intent, "bootstrap-intent", intent)
	state, err := ledger.ReserveSlot(t.Context(), scope, wire, headFor(wire))
	if err != nil || state.Intent.SchemaVersion != 1 || state.Intent.OriginalLaunch != nil || state.Intent.CreateKey != "ordinary-bootstrap-create-key" {
		t.Fatal("ordinary schema1 create identity changed", err)
	}
	if _, err := ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, bootstrap.ErrExternalSeedMode) {
		t.Fatal("ordinary external seed create denial changed", err)
	}
}

func TestOriginalStartupTrustSDKCancellationHoldsAtIAMBoundary(t *testing.T) {
	f, anchor := originalStartupTrustFixture(t, false)
	originalStartupTemplate(t, f, anchor, oci.RegionGRU)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	seen := make(chan struct{}, 1)
	originalStartupLedgerSDK(t, f, func(request *http.Request) {
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/policies/") {
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
				t.Error("cancellation boundary received unsigned request")
			}
			select {
			case seen <- struct{}{}:
			default:
			}
			cancel()
		}
	})
	template, err := bootstrap.VerifyBoundOriginalStartupTemplate(ctx, f.factoryFor(), f.bundle.GrantWire, f.roots, anchor, oci.RegionGRU, time.Now())
	if err == nil || template.IsVerified() {
		t.Fatal("cancelled current IAM observation minted startup authority")
	}
	select {
	case <-seen:
	default:
		t.Fatal("cancellation did not cross actual SDK IAM boundary")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("SDK-bound cancellation was not observed")
	}
}

func TestOriginalStartupLedgerSDKRejectsSourceAndLinkChanges(t *testing.T) {
	f := newOriginalStartupLedgerFixture(t)
	original := originalStartupJSON(t, f.source)
	for _, mutation := range []string{"scope", "inventory", "unknown-field"} {
		t.Run(mutation, func(t *testing.T) {
			var state map[string]any
			if err := json.Unmarshal(original, &state); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "scope":
				state["scope"].(map[string]any)["InstanceID"] = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
			case "inventory":
				state["originalAdmissionInventory"] = []byte("altered unsigned inventory")
			case "unknown-field":
				state["unexpectedAuthority"] = true
			}
			f.producer.cloud.writeObject(f.sourceKey, originalStartupJSON(t, state))
			if proof, err := bootstrap.LoadRegionalSource(t.Context(), f.template, f.client, time.Now()); err == nil || proof.IsVerified() {
				t.Fatal("changed protected source minted inventory authority")
			}
			f.producer.cloud.writeObject(f.sourceKey, original)
		})
	}
	var pending map[string]any
	if err := json.Unmarshal(original, &pending); err != nil {
		t.Fatal(err)
	}
	delete(pending, "startup")
	delete(pending["publication"].(map[string]any), "result")
	f.producer.cloud.writeObject(f.sourceKey, originalStartupJSON(t, pending))
	if proof, err := bootstrap.LoadRegionalSource(t.Context(), f.template, f.client, time.Now()); !errors.Is(err, bootstrap.ErrOriginalSourcePending) || proof.IsVerified() {
		t.Fatal("legitimate incomplete source did not hold without authority", err)
	}
	f.producer.cloud.writeObject(f.sourceKey, original)
	envelope, err := trust.DecodeEnvelope(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	var binding bootstrap.DerivedStartupBinding
	if err := json.Unmarshal(envelope.Payload, &binding); err != nil {
		t.Fatal(err)
	}
	domain, _, err := bootstrap.OriginalSourceObject(f.template)
	if err != nil {
		t.Fatal(err)
	}
	key := domain.HeadBucket + "/" + binding.Link.SourceObjectKey
	linkWire, err := os.ReadFile(f.producer.cloud.objectPath(key))
	if err != nil {
		t.Fatal(err)
	}
	var link map[string]any
	if err := json.Unmarshal(linkWire, &link); err != nil {
		t.Fatal(err)
	}
	link["delivery"] = []byte("altered unsigned Link delivery")
	f.producer.cloud.writeObject(key, originalStartupJSON(t, link))
	if authority, err := bootstrap.VerifyDerivedStartupAuthority(t.Context(), f.template, f.client, f.wire, time.Now()); err == nil || authority.IsVerified() {
		t.Fatal("changed live Link CAS retained derived authority")
	}
}
