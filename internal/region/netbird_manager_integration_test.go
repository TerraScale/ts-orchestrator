package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// This fixture crosses the real OCI SDK, public-price HTTP and disk-backed
// Object Storage CAS; only the remote services and ARM64 binary measurement are fixtures.
func TestNetBirdManagerSignedLaunchAndStoreRecovery(t *testing.T) {
	withNetBirdManagerFixture(t, nil)
}

func withNetBirdManagerFixture(t *testing.T, run func(*ociclient.Factory, FoundationResolver, VerifiedNetBirdManager)) {
	t.Helper()
	store, objects, writeOriginal := foundationProtocolStore(t)
	// Retain the original journal fixture while serving the signed home bucket.
	write := func(name string, wire []byte) {
		writeOriginal(name, wire)
		_, err := objects.PutObject(ociclient.RequestContext(t.Context()), objectstorage.PutObjectRequest{NamespaceName: new("ns"), BucketName: new("gru-1-head"), ObjectName: new(name), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentLength: new(int64(len(wire)))})
		if err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()}
	reader := &SignedFootprint{client: objects, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "gru-1-head", LedgerBucket: "gru-1-ledger", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "bootstrap"}, scope: scope, expires: now.Add(time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test", home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(30*time.Minute), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	digest := func(wire []byte) string { h := sha256.Sum256(wire); return hex.EncodeToString(h[:]) }
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: "arm64", BinaryBytes: 13, BinarySHA256: strings.Repeat("b", 64), QualificationSHA256: strings.Repeat("c", 64),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU", BaseImageSHA256: strings.Repeat("d", 64), KernelRelease: "6.1.0-test+1", KernelSHA256: strings.Repeat("e", 64), ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: strings.Repeat("f", 64), OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.CUSTOM", OCIRegion: "GRU"}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256, Cell: "GRU", Environment: "production", Runtime: release.NetBirdProductionRuntime, Architecture: "arm64", Role: NetBirdManagerRole}}
	for _, gate := range []string{"netbird-foundation", "netbird-recovery"} {
		wire := []byte("retained real-boundary fixture " + gate)
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: digest(wire), Bytes: int64(len(wire)), CompletedAt: now.Add(-2 * time.Minute)})
		write(releasechannel.ImageProductionEvidenceObject(digest(wire)), wire)
	}
	proof := release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), private)}
	receipt.HostProduction = map[string]release.ProductionProof{NetBirdManagerRole: proof}
	imagePublic, imagePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	imageScope := release.NetBirdImageScope(receipt, "production")
	keyID, err := trust.KeyID(imagePublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(imagePublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic, Capabilities: []trust.Capability{{Domain: imageScope.Domain, DeploymentID: imageScope.DeploymentID, Cell: imageScope.Cell, Environment: imageScope.Environment, Role: imageScope.Role, Slots: []string{imageScope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Hour), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	manager := NetBirdManagerIntent{Role: NetBirdManagerRole, StoreOrigin: "new", Profile: NetBirdManagerProfile{AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1", PrivateIP: "10.251.1.10", NetworkCIDR: "10.251.1.0/24", Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootVolumeGB: 50}, ImageOCID: receipt.OCIImageOCID, Architecture: "arm64", ImageReceiptWire: sign(receipt, imageScope, imagePrivate), ImageDelegationWire: delegationWire, QualificationWire: proof.Qualification}
	const control = "ocid1.compartment.oc1..control"
	const networkCompartment = "ocid1.compartment.oc1..network"
	plan := map[string]any{"cell": "GRU", "region": foundationHomeRegion, "tenancy_id": reader.tenancy, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "network_cidr": "10.251.0.0/24", "subnet_cidr": "10.251.0.0/25", "resource_ids": map[string]any{"control_compartment": control, "network_compartment": networkCompartment, "workload_compartment": "ocid1.compartment.oc1..workload", "vault": "ocid1.vault.oc1.sa-saopaulo-1.owned", "key": "ocid1.key.oc1.sa-saopaulo-1.owned"}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy, ParentCompartmentID: plan["parent_compartment_id"].(string), SharedCompartmentID: plan["shared_compartment_id"].(string), Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration", Regions: []FoundationIntent{{Generation: 1, Plan: plan, NetBirdManager: &manager}}}
	components := netBirdComponentFixtures(t, private, roots, reader.storage, objects, now, sign, write)
	for _, component := range components {
		grant.ReleaseAuthorities = append(grant.ReleaseAuthorities, component.authority)
		principal, email, secret, err := OCIRServiceIdentity(grant.InstallationID, component.authority.ImageRepository)
		if err != nil {
			t.Fatal(err)
		}
		grant.OCIRIssuances = append(grant.OCIRIssuances, OCIRIssuerIntent{OCIRegion: foundationHomeRegion, RegistryHost: "gru.ocir.io", RepositoryCompartmentID: control, RepositoryName: component.claim.Role, RegistryNamespace: "ns", PrincipalName: principal, PrincipalEmail: email, VaultTarget: vaultsecret.Target{CompartmentID: control, VaultID: "ocid1.vault.oc1.sa-saopaulo-1.owned", KeyID: "ocid1.key.oc1.sa-saopaulo-1.owned"}, SecretName: secret})
	}
	profileSHA, err := NetBirdManagerProfileDigest(manager.Profile)
	if err != nil {
		t.Fatal(err)
	}
	recipeSHA, err := NetBirdManagerRecipeDigest(manager, receipt.ImageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	spendSHA, err := FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	slotID := BootstrapSlotID(grant.InstallationID, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	grant.InfrastructureSpend = &InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: spendSHA, Bootstrap: &BootstrapSpendingIntent{ReservedMinor: 3000, Slots: []BootstrapSlotIntent{{SlotID: slotID, Cell: "GRU", Role: NetBirdManagerRole, Slot: NetBirdManagerRole, CompartmentID: control, ProfileSHA256: profileSHA, RecipeSHA256: recipeSHA, Shape: manager.Profile.Shape, OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyLimitMinor: 3000}}}}
	publish := func() {
		wire := sign(grant, scope, private)
		reader.home.GrantSHA256 = digest(wire)
		write("bootstrap/"+foundationGrantObject, wire)
	}
	publish()
	intentSHA, err := FoundationIntentDigest(grant.Regions[0])
	if err != nil {
		t.Fatal(err)
	}
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: foundationHomeRegion, TenancyID: reader.tenancy, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1, IntentDigest: intentSHA, OperationID: entityid.New(), Epoch: 1, LeaseID: entityid.New(), ExpiresAt: time.Now().Add(foundationLease), Stage: "foundation", StartedAt: now, UpdatedAt: now, ResourceIDs: map[string]string{}, AuxiliaryIDs: map[string]string{}, PendingCreates: map[string]PendingFoundationCreate{}}
	for key, id := range plan["resource_ids"].(map[string]any) {
		record.ResourceIDs[key] = id.(string)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	blockedObjects := map[string]bool{}
	channelOverrides := map[string][]byte{}
	channelReads := map[string]int{}
	var replaceChannel string
	var replacement []byte
	secretVersions := map[string]int64{}
	for _, issuer := range grant.OCIRIssuances {
		secretVersions[issuer.SecretName] = 1
	}
	componentReads, componentWrites := 0, 0
	live := map[string]map[string]any{}
	tokens := map[string]string{}
	creates, launches, launchPosts := 0, 0, 0
	lost := true
	cpuTariff := .01
	observedImage := manager.ImageOCID
	idFor := func(kind string) string { return "ocid1." + kind + ".oc1.sa-saopaulo-1.manager" }
	kinds := map[string]string{"vcns": "vcn", "internetGateways": "internetgateway", "routeTables": "routetable", "securityLists": "securitylist", "networkSecurityGroups": "networksecuritygroup", "subnets": "subnet"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Host, "apexapps.oracle.com") {
			metric, price := "", 0.0
			switch r.URL.Query().Get("partNumber") {
			case "B93297":
				metric, price = "OCPU Per Hour", cpuTariff
			case "B93298":
				metric, price = "Gigabyte Per Hour", .0015
			case "B91961":
				metric, price = "Gigabyte Storage Capacity Per Month", .0255
			case "B91962":
				metric, price = "Performance Units Per Gigabyte Per Month", .0017
			default:
				t.Errorf("unexpected tariff %s", r.URL)
			}
			fmt.Fprintf(w, `{"lastUpdated":%q,"items":[{"partNumber":%q,"metricName":%q,"currencyCodeLocalizations":[{"currencyCode":"USD","prices":[{"model":"PAY_AS_YOU_GO","value":%v}]}]}]}`, time.Now().UTC().Format(time.RFC3339), r.URL.Query().Get("partNumber"), metric, price)
			return
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned manager OCI operation")
			w.WriteHeader(401)
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/n/ns/b/gru-1-head/o/"); ok {
			if r.Method != http.MethodGet {
				componentWrites++
				http.Error(w, "receiver attempted object mutation", 405)
				return
			}
			componentReads++
			channelReads[name]++
			if blockedObjects[name] {
				http.Error(w, `{"code":"ObjectNotFound","message":"absent"}`, 404)
				return
			}
			if name == replaceChannel && channelReads[name] > 1 {
				w.Header().Set("ETag", digest(replacement))
				w.Write(replacement)
				return
			}
			if wire, ok := channelOverrides[name]; ok {
				w.Header().Set("ETag", digest(wire))
				w.Write(wire)
				return
			}
			response, err := objects.GetObject(ociclient.RequestContext(r.Context()), objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("gru-1-head"), ObjectName: new(name)})
			if err != nil {
				http.Error(w, `{"code":"ObjectNotFound","message":"absent"}`, 404)
				return
			}
			defer response.Content.Close()
			if response.ETag != nil {
				w.Header().Set("ETag", *response.ETag)
			}
			io.Copy(w, response.Content)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName") {
			componentReads++
			name := r.URL.Query().Get("secretName")
			version := secretVersions[name]
			if r.Method != http.MethodPost || r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Get("vaultId") != "ocid1.vault.oc1.sa-saopaulo-1.owned" || version == 0 {
				http.Error(w, `{"code":"NotAuthorizedOrNotFound","message":"absent"}`, 404)
				return
			}
			value, err := json.Marshal(map[string]string{"username": "ns/fixture-ocir", "password": "fixture-only-issued-token"}, json.Deterministic(true))
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			json.MarshalWrite(w, map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1." + strings.ReplaceAll(name, "-", ""), "versionNumber": version, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(value)}})
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/20160918/")
		parts := strings.Split(path, "/")
		collection := parts[0]
		if r.Method == http.MethodPost && collection == "instances" {
			launchPosts++
			saved, _, err := store.Load(r.Context(), "GRU")
			if err != nil || saved.NetBirdManager == nil || saved.NetBirdManager.RetryToken != r.Header.Get("opc-retry-token") {
				t.Error("compute launch preceded durable exact request reservation")
				w.WriteHeader(400)
				return
			}
			quote := saved.NetBirdManager.OriginalQuote
			if quote == nil || quote.Validate() != nil || quote.ScopeSHA256 != saved.NetBirdManager.PhysicalScopeSHA256 || quote.CompartmentID != control || quote.Cell != "GRU" ||
				quote.Shape != manager.Profile.Shape || quote.OCPUs != 2 || quote.MemoryGB != 4 || quote.BootGB != 50 || quote.IssuedAt.After(saved.NetBirdManager.StartedAt) || !saved.NetBirdManager.StartedAt.Before(quote.ExpiresAt) {
				t.Error("compute launch preceded durable original payable tariffs and exact billing geometry")
				w.WriteHeader(400)
				return
			}
			var body map[string]any
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			expected := netBirdLaunchDetails(manager, control, idFor("subnet"), idFor("networksecuritygroup"))
			sdkRequest := core.LaunchInstanceRequest{LaunchInstanceDetails: expected}
			httpRequest, err := sdkRequest.HTTPRequest(http.MethodPost, "/20160918/instances", nil, nil)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			wire, readErr := io.ReadAll(httpRequest.Body)
			closeErr := httpRequest.Body.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			var expectedBody map[string]any
			json.Unmarshal(wire, &expectedBody)
			actualWire, _ := json.Marshal(body, json.Deterministic(true))
			expectedWire, _ := json.Marshal(expectedBody, json.Deterministic(true))
			if string(actualWire) != string(expectedWire) {
				t.Error("actual SDK body differs from compiled durable recipe")
			}
			if digest(actualWire) != saved.NetBirdManager.RequestDigest {
				t.Error("persisted request digest does not authenticate actual SDK body")
			}
			if launches == 0 {
				launches++
				live["instances"] = body
				live["instances"]["id"] = idFor("instance")
			}
			if lost {
				lost = false
				w.WriteHeader(503)
				io.WriteString(w, `{"code":"InternalError","message":"accepted launch response lost"}`)
				return
			}
			json.MarshalWrite(w, map[string]any{"id": idFor("instance")})
			return
		}
		if r.Method == http.MethodGet {
			switch collection {
			case "dhcps":
				json.MarshalWrite(w, map[string]any{"id": idFor("dhcpoptions"), "vcnId": idFor("vcn"), "compartmentId": networkCompartment, "lifecycleState": "AVAILABLE", "options": []map[string]any{{"type": "DomainNameServer", "serverType": "VcnLocalPlusInternet"}}})
				return
			case "instances":
				json.MarshalWrite(w, map[string]any{"id": idFor("instance"), "compartmentId": control, "availabilityDomain": "AD-1", "faultDomain": "FAULT-DOMAIN-1", "shape": manager.Profile.Shape, "shapeConfig": map[string]any{"ocpus": 2, "memoryInGBs": 4}, "imageId": observedImage, "sourceDetails": map[string]any{"sourceType": "image", "imageId": observedImage}, "lifecycleState": "RUNNING"})
				return
			case "vnicAttachments":
				json.MarshalWrite(w, []map[string]any{{"instanceId": idFor("instance"), "compartmentId": control, "vnicId": idFor("vnic"), "subnetId": idFor("subnet"), "lifecycleState": "ATTACHED"}})
				return
			case "vnics":
				json.MarshalWrite(w, map[string]any{"id": idFor("vnic"), "compartmentId": networkCompartment, "availabilityDomain": "AD-1", "subnetId": idFor("subnet"), "nsgIds": []string{idFor("networksecuritygroup")}, "privateIp": manager.Profile.PrivateIP, "publicIp": "203.0.113.10", "isPrimary": true, "skipSourceDestCheck": false, "lifecycleState": "AVAILABLE"})
				return
			case "bootVolumeAttachments":
				json.MarshalWrite(w, []map[string]any{{"instanceId": idFor("instance"), "bootVolumeId": idFor("bootvolume"), "lifecycleState": "ATTACHED"}})
				return
			case "bootVolumes":
				json.MarshalWrite(w, map[string]any{"id": idFor("bootvolume"), "compartmentId": control, "imageId": manager.ImageOCID, "sizeInGBs": 50, "vpusPerGB": 10, "lifecycleState": "AVAILABLE"})
				return
			}
			if len(parts) == 3 && parts[2] == "securityRules" {
				io.WriteString(w, `[]`)
				return
			}
			if len(parts) == 2 && live[collection] != nil {
				json.MarshalWrite(w, live[collection])
				return
			}
		}
		if r.Method != http.MethodPost || len(parts) != 1 || kinds[collection] == "" {
			t.Errorf("unexpected manager operation %s %s", r.Method, r.URL)
			w.WriteHeader(400)
			return
		}
		token := r.Header.Get("opc-retry-token")
		saved, _, err := store.Load(r.Context(), "GRU")
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		prepared := false
		for _, pending := range saved.PendingCreates {
			if pending.Request.RetryToken == token && token != "" {
				prepared = true
			}
		}
		if !prepared {
			t.Error("network effect preceded durable exact request")
			w.WriteHeader(400)
			return
		}
		if tokens[token] != "" {
			json.MarshalWrite(w, live[collection])
			return
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		body["id"], body["lifecycleState"] = idFor(kinds[collection]), "AVAILABLE"
		if collection == "vcns" {
			body["defaultDhcpOptionsId"] = idFor("dhcpoptions")
		}
		if collection == "subnets" {
			body["prohibitInternetIngress"] = false
		}
		live[collection], tokens[token] = body, collection
		creates++
		json.MarshalWrite(w, body)
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(reader.tenancy, "ocid1.user.oc1..test", foundationHomeRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reader.factory = factory
	resume := func() (*foundationAttempt, FoundationProgress) {
		saved, etag, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		_, cancel := context.WithCancelCause(t.Context())
		t.Cleanup(func() { cancel(nil) })
		attempt := &foundationAttempt{controller: &FoundationController{Store: store, Authority: recoveryAuthority{}}, record: saved, etag: etag, leaseID: saved.LeaseID, epoch: saved.Epoch, cancel: cancel}
		return attempt, FoundationProgress{OperationID: saved.OperationID, BeforeWrite: attempt.beforeWrite, Checkpoint: attempt.checkpoint, AuxiliaryIDs: maps.Clone(saved.AuxiliaryIDs), CheckpointAuxiliary: attempt.checkpointAuxiliary, PrepareCreate: attempt.prepareCreate, NetBirdManager: saved.NetBirdManager, ManagerAuthority: reader.authorizedNetBirdManager, ManagerAllocation: reader.BootstrapAllocation, CheckpointManager: attempt.checkpointManager}
	}
	// A real signed insufficient allocation must fail before any network create.
	grant.InfrastructureSpend.Bootstrap.Slots[0].MonthlyLimitMinor = 1
	publish()
	_, progress := resume()
	if err := reconcileNetBirdManager(t.Context(), factory, plan, progress); err == nil || creates != 0 || launchPosts != 0 {
		t.Fatalf("unfunded manager mutated cloud: creates=%d launches=%d err=%v", creates, launchPosts, err)
	}
	grant.InfrastructureSpend.Bootstrap.Slots[0].MonthlyLimitMinor = 3000
	publish()
	_, progress = resume()
	if err := reconcileNetBirdManager(t.Context(), factory, plan, progress); err == nil {
		t.Fatal("lost accepted compute response reported success")
	}
	saved, _, err := store.Load(t.Context(), "GRU")
	if err != nil || saved.NetBirdManager == nil || saved.NetBirdManager.InstanceID != "" || launches != 1 || creates != 6 {
		t.Fatalf("unknown launch failed to preserve exact reservation: %+v err=%v creates=%d launches=%d", saved.NetBirdManager, err, creates, launches)
	}
	originalLaunch := *saved.NetBirdManager
	if originalLaunch.OriginalQuote == nil {
		t.Fatal("lost compute response discarded original quote")
	}
	originalQuote := originalLaunch.OriginalQuote.Clone()
	reopened, err := NewObjectFoundationStore(objects, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	for fault, mutate := range map[string]func(*FoundationRecord){
		"remove reservation": func(r *FoundationRecord) { r.NetBirdManager = nil },
		"remove quote":       func(r *FoundationRecord) { r.NetBirdManager.OriginalQuote = nil },
		"replace quote identity": func(r *FoundationRecord) {
			r.NetBirdManager.OriginalQuote.IssuedAt = r.NetBirdManager.OriginalQuote.IssuedAt.Add(time.Nanosecond)
		},
		"reorder original tariffs": func(r *FoundationRecord) { slices.Reverse(r.NetBirdManager.OriginalQuote.Prices) },
		"transplant launch identity": func(r *FoundationRecord) {
			r.NetBirdManager.OriginGrantSHA256 = strings.Repeat("f", 64)
		},
		"transplant physical scope": func(r *FoundationRecord) {
			r.NetBirdManager.PhysicalScopeSHA256 = strings.Repeat("e", 64)
			r.NetBirdManager.OriginalQuote.ScopeSHA256 = r.NetBirdManager.PhysicalScopeSHA256
		},
	} {
		current, etag, err := reopened.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		mutate(&current)
		if _, err := reopened.CompareAndSwap(t.Context(), current, etag); err == nil {
			t.Fatalf("original manager quote custody accepted %s", fault)
		}
		retained, actual, err := reopened.Load(t.Context(), "GRU")
		if err != nil || actual != etag || !sameCapacityValue(retained.NetBirdManager, &originalLaunch) {
			t.Fatalf("refused %s changed protected manager reservation: %v", fault, err)
		}
	}
	mu.Lock()
	cpuTariff = .0101
	beforeRetry := launchPosts
	mu.Unlock()
	_, progress = resume()
	if err := reconcileNetBirdManager(t.Context(), factory, plan, progress); err == nil || !strings.Contains(err.Error(), "original quoted financial terms") {
		t.Fatalf("changed current manager tariff did not refuse launch replay: %v", err)
	}
	saved, _, err = reopened.Load(t.Context(), "GRU")
	if err != nil || launchPosts != beforeRetry || creates != 6 || !sameCapacityValue(saved.NetBirdManager, &originalLaunch) {
		t.Fatalf("changed manager tariff replay dispatched or replaced original evidence: %v", err)
	}
	mu.Lock()
	cpuTariff = .01
	mu.Unlock()
	attempt, progress := resume()
	if err := reconcileNetBirdManager(t.Context(), factory, plan, progress); err != nil {
		t.Fatal(err)
	}
	if launches != 1 || launchPosts != 2 || creates != 6 {
		t.Fatalf("recovery duplicated cloud resources: creates=%d launches=%d posts=%d", creates, launches, launchPosts)
	}
	saved, _, err = store.Load(t.Context(), "GRU")
	if err != nil || saved.NetBirdManager.StartedAt != originalLaunch.StartedAt || saved.NetBirdManager.RetryToken != originalLaunch.RetryToken || saved.NetBirdManager.RequestDigest != originalLaunch.RequestDigest {
		t.Fatalf("recovery changed original bounded launch request: %+v %v", saved.NetBirdManager, err)
	}
	if saved.NetBirdManager.InstanceID != idFor("instance") || saved.NetBirdManager.BootVolumeID != idFor("bootvolume") || !sameCapacityValue(saved.NetBirdManager.OriginalQuote, &originalQuote) {
		t.Fatal("equal-price recovery replaced original quote identity, validity or exact resource binding")
	}
	if _, err := attempt.finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	resolver := FoundationResolver{Footprint: reader, Store: store}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.RegionGRU, factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	admit := func() (VerifiedNetBirdManager, error) {
		return admitNetBirdManager(t.Context(), resolver, reader, netBirdObservedInstance{factory: factory, resolver: resolver, reader: reader, observer: observer}, idFor("instance"), func(image release.VerifiedImage) (bootstrapstart.RunningBinary, error) {
			if !image.IsVerified() {
				return bootstrapstart.RunningBinary{}, errors.New("unverified image")
			}
			return bootstrapstart.RunningBinary{}, nil
		})
	}
	claim, err := admit()
	if err != nil {
		t.Fatal(err)
	}
	if run != nil {
		run(factory, resolver, claim)
		return
	}
	if claim.RecoveryRequired() {
		t.Fatal("new explicitly funded store required restore")
	}
	beforeMaterial, beforeETag, err := reopened.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	material, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("actual admitted manager failed signed component material: %v", err)
	}
	for _, role := range netBirdComponentRoles() {
		component, err := material.Component(t.Context(), role)
		if err != nil || component.Role() != role || component.Release().Claim().Role != role || component.PullClaim().Version != 1 ||
			component.PullClaim().Scope.TaskPrincipal != entityid.Derive("netbird-component", claim.StoreGeneration(), role) {
			t.Fatalf("incomplete exact component metadata for %s: %v", role, err)
		}
		wire, err := json.Marshal(component.PullClaim())
		if err != nil || bytes.Contains(wire, []byte("fixture-only-issued-token")) || bytes.Contains(wire, []byte("fixture-ocir")) {
			t.Fatal("component material exposed credential bytes")
		}
	}
	if _, err := material.Component(t.Context(), "terrabase"); err == nil {
		t.Fatal("dedicated material admitted an arbitrary role")
	}
	if err := (NetBirdComponents{}).Check(t.Context()); err == nil {
		t.Fatal("zero component material retained authority")
	}
	if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, VerifiedNetBirdManager{}); err == nil {
		t.Fatal("missing manager proof obtained component material")
	}
	first := components[0]
	channelName := releasechannel.ContainerReleaseObject(first.claim.Role, "arm64")
	for _, name := range []string{channelName, releasechannel.ContainerReleaseObject(components[1].claim.Role, "arm64"), releasechannel.ContainerReleaseObject(components[2].claim.Role, "arm64"), first.evidence[0], release.SequenceReservationObject(first.claim.Role, "production", first.claim.SequenceMigrationSHA256, first.claim.ReleaseSequence)} {
		mu.Lock()
		blockedObjects[name] = true
		mu.Unlock()
		if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim); err == nil {
			t.Fatalf("missing authenticated component object %s was accepted", name)
		}
		mu.Lock()
		delete(blockedObjects, name)
		mu.Unlock()
	}
	for _, fault := range []string{"cell", "role", "architecture", "environment", "repository", "source", "expired", "delegation", "migration"} {
		broken := first.bundle
		changed := first.claim
		switch fault {
		case "cell":
			changed.Cell = "SJC"
		case "role":
			changed.Role = "terrabase"
		case "architecture":
			changed.Architecture = "amd64"
		case "environment":
			changed.Environment = "staging"
		case "repository":
			changed.Image = "gru.ocir.io/ns/unapproved@sha256:" + strings.Repeat("a", 64)
		case "source":
			changed.SourceRepository = "https://github.com/TerraScale/unapproved"
		case "delegation":
			broken.Delegation = components[1].bundle.Delegation
		case "migration":
			broken.Migration = components[1].bundle.Migration
		}
		if fault == "expired" {
			payload, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			expired, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: changed.Cell, Role: changed.Role, Environment: changed.Environment, Architecture: changed.Architecture}), now.Add(-2*time.Hour), now.Add(-time.Hour), first.signer)
			if err != nil {
				t.Fatal(err)
			}
			broken.Claim, err = trust.EncodeEnvelope(expired)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			broken.Claim = sign(changed, release.ContainerScope(release.ContainerTarget{Cell: changed.Cell, Role: changed.Role, Environment: changed.Environment, Architecture: changed.Architecture}), first.signer)
		}
		wire, err := json.Marshal(broken)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		channelOverrides[channelName] = wire
		mu.Unlock()
		if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim); err == nil {
			t.Fatalf("signed component %s mismatch was accepted", fault)
		}
		mu.Lock()
		delete(channelOverrides, channelName)
		mu.Unlock()
	}
	// Replace an otherwise valid channel between its original and final read.
	alternate := first.bundle
	alternate.Claim = sign(first.claim, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Role: first.claim.Role, Environment: "production", Architecture: "arm64"}), first.signer)
	alternate.Index = []byte("changed retained index")
	changedWire, err := json.Marshal(alternate)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	clear(channelReads)
	replaceChannel, replacement = channelName, changedWire
	mu.Unlock()
	if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim); err == nil {
		t.Fatal("channel replaced during verification retained component material")
	}
	mu.Lock()
	replaceChannel, replacement = "", nil
	issuerName := grant.OCIRIssuances[0].SecretName
	secretVersions[issuerName] = 0
	mu.Unlock()
	if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim); err == nil {
		t.Fatal("missing CURRENT credential returned component material")
	}
	mu.Lock()
	secretVersions[issuerName] = 1
	mu.Unlock()
	rotationMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("fresh CURRENT material before rotation: %v", err)
	}
	mu.Lock()
	secretVersions[issuerName] = 2
	mu.Unlock()
	if err := rotationMaterial.Check(t.Context()); err == nil {
		t.Fatal("rotated CURRENT credential retained original component metadata")
	}
	if err := rotationMaterial.RetainReleaseFloors(t.Context()); err == nil {
		t.Fatal("rotated CURRENT credential initialized component release floors")
	}
	mu.Lock()
	secretVersions[issuerName] = 1
	mu.Unlock()
	sourceMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("fresh signed source material before replacement: %v", err)
	}
	issuers := grant.OCIRIssuances
	grant.OCIRIssuances = grant.OCIRIssuances[1:]
	publish()
	if _, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim); err == nil {
		t.Fatal("missing same-grant OCIR issuer returned component material")
	}
	if err := sourceMaterial.Check(t.Context()); err == nil {
		t.Fatal("replaced foundation source retained original component material")
	}
	grant.OCIRIssuances = issuers
	publish()
	afterMaterial, afterETag, err := reopened.Load(t.Context(), "GRU")
	if err != nil || beforeETag != afterETag || !sameCapacityValue(beforeMaterial, afterMaterial) || componentWrites != 0 || componentReads == 0 || creates != 6 || launchPosts != 2 {
		t.Fatalf("component reads mutated journal/cloud or bypassed actual protocol: %v", err)
	}
	if err := (NetBirdComponents{}).RetainReleaseFloors(t.Context()); err == nil {
		t.Fatal("zero material initialized durable release floors")
	}
	material, err = ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("fresh complete component set before retaining floors: %v", err)
	}
	// The real SDK receives 502 only after the disk-backed CAS has committed.
	var foundationPuts atomic.Int32
	func() {
		client := objects.(*objectstorage.ObjectStorageClient)
		originalHost := client.Host
		upstream, err := url.Parse(originalHost)
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.ModifyResponse = func(response *http.Response) error {
			if response.Request.Method == http.MethodPut && strings.Contains(response.Request.URL.Path, foundationObjectPrefix+"GRU.json") {
				if foundationPuts.Add(1) == 1 && response.StatusCode == http.StatusOK {
					return errors.New("fixture lost committed floor CAS response")
				}
			}
			return nil
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `{"code":"BadGateway","message":"committed response lost"}`)
		}
		server := httptest.NewServer(proxy)
		defer server.Close()
		client.Host = server.URL
		defer func() { client.Host = originalHost }()
		if err := material.RetainReleaseFloors(t.Context()); err != nil {
			t.Fatalf("lost committed floor response did not reobserve complete durable set: %v", err)
		}
		if err := material.RetainReleaseFloors(t.Context()); err != nil {
			t.Fatalf("complete floor replay failed: %v", err)
		}
	}()
	if foundationPuts.Load() != 1 {
		t.Fatalf("lost response or complete replay dispatched %d floor writes; want one", foundationPuts.Load())
	}
	floorStore, err := NewObjectFoundationStore(objects, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	withFloors, floorETag, err := floorStore.Load(t.Context(), "GRU")
	if err != nil || withFloors.NetBirdManager.ComponentFloors == nil {
		t.Fatalf("reopened store lost the complete component floors: %v", err)
	}
	originalFloors := *withFloors.NetBirdManager.ComponentFloors
	for i, component := range material.state.components {
		floor := originalFloors[i]
		if floor.Role != component.Role() || floor.ReleaseSequence != component.Release().Claim().ReleaseSequence || floor.ReleaseIdentity != component.Release().ReleaseIdentity() ||
			floor.Image != component.Release().Claim().Image || floor.BundleSHA256 != component.Release().BundleSHA256() || floor.SequenceMigrationSHA256 != component.Release().Claim().SequenceMigrationSHA256 {
			t.Fatalf("floor %s lost original signed release evidence", floor.Role)
		}
	}
	expectedLaunch := *afterMaterial.NetBirdManager
	expectedLaunch.ComponentFloors = &originalFloors
	if !sameCapacityValue(withFloors.NetBirdManager, &expectedLaunch) {
		t.Fatal("retaining floors replaced original launch, physical store or financial metadata")
	}
	// A renewed current signature preserves the original bundle and performs no CAS.
	renewedBundle := first.bundle
	payload, err := trust.EncodePayload(first.claim)
	if err != nil {
		t.Fatal(err)
	}
	renewedEnvelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Role: first.claim.Role, Environment: "production", Architecture: "arm64"}), now.Add(-30*time.Second), now.Add(25*time.Minute), first.signer)
	if err != nil {
		t.Fatal(err)
	}
	renewedBundle.Claim, err = trust.EncodeEnvelope(renewedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	renewedWire, err := json.Marshal(renewedBundle)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	channelOverrides[channelName] = renewedWire
	mu.Unlock()
	renewedMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("renewed genuine component material: %v", err)
	}
	if renewedMaterial.state.components[0].Release().BundleSHA256() == originalFloors[0].BundleSHA256 {
		t.Fatal("renewed fixture did not change signed bundle bytes")
	}
	if err := renewedMaterial.RetainReleaseFloors(t.Context()); err != nil {
		t.Fatalf("equal signed release renewal failed: %v", err)
	}
	retainedFloors, retainedETag, err := floorStore.Load(t.Context(), "GRU")
	if err != nil || retainedETag != floorETag || *retainedFloors.NetBirdManager.ComponentFloors != originalFloors {
		t.Fatalf("renewal replaced original bundle evidence or dispatched CAS: %v", err)
	}
	mu.Lock()
	delete(channelOverrides, channelName)
	mu.Unlock()
	// Allocate and publish a genuinely signed successor for just the server.
	nextClaim := first.claim
	nextClaim.SourceRevision = strings.Repeat("d", 40)
	family, err := nextClaim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	allocations := release.SequenceLocation{Client: objects, Namespace: reader.storage.Namespace, Bucket: reader.storage.HeadBucket}
	nextClaim.ReleaseSequence, payload, err = allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{Role: nextClaim.Role, Environment: "production", SourceRevision: nextClaim.SourceRevision, ManifestSHA256: family}, roots, first.signer)
	if err != nil {
		t.Fatal(err)
	}
	qualificationEnvelope, err := trust.DecodeEnvelope(nextClaim.Production.Qualification)
	if err != nil {
		t.Fatal(err)
	}
	var nextQualification release.ProductionQualification
	if err := json.Unmarshal(qualificationEnvelope.Payload, &nextQualification); err != nil {
		t.Fatal(err)
	}
	nextQualification.Candidate.SourceRevision = nextClaim.SourceRevision
	nextClaim.Production.Qualification = sign(nextQualification, release.ProductionQualificationScope(nextQualification.Candidate), private)
	nextBundle := first.bundle
	nextBundle.Sequence = payload
	nextBundle.Claim = sign(nextClaim, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Role: nextClaim.Role, Environment: "production", Architecture: "arm64"}), first.signer)
	location := releasechannel.Location{Client: objects, Namespace: reader.storage.Namespace, Bucket: reader.storage.HeadBucket}
	if err := releasechannel.PublishContainer(t.Context(), location, nextBundle, roots, release.ContainerTarget{Cell: "GRU", Role: nextClaim.Role, Environment: "production", Architecture: "arm64"}, now, now.Add(time.Minute), func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return releasechannel.ReadContainerEvidence(ctx, location, nextClaim.Role, digest)
	}, allocations); err != nil {
		t.Fatal(err)
	}
	nextMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("higher genuine signed sequence: %v", err)
	}
	if err := nextMaterial.RetainReleaseFloors(t.Context()); err != nil {
		t.Fatalf("higher sequence could not advance its floor: %v", err)
	}
	advanced, advancedETag, err := floorStore.Load(t.Context(), "GRU")
	if err != nil || advancedETag == floorETag || advanced.NetBirdManager.ComponentFloors[0].ReleaseSequence <= originalFloors[0].ReleaseSequence ||
		advanced.NetBirdManager.ComponentFloors[1] != originalFloors[1] || advanced.NetBirdManager.ComponentFloors[2] != originalFloors[2] {
		t.Fatalf("successor reset unrelated role floors: %v", err)
	}
	oldWire, err := json.Marshal(first.bundle)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	channelOverrides[channelName] = oldWire
	mu.Unlock()
	rollbackMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, claim)
	if err != nil {
		t.Fatalf("historical still-current signed rollback fixture: %v", err)
	}
	if err := rollbackMaterial.RetainReleaseFloors(t.Context()); err == nil {
		t.Fatal("genuine lower signed sequence replaced the durable release floor")
	}
	mu.Lock()
	delete(channelOverrides, channelName)
	mu.Unlock()
	for fault, mutate := range map[string]func(*NetBirdManagerLaunch){
		"remove all":              func(l *NetBirdManagerLaunch) { l.ComponentFloors = nil },
		"partial set":             func(l *NetBirdManagerLaunch) { l.ComponentFloors[1] = NetBirdComponentFloor{} },
		"lower sequence":          func(l *NetBirdManagerLaunch) { l.ComponentFloors[0].ReleaseSequence-- },
		"equal sequence identity": func(l *NetBirdManagerLaunch) { l.ComponentFloors[0].ReleaseIdentity = strings.Repeat("f", 64) },
		"equal sequence image": func(l *NetBirdManagerLaunch) {
			l.ComponentFloors[0].Image = "gru.ocir.io/ns/netbird-server@sha256:" + strings.Repeat("f", 64)
		},
		"replace bundle evidence": func(l *NetBirdManagerLaunch) { l.ComponentFloors[0].BundleSHA256 = strings.Repeat("f", 64) },
		"migration namespace": func(l *NetBirdManagerLaunch) {
			l.ComponentFloors[0].SequenceNamespace += "other"
			l.ComponentFloors[0].ReleaseSequence++
		},
		"migration identity": func(l *NetBirdManagerLaunch) {
			l.ComponentFloors[0].SequenceMigrationSHA256 = strings.Repeat("f", 64)
			l.ComponentFloors[0].ReleaseSequence++
		},
	} {
		current, etag, err := floorStore.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		mutate(current.NetBirdManager)
		if _, err := floorStore.CompareAndSwap(t.Context(), current, etag); err == nil {
			t.Fatalf("floor journal accepted %s", fault)
		}
		retained, actualETag, err := floorStore.Load(t.Context(), "GRU")
		if err != nil || actualETag != advancedETag || !sameCapacityValue(retained.NetBirdManager, advanced.NetBirdManager) {
			t.Fatalf("refused %s changed the durable floor or launch: %v", fault, err)
		}
	}
	mu.Lock()
	observedImage += "OTHER"
	mu.Unlock()
	if err := claim.Check(t.Context()); err == nil {
		t.Fatal("actual instance image drift retained manager authority")
	}
	mu.Lock()
	observedImage = manager.ImageOCID
	mu.Unlock()
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- claim.ClaimGenesis(t.Context()) }()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent genesis accepted %d consumers; want one", successes)
	}
	if err := claim.ClaimGenesis(t.Context()); err == nil {
		t.Fatal("genesis authorization was consumed twice")
	}
	restarted, err := admit()
	if err != nil || !restarted.RecoveryRequired() {
		t.Fatalf("initializing store loss authorized new genesis: recovery=%t err=%v", restarted.RecoveryRequired(), err)
	}
	if err := restarted.MarkStoreReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, err = admit()
	if err != nil || !restarted.RecoveryRequired() || restarted.StoreGeneration() != claim.StoreGeneration() {
		t.Fatalf("ready store identity was reset: %+v %v", restarted, err)
	}
	restartedMaterial, err := ReadNetBirdComponents(t.Context(), factory, resolver, restarted)
	if err != nil {
		t.Fatalf("restarted actual manager lost signed component material: %v", err)
	}
	if err := restartedMaterial.RetainReleaseFloors(t.Context()); err != nil {
		t.Fatalf("ready store failed unchanged complete floor replay: %v", err)
	}
	// Historical initialized stores cannot invent missing release-floor evidence.
	readyRecord, readyETag, err := floorStore.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"initializing", "ready"} {
		missing := readyRecord
		launch := *missing.NetBirdManager
		launch.ComponentFloors, launch.StoreState = nil, state
		missing.NetBirdManager = &launch
		wire, err := json.Marshal(missing, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		writeOriginal(foundationObjectPrefix+"GRU.json", wire)
		if err := restartedMaterial.RetainReleaseFloors(t.Context()); err == nil {
			t.Fatalf("%s historical store synthesized missing release floors", state)
		}
		stillMissing, _, err := floorStore.Load(t.Context(), "GRU")
		if err != nil || stillMissing.NetBirdManager.ComponentFloors != nil {
			t.Fatalf("refused historical floor initialization mutated the journal: %v", err)
		}
	}
	readyWire, err := json.Marshal(readyRecord, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	writeOriginal(foundationObjectPrefix+"GRU.json", readyWire)
	_, restoredETag, err := floorStore.Load(t.Context(), "GRU")
	if err != nil || restoredETag != readyETag {
		t.Fatalf("historical fixtures did not restore the original ready record: %v", err)
	}
	for _, role := range netBirdComponentRoles() {
		component, err := restartedMaterial.Component(t.Context(), role)
		if err != nil || component.PullClaim().Scope.TaskPrincipal != entityid.Derive("netbird-component", claim.StoreGeneration(), role) {
			t.Fatalf("unchanged store restart reset component principal: %s %v", role, err)
		}
	}
	saved, _, err = reopened.Load(t.Context(), "GRU")
	if err != nil || !sameCapacityValue(saved.NetBirdManager.OriginalQuote, &originalQuote) {
		t.Fatalf("manager admission or store recovery changed original financial evidence: %v", err)
	}
	for fault, mutate := range map[string]func(*NetBirdManagerLaunch){
		"replace instance": func(l *NetBirdManagerLaunch) { l.InstanceID += "replacement" },
		"replace boot":     func(l *NetBirdManagerLaunch) { l.BootVolumeID += "replacement" },
		"reset store":      func(l *NetBirdManagerLaunch) { l.StoreState = "empty" },
	} {
		current, etag, err := reopened.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		mutate(current.NetBirdManager)
		if _, err := reopened.CompareAndSwap(t.Context(), current, etag); err == nil {
			t.Fatalf("bound original manager accepted %s", fault)
		}
		retained, actual, err := reopened.Load(t.Context(), "GRU")
		if err != nil || actual != etag || !sameCapacityValue(retained.NetBirdManager, saved.NetBirdManager) {
			t.Fatalf("refused %s changed protected manager binding: %v", fault, err)
		}
	}
	// Historical absence remains unknown; today's tariffs cannot reconstruct it.
	saved.NetBirdManager.OriginalQuote = nil
	legacyWire, err := json.Marshal(saved, json.Deterministic(true))
	if err != nil || bytes.Contains(legacyWire, []byte(`"originalQuote"`)) {
		t.Fatalf("absent historical manager quote changed legacy wire schema: %v", err)
	}
	write(foundationObjectPrefix+"GRU.json", legacyWire)
	legacy, etag, err := reopened.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	removed := legacy
	removed.NetBirdManager = nil
	if _, err := reopened.CompareAndSwap(t.Context(), removed, etag); err == nil {
		t.Fatal("historical manager could be erased before reconstructing quote evidence")
	}
	legacy.NetBirdManager.OriginalQuote = new(originalQuote.Clone())
	if _, err := reopened.CompareAndSwap(t.Context(), legacy, etag); err == nil {
		t.Fatal("historical manager acquired reconstructed original tariff evidence")
	}
	beforeLegacy := launchPosts
	restarted, err = admit()
	if err != nil || !restarted.RecoveryRequired() {
		t.Fatalf("legacy manager could not reopen its existing durable store: %v", err)
	}
	if err := restarted.MarkStoreReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	legacy, _, err = reopened.Load(t.Context(), "GRU")
	if err != nil || legacy.NetBirdManager.OriginalQuote != nil || launchPosts != beforeLegacy || creates != 6 {
		t.Fatalf("legacy manager reopen invented quote evidence or purchased resources: %v", err)
	}
	grant.Regions[0].NetBirdManager = nil
	publish()
	if err := restartedMaterial.Check(t.Context()); err == nil {
		t.Fatal("revoked actual manager retained component material")
	}
	if err := claim.Check(t.Context()); err == nil {
		t.Fatal("revoked same-grant manager role retained secret/process authority")
	}
	if err := claim.MarkStoreReady(t.Context()); err == nil {
		t.Fatal("revoked manager mutated store journal")
	}
}

type netBirdComponentFixture struct {
	authority ContainerReleaseAuthorityIntent
	claim     release.ContainerClaim
	bundle    release.ContainerBundle
	signer    ed25519.PrivateKey
	evidence  []string
}

func netBirdComponentFixtures(t *testing.T, root ed25519.PrivateKey, roots trust.Keyring, home bootstrap.StorageDomain, objects FoundationObjects, now time.Time,
	sign func(any, trust.Scope, ed25519.PrivateKey) []byte, write func(string, []byte),
) []netBirdComponentFixture {
	t.Helper()
	var result []netBirdComponentFixture
	allocations := release.SequenceLocation{Client: objects, Namespace: home.Namespace, Bucket: home.HeadBucket}
	for _, role := range netBirdComponentRoles() {
		public, signer, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		keyWire, err := trust.EncodeDelegatedPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		target := release.ContainerTarget{Cell: "GRU", Role: role, Environment: "production", Architecture: "arm64"}
		scope := release.ContainerScope(target)
		delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: keyWire, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(30*24*time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		delegationWire, err := trust.EncodeEnvelope(delegation)
		if err != nil {
			t.Fatal(err)
		}
		migration := release.SequenceMigration{Namespace: home.Namespace, Bucket: home.HeadBucket, Region: "GRU", Schema: release.SequenceMigrationSchema, SignerKeyID: keyID, SignerPublicKey: keyWire, Role: role, Environment: "production", SequenceFloor: 100}
		for _, cell := range []string{"GRU", "SJC", "FRA"} {
			migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
		}
		migrationEnvelope, err := release.SignSequenceMigration(migration, now.Add(-time.Minute), root)
		if err != nil {
			t.Fatal(err)
		}
		migrationWire, err := trust.EncodeEnvelope(migrationEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		migrationSHA, err := trust.Fingerprint(migrationEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := allocations.ImportMigration(t.Context(), migrationEnvelope, roots, role, "production", now); err != nil {
			t.Fatal(err)
		}
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "gru.ocir.io/ns/" + role + "@sha256:" + strings.Repeat("a", 64), SourceRepository: "https://github.com/TerraScale/" + role, SourceRevision: strings.Repeat("b", 40), SourceTreeSHA256: strings.Repeat("c", 64), Cell: "GRU", Environment: "production", Role: role, Architecture: "arm64", SequenceMigrationSHA256: migrationSHA, QualificationSHA256: strings.Repeat("a", 64)}
		family, err := claim.WorkerFamilyDigest()
		if err != nil {
			t.Fatal(err)
		}
		sequence, familyWire, err := allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{Role: role, Environment: "production", SourceRevision: claim.SourceRevision, ManifestSHA256: family}, roots, signer)
		if err != nil {
			t.Fatal(err)
		}
		claim.ReleaseSequence = sequence
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: claim.QualificationSHA256, Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: "arm64", Role: role}}
		var evidence []string
		for _, gate := range []string{"runtime-ha", "workload-safety"} {
			wire := []byte("test-only retained " + role + " " + gate)
			sum := sha256.Sum256(wire)
			digest := hex.EncodeToString(sum[:])
			name := releasechannel.ContainerEvidenceObject(role, digest)
			evidence = append(evidence, name)
			write(name, wire)
			qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: digest, Bytes: int64(len(wire)), CompletedAt: now.Add(-2 * time.Minute)})
		}
		claim.Production = release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), root)}
		bundle := release.ContainerBundle{Claim: sign(claim, scope, signer), Delegation: delegationWire, Migration: migrationWire, Sequence: familyWire}
		location := releasechannel.Location{Client: objects, Namespace: home.Namespace, Bucket: home.HeadBucket}
		if err := releasechannel.PublishContainer(t.Context(), location, bundle, roots, target, now, now.Add(time.Minute), func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return releasechannel.ReadContainerEvidence(ctx, location, role, digest)
		}, allocations); err != nil {
			t.Fatal(err)
		}
		result = append(result, netBirdComponentFixture{authority: ContainerReleaseAuthorityIntent{Role: role, Environment: "production", Cells: []string{"GRU"}, Architectures: []string{"arm64"}, ImageRepository: "gru.ocir.io/ns/" + role, SourceRepository: claim.SourceRepository, DelegationWire: delegationWire, SequenceMigrationWire: migrationWire}, claim: claim, bundle: bundle, signer: signer, evidence: evidence})
	}
	return result
}
