package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// This extends the real generation/publication fixture across a signed SFO
// anchor and a public-only SDK endpoint. Config markers exercise proof binding;
// house-rendered controller startup remains the app/CLI scenario's contract.
func assertHomeStartupPublicProof(t *testing.T, source *ColdStartMaterial, material VerifiedColdStartMaterial, home bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, root ed25519.PrivateKey, server *materialProtocol, now time.Time) {
	t.Helper()
	grantWire := material.Grant().FoundationGrantWire()
	template, err := bootstrap.VerifyStartupTemplate(grantWire, roots, home, now)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := NewStartupProjection(template, material, template.Template().SeedSlot)
	if err != nil {
		t.Fatal(err)
	}
	configs := make(map[string][]byte)
	for _, slot := range home.Anchor().ControllerSlots {
		configs[slot], err = json.Marshal(map[string]any{"nats": map[string]any{}, "controller": map[string]string{"cell": "gru", "slot": slot}})
		if err != nil {
			t.Fatal(err)
		}
	}
	bound, err := projection.BindConfigs(t.Context(), configs)
	if err != nil {
		t.Fatal(err)
	}
	var grant region.FoundationGrant
	grantEnvelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil || json.Unmarshal(grantEnvelope.Payload, &grant) != nil {
		t.Fatal("decode signed foundation fixture")
	}
	var registration *bootstrap.InitialSourceRegistration
	for _, item := range grant.Regions {
		if item.BootstrapMaterial != nil && item.BootstrapMaterial.Config.Cell == "sfo" {
			registration = item.BootstrapMaterial.SourceRegistration
		}
	}
	if registration == nil {
		t.Fatal("signed SFO registration missing")
	}
	spoke := home.Anchor()
	spoke.Cell, spoke.OCIRegion, spoke.ClusterID = registration.Cell, "us-sanjose-1", registration.ClusterID
	spoke.StorageDomain, spoke.ControllerSlots = registration.StorageDomain, registration.ControllerSlots
	spoke.InitialSourceRegistration, spoke.LedgerDelegationWire = new(registration.Clone()), nil
	intent, err := oci.ParseRegionIntent(spoke.InitialRegionIntentWire)
	if err != nil {
		t.Fatal(err)
	}
	intent.Regions = append(intent.Regions, oci.RegionMapping{Cell: oci.RegionSFO, OCIRegion: spoke.OCIRegion})
	spoke.InitialRegionIntentWire, err = trust.EncodePayload(intent)
	if err != nil {
		t.Fatal(err)
	}
	spoke.InitialRegionIntentSHA256 = digestWire(spoke.InitialRegionIntentWire)
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(spoke, home.IssuedAt(), home.ExpiresAt(), root)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: spoke.DeploymentID, Environment: spoke.Environment, Cell: spoke.Cell}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var publicReads, forbiddenRequests atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/n/") {
			forbiddenRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"code":"NotAuthorized","message":"public source reader cannot write or read Vault"}`)
			return
		}
		publicReads.Add(1)
		server.ServeHTTP(w, r)
	}))
	defer endpoint.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(grant.TenancyID, "ocid1.user.oc1..peer", spoke.OCIRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	publicObjects, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	publicObjects.Host, publicObjects.HTTPClient = endpoint.URL, endpoint.Client()
	noRetry := common.NoRetryPolicy()
	publicObjects.Configuration.RetryPolicy = &noRetry
	ociclient.ConfigureRequestCancellation(&publicObjects.BaseClient)
	authority, err := bootstrap.LoadHomeStartupAuthority(t.Context(), grantWire, anchor, roots, &publicObjects, now)
	if err != nil || authority.Manifest().Cell != oci.RegionGRU || authority.Digest() != bound.Digest() {
		t.Fatalf("public SFO to GRU startup proof: %v", err)
	}
	public, err := authority.ControllerResponsePublicKey()
	if err != nil || base64.StdEncoding.EncodeToString(public) != material.Record().Public.ControllerResponsePublicKey {
		t.Fatalf("home response key: %v", err)
	}
	responseWire, err := os.ReadFile(filepath.Join(source.directory, template.Template().SeedSlot+"-response.key"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(responseWire)))
	clear(responseWire)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatal("invalid fixture response key")
	}
	defer clear(private)
	message := []byte("same-grant home capacity response")
	if !ed25519.Verify(public, message, ed25519.Sign(ed25519.PrivateKey(private), message)) {
		t.Fatal("public home key could not verify actual controller response signer")
	}
	public[0] ^= 1
	again, err := authority.ControllerResponsePublicKey()
	if err != nil || base64.StdEncoding.EncodeToString(again) != material.Record().Public.ControllerResponsePublicKey || authority.VerifyCurrent(t.Context(), now) != nil {
		t.Fatal("home public key was mutable or lost current provenance")
	}
	if publicReads.Load() == 0 || forbiddenRequests.Load() != 0 {
		t.Fatal("public verification used non-public source APIs")
	}
	changedGrant := bytes.Clone(grantWire)
	changedGrant[len(changedGrant)-1] ^= 1
	if _, err := bootstrap.LoadHomeStartupAuthority(t.Context(), changedGrant, anchor, roots, &publicObjects, now); err == nil {
		t.Fatal("spoke accepted another foundation grant")
	}
	homeTemplate, err := bootstrap.VerifyHomeStartupTemplate(grantWire, roots, anchor, now)
	if err != nil {
		t.Fatal(err)
	}
	proofEnvelope, err := trust.DecodeEnvelope(bound.Wire())
	if err != nil {
		t.Fatal(err)
	}
	var proof bootstrap.DerivedStartupBinding
	if json.Unmarshal(proofEnvelope.Payload, &proof) != nil {
		t.Fatal("decode public proof")
	}
	proof.MaterialRecord = bytes.Replace(proof.MaterialRecord, []byte(material.Record().Public.ControllerResponsePublicKey), []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))), 1)
	payload, err := trust.EncodePayload(proof)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := os.ReadFile(filepath.Join(source.directory, "founder-ledger.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ledger)
	forged, err := trust.Sign(payload, bootstrap.DerivedStartupScope(proof.Manifest), proofEnvelope.IssuedAt, proofEnvelope.ExpiresAt, ed25519.PrivateKey(ledger))
	if err != nil {
		t.Fatal(err)
	}
	forgedWire, err := trust.EncodeEnvelope(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.VerifyDerivedStartupAuthority(t.Context(), homeTemplate, &publicObjects, forgedWire, now); err == nil {
		t.Fatal("source-signed substituted response key bypassed exact public CAS binding")
	}
	domain := home.StorageDomain()
	_, err = publicObjects.PutObject(ociclient.RequestContext(t.Context()), objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(source.key), PutObjectBody: io.NopCloser(bytes.NewReader(forgedWire))})
	if service, ok := common.IsServiceError(err); !ok || service.GetHTTPStatusCode() != http.StatusForbidden || forbiddenRequests.Load() != 1 {
		t.Fatalf("public source write denial: %v", err)
	}
}
