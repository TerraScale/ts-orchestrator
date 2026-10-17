package fixturegen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func verifiedCaptureAnchor(t *testing.T, now time.Time) (bootstrap.VerifiedBootstrapAnchor, trust.Keyring) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegatePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(delegatePublic)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-a", "controller-b", "controller-c"}
	var capabilities []trust.Capability
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z",
			Cell: "GRU", Environment: "production", Role: "controller", Slots: slots, Actions: []string{"sign"}})
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: publicWire, Capabilities: capabilities},
		now.Add(-time.Minute), now.Add(23*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	regionWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(regionWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", ControllerSlots: slots, LedgerDelegationWire: grantWire,
		StorageDomain: bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "head-bucket",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"},
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(digest[:]),
		InitialRegionIntentWire: regionWire}
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, now, now.Add(22*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyBootstrapAnchor(envelope, roots,
		bootstrap.BootstrapAnchorExpectation{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment,
			Cell: anchor.Cell}, now, trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return verified, roots
}

func TestCapturedInventoryUsesAnchorDomainAndExactKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	anchor, _ := verifiedCaptureAnchor(t, now)
	store, err := NewCapturingObjectStorage(now)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"signed":"record"}`)
	digest := sha256.Sum256(body)
	objectName := "private/bootstrap/controller-c/attempt-1/result.json"
	_, err = store.PutObject(t.Context(), objectstorage.PutObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("ledger-bucket"), ObjectName: &objectName,
		PutObjectBody: io.NopCloser(bytes.NewReader(body)), ContentLength: new(int64(len(body))),
		IfNoneMatch: new("*"), OpcSseKmsKeyId: new("ocid1.key.oc1.sa-saopaulo-1.ledger"),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
	})
	if err != nil {
		t.Fatal(err)
	}
	absent := "private/bootstrap/controller-c/attempt-1/absent.json"
	_, err = store.GetObject(t.Context(), objectstorage.GetObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("ledger-bucket"), ObjectName: &absent})
	if !isCaptureStatus(err, http.StatusNotFound) {
		t.Fatalf("expected missing key: %v", err)
	}
	controllers := []Controller{
		{Slot: "controller-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.a", GuestRoot: "controllers/controller-a/guest-root"},
		{Slot: "controller-b", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.b", GuestRoot: "controllers/controller-b/guest-root"},
		{Slot: "controller-c", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed", GuestRoot: "controllers/controller-c/guest-root"},
	}
	inventory, err := BuildCapturedInventory(anchor, controllers, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Routes) != 6 || len(inventory.Bodies) != 1 {
		t.Fatalf("capture inventory = %+v", inventory)
	}
	for _, route := range inventory.Routes {
		if route.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" ||
			route.RequestURI == "" || route.ControllerSlot == "" || route.InstanceOCID == "" {
			t.Fatalf("unbound captured route: %+v", route)
		}
	}
	wrong := slices.Clone(controllers)
	wrong[0].Slot = "another-slot"
	if _, err := BuildCapturedInventory(anchor, wrong, store); err == nil {
		t.Fatal("slot set outside signed anchor accepted")
	}
	wrongInstance := append([]Controller(nil), controllers...)
	wrongInstance[1].InstanceOCID = wrongInstance[0].InstanceOCID
	if _, err := BuildCapturedInventory(anchor, wrongInstance, store); err == nil {
		t.Fatal("two slots with one IMDS instance accepted")
	}
	escape := "outside-private-prefix/result.json"
	_, err = store.PutObject(t.Context(), objectstorage.PutObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("ledger-bucket"), ObjectName: &escape,
		PutObjectBody: io.NopCloser(bytes.NewReader(body)), ContentLength: new(int64(len(body))),
		IfNoneMatch: new("*"), OpcSseKmsKeyId: new("ocid1.key.oc1.sa-saopaulo-1.ledger"),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCapturedInventory(anchor, controllers, store); err == nil {
		t.Fatal("object outside signed private prefix accepted")
	}
}
