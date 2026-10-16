package bootstrapstart

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// Signed objects cross the actual OCI SDK HTTP transport and durable floor.
func TestRuntimeAuthorityHTTPIntegration(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	founderFixtureWithAdmissibleRelease(t, fixture)
	objects := fixture.objects.items
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
			http.Error(w, "expected signed SDK GET", http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/n/namespace-a/b/")
		bucket, key, ok := strings.Cut(path, "/o/")
		wire, exists := objects[bucket+"/"+key]
		if !ok || !exists {
			http.Error(w, `{"code":"NotFound","message":"absent"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", digestWire(wire))
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test-fingerprint", string(private), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.Host, client.HTTPClient = server.URL, server.Client()

	for _, slot := range []string{"controller-c", "controller-a"} {
		t.Run(slot, func(t *testing.T) {
			marker := fixture.accepted
			marker.Slot, marker.PrimaryPrivateIP = slot, fixture.plan.SeedPrivateIP
			marker.ManifestSHA256 = digestWire(fixture.manifests[slot])
			marker.ImageOCID = fixture.plan.Peers[0].ImageOCID
			for _, peer := range fixture.plan.Peers {
				if peer.Slot == slot {
					marker.PrimaryPrivateIP = peer.PrivateIP
				}
			}
			accepted := acceptedIdentityFixture(t)
			accepted.DeploymentID, accepted.ClusterID = marker.DeploymentID, fixture.current.Anchor.Anchor().ClusterID
			accepted.Environment, accepted.Slot, accepted.SeedSlot = fixture.plan.Environment, slot, fixture.plan.SeedSlot
			accepted.InstanceOCID, accepted.ImageOCID = marker.InstanceOCID, marker.ImageOCID
			accepted.PrimaryVNICOCID, accepted.PrimaryPrivateIP = marker.PrimaryVNICOCID, marker.PrimaryPrivateIP
			accepted.MaterialReferences = acceptedReferences(slot)
			accepted.ControllerBindings = []ControllerBinding{accepted.localBinding()}
			if err := accepted.Validate(); err != nil {
				t.Fatal(err)
			}
			floor := testFounderFloor(t)
			if err := floor.Initialize(fixture.selection.Generation, fixture.current.SelectionSHA256); err != nil {
				t.Fatal(err)
			}
			reader, err := NewCurrentFounderAuthorityReader(fixture.baked, marker, &client, floor)
			if err != nil {
				t.Fatal(err)
			}
			authority, err := reader.ReadRuntimeAuthority(t.Context(), accepted, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			identity := authority.Identity()
			if identity.Slot != slot || identity.SeedSlot != "controller-c" || identity.InstanceID != marker.InstanceOCID ||
				identity.PrivateIP != marker.PrimaryPrivateIP || identity.SeedPrivateIP != fixture.plan.SeedPrivateIP ||
				!authority.Anchor().IsVerified() || !fixture.now.Before(authority.ExpiresAt()) {
				t.Fatal("runtime authority lost signed slot or accepted OCI binding")
			}
			changed := accepted
			changed.ClusterID = "0000000000NBCYX286D4RHE6ZP"
			if _, err := reader.ReadRuntimeAuthority(t.Context(), changed, fixture.now); err == nil {
				t.Fatal("runtime accepted another cluster")
			}
			changed = accepted
			changed.InstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.other"
			changed.ControllerBindings = []ControllerBinding{changed.localBinding()}
			if _, err := reader.ReadRuntimeAuthority(t.Context(), changed, fixture.now); err == nil {
				t.Fatal("runtime accepted another OCI instance")
			}
			if _, err := reader.ReadRuntimeAuthority(t.Context(), accepted, fixture.now.Add(2*time.Hour)); err == nil {
				t.Fatal("runtime accepted an expired current selection")
			}
		})
	}
}
