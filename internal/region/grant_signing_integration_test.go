package region

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type lostFoundationPublicationReply struct {
	next common.HTTPRequestDispatcher
	lost bool
}

func (f *lostFoundationPublicationReply) Do(request *http.Request) (*http.Response, error) {
	response, err := f.next.Do(request)
	if err == nil && request.Method == http.MethodPut && !f.lost {
		f.lost = true
		response.Body.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return response, err
}

func TestFoundationBundlePublishesExplicitCurrentRootsThroughSDK(t *testing.T) {
	f := newCurrentDiscoveryScenario(t)
	f.rotate()
	f.publish()
	chain, err := trust.EncodeRootChain(f.chain)
	if err != nil {
		t.Fatal(err)
	}
	bundle := RetainedFoundation{TenancyID: f.grant.TenancyID, Namespace: "ns", RootChainWire: chain,
		AnchorWire: bytes.Clone(f.objects[foundationDiscoveryObject]), GrantWire: bytes.Clone(f.objects["bootstrap/"+foundationGrantObject])}
	_, client, _ := foundationProtocolStore(t)
	remote := client.(*objectstorage.ObjectStorageClient)
	fault := &lostFoundationPublicationReply{next: remote.HTTPClient}
	remote.HTTPClient = fault
	for range 2 {
		if err := publishFoundationBundle(t.Context(), client.(foundationDiscoveryObjects), f.grant.TenancyID, f.genesis, bundle); err != nil {
			t.Fatal(err)
		}
	}
	if !fault.lost {
		t.Fatal("scenario did not interrupt an accepted SDK publication")
	}
	lineage, err := trust.VerifyRootChain(f.genesis, foundationChainIdentity(f.anchor.DeploymentID), f.chain)
	if err != nil {
		t.Fatal(err)
	}
	observedChain, err := readDiscoveryObject(t.Context(), client, "ns", foundationRootChainObject, trust.MaxRootChainBytes)
	if err != nil || !bytes.Equal(observedChain, chain) {
		t.Fatalf("published root lineage changed: %v", err)
	}
	resolver, err := discoverFoundation(t.Context(), client.(foundationDiscoveryObjects), f.grant.TenancyID, lineage.Current)
	if err != nil {
		t.Fatal(err)
	}
	if footprint, err := resolver.Footprint.AuthorizedRegions(t.Context()); err != nil || len(footprint.Regions) != 1 {
		t.Fatalf("published footprint=%+v error=%v", footprint, err)
	}
	original := bytes.Clone(bundle.GrantWire)
	bundle.GrantWire[len(bundle.GrantWire)-2] ^= 1
	if err := publishFoundationBundle(t.Context(), client.(foundationDiscoveryObjects), f.grant.TenancyID, f.genesis, bundle); err == nil {
		t.Fatal("tampered grant published")
	}
	bundle.GrantWire = original
	bundle.TenancyID = "ocid1.tenancy.oc1..foreign"
	if err := publishFoundationBundle(t.Context(), client.(foundationDiscoveryObjects), f.grant.TenancyID, f.genesis, bundle); err == nil {
		t.Fatal("foreign tenancy bundle published")
	}
}
