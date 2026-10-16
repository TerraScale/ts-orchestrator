//go:build fixturetest

package materialsource

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type sourceInstanceProvider struct {
	common.ConfigurationProvider
	token string
}

func (p sourceInstanceProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{AuthType: common.InstancePrincipal}, nil
}
func (p sourceInstanceProvider) KeyID() (string, error) { return p.token, nil }

type sourceMetadataHTTP struct {
	client   *http.Client
	endpoint string
}

func (m sourceMetadataHTTP) fetch(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("metadata status %d", response.StatusCode)
	}
	return io.ReadAll(response.Body)
}
func (m sourceMetadataHTTP) FetchInstanceID(ctx context.Context) (string, error) {
	wire, err := m.fetch(ctx, "/id")
	return string(wire), err
}
func (m sourceMetadataHTTP) FetchDescriptor(ctx context.Context) (bootstrapstart.Descriptor, error) {
	wire, err := m.fetch(ctx, "/descriptor")
	if err != nil {
		return bootstrapstart.Descriptor{}, err
	}
	return bootstrapstart.ParseDescriptor(wire)
}

// Only remote metadata/OCI protocol responses are simulated. The actor still
// verifies the actual test binary, signed roots, instance token and SDK observations.
func sourceFounderFixture(t *testing.T, grant region.VerifiedBootstrapMaterial, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, objects *objectstorage.ObjectStorageClient, protocol *materialProtocol, reader *region.SignedFootprint, instanceID string) *region.SourceFounder {
	t.Helper()
	actor, _ := sourceFounderFixtureWithAuthority(t, grant, anchor, roots, objects, protocol, reader, instanceID)
	return actor
}

func sourceFounderFixtureWithAuthority(t *testing.T, grant region.VerifiedBootstrapMaterial, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, objects *objectstorage.ObjectStorageClient, protocol *materialProtocol, reader *region.SignedFootprint, instanceID string) (*region.SourceFounder, *region.HomeIAMAuthority) {
	t.Helper()
	template, err := bootstrap.VerifyRegionalStartupTemplate(grant.FoundationGrantWire(), roots, anchor, oci.Region(strings.ToUpper(grant.Config().Cell)), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := template.ManifestFor(template.Template().SeedSlot, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.Profiles[0]
	for _, p := range manifest.Profiles {
		if p.Slot == template.Template().SeedSlot {
			profile = p
		}
	}
	address, err := template.SlotPrivateIP(profile.Slot)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{"sub": instanceID, "opc-instance": instanceID, "ptype": "instance", "tenant": "ocid1.tenancy.oc1..test", "exp": time.Now().Add(time.Hour).Unix()})
	provider := sourceInstanceProvider{ConfigurationProvider: common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "unused", manifest.OCIRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil), token: "ST$e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"}
	protocol.mu.Lock()
	if protocol.policies == nil {
		protocol.policies = map[string]identity.Policy{}
	}
	protocol.mu.Unlock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if protocol.interceptIAM != nil && protocol.interceptIAM(w, r) {
			return
		}
		if r.URL.Path == "/id" {
			io.WriteString(w, instanceID)
			return
		}
		if r.URL.Path == "/descriptor" {
			json.MarshalWrite(w, bootstrapstart.Descriptor{SchemaVersion: 1, Slot: profile.Slot})
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), provider.token) {
			w.WriteHeader(401)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/20160918/instances/"):
			json.MarshalWrite(w, core.Instance{Id: new(instanceID), CompartmentId: new(profile.CompartmentOCID), ImageId: new(manifest.ImageOCID), AvailabilityDomain: new(profile.AvailabilityDomain), FaultDomain: new(profile.FaultDomain), Shape: new(profile.Shape), LifecycleState: core.InstanceLifecycleStateRunning, FreeformTags: map[string]string{"BootstrapCreateKey": "source-founder-" + profile.Slot}})
		case r.URL.Path == "/20160918/vnicAttachments":
			json.MarshalWrite(w, []core.VnicAttachment{{Id: new("ocid1.vnicattachment.oc1." + manifest.OCIRegion + ".test"), InstanceId: new(instanceID), CompartmentId: new(profile.CompartmentOCID), VnicId: new("ocid1.vnic.oc1." + manifest.OCIRegion + ".test"), SubnetId: new(profile.SubnetOCID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}})
		case strings.HasPrefix(r.URL.Path, "/20160918/vnics/"):
			json.MarshalWrite(w, core.Vnic{Id: new("ocid1.vnic.oc1." + manifest.OCIRegion + ".test"), CompartmentId: new(profile.CompartmentOCID), AvailabilityDomain: new(profile.AvailabilityDomain), SubnetId: new(profile.SubnetOCID), PrivateIp: new(address), IsPrimary: new(true), NsgIds: profile.NetworkSecurityGroupOCIDs, LifecycleState: core.VnicLifecycleStateAvailable})
		case strings.HasPrefix(r.URL.Path, "/20160918/subnets/"):
			json.MarshalWrite(w, core.Subnet{Id: new(profile.SubnetOCID), CompartmentId: new(profile.CompartmentOCID), VcnId: new("ocid1.vcn.oc1." + manifest.OCIRegion + ".test"), LifecycleState: core.SubnetLifecycleStateAvailable})
		case strings.HasPrefix(r.URL.Path, "/20160918/policies"):
			protocol.mu.Lock()
			defer protocol.mu.Unlock()
			if r.Method == http.MethodPost {
				var details identity.CreatePolicyDetails
				if json.UnmarshalRead(r.Body, &details) != nil || r.Header.Get("opc-retry-token") == "" {
					w.WriteHeader(400)
					return
				}
				id := "ocid1.policy.oc1.." + digestWire([]byte(*details.Name))
				policy := identity.Policy{Id: new(id), Name: details.Name, CompartmentId: details.CompartmentId, Statements: details.Statements, LifecycleState: identity.PolicyLifecycleStateActive}
				protocol.policies[id] = policy
				json.MarshalWrite(w, policy)
				return
			}
			if r.URL.Path == "/20160918/policies" {
				items := []identity.Policy{}
				for _, p := range protocol.policies {
					if r.URL.Query().Get("name") == "" || r.URL.Query().Get("name") == *p.Name {
						items = append(items, p)
					}
				}
				json.MarshalWrite(w, items)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/20160918/policies/")
			p, ok := protocol.policies[id]
			if !ok {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"NotFound","message":"absent"}`)
				return
			}
			json.MarshalWrite(w, p)
		default:
			t.Errorf("unexpected founder SDK request %s %s", r.Method, r.URL)
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(server.Close)
	factory, err := ociclient.New(provider, ociclient.Options{Region: manifest.OCIRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := bootstrapstart.NewOCIInstanceObserverWithClients(manifest.Cell, provider, &compute, &network)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&compute.BaseClient, &network.BaseClient, &iam.BaseClient} {
		client.Host = server.URL
		client.HTTPClient = server.Client()
		policy := common.NoRetryPolicy()
		client.Configuration.RetryPolicy = &policy
		ociclient.ConfigureRequestCancellation(client)
	}
	proof, err := bootstrapstart.VerifySourceFounderWithSources(t.Context(), factory, template, sourceMetadataHTTP{client: server.Client(), endpoint: server.URL}, observer)
	if err != nil {
		t.Fatal(err)
	}
	store, err := region.NewObjectFoundationStore(objects, grant.StorageDomain().Namespace, grant.StorageDomain().HeadBucket)
	if err != nil {
		t.Fatal(err)
	}
	resolver := region.FoundationResolver{Footprint: reader, Store: store}
	authority, err := region.NewHomeIAMAuthorityWithClient(t.Context(), proof, resolver, objects, roots)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := region.NewSourceFounderWithClient(t.Context(), resolver, authority, &iam)
	if err != nil {
		t.Fatal(err)
	}
	return actor, authority
}

func sourceFoundationRecords(t *testing.T, protocol *materialProtocol, grant region.FoundationGrant) {
	t.Helper()
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	for _, intent := range grant.Regions {
		cell := intent.Plan["cell"].(string)
		intentDigest, err := region.FoundationIntentDigest(intent)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]string{}
		for k, v := range intent.Plan["resource_ids"].(map[string]any) {
			ids[k] = v.(string)
		}
		path := "/n/namespace-a/b/gru-1-head/o/orchestrator/regions/v1/" + cell + ".json"
		record := region.FoundationRecord{SchemaVersion: 1, Cell: cell, OCIRegion: intent.Plan["region"].(string), TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: intent.Generation, IntentDigest: intentDigest, OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(), ResourceIDs: ids}
		if previous, err := os.ReadFile(protocol.objectPath(path)); err == nil {
			var old region.FoundationRecord
			if json.Unmarshal(previous, &old) == nil {
				record.SourcePolicyIDs = old.SourcePolicyIDs
				record.OperationID = old.OperationID
			}
		}
		wire, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err = protocol.put(path, wire); err != nil {
			t.Fatal(err)
		}
	}
}
