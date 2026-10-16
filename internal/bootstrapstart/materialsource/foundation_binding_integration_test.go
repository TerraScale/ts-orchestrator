//go:build fixturetest

package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestBoundFoundationStartupSDKCAS(t *testing.T) {
	for _, soleFounderReference := range []bool{false, true} {
		name := "all finite resource fields"
		if soleFounderReference {
			name = "sole founder image compartment reference"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			originalAnchor, _, roots, root, _ := materialSourceAnchor(t)
			identity := originalAnchor.Anchor()
			config := bootstrapmaterial.Config{Environment: identity.Environment, Region: identity.OCIRegion, Cell: "gru", DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID, SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
				Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			ids := map[string]string{}
			helperIDs := map[string]any{}
			for role, kind := range map[string]string{"control_compartment": "compartment", "network_compartment": "compartment", "workload_compartment": "compartment", "vcn": "vcn", "subnet": "subnet", "network_security_group": "networksecuritygroup", "vault": "vault", "key": "key"} {
				idRegion := config.Region
				if kind == "compartment" {
					idRegion = ""
				}
				ids[role] = "ocid1." + kind + ".oc1." + idRegion + "." + strings.ReplaceAll(role, "_", "")
				if role == "key" {
					ids[role] = identity.StorageDomain.HeadKMSKeyOCID
				}
				helperIDs[role] = ids[role]
			}
			template, _ := sourceImageRecipe(t, root, roots, now, config, helperIDs, identity.InitialRegionIntentWire)
			if soleFounderReference {
				template.FounderResources.Slots[0].ImageCompartmentOCID = "foundation:GRU:control_compartment"
			} else {
				for index := range template.Profiles {
					profile := &template.Profiles[index]
					profile.CompartmentOCID, profile.SubnetOCID = "foundation:GRU:control_compartment", "foundation:GRU:subnet"
					profile.NetworkSecurityGroupOCIDs = []string{"foundation:GRU:network_security_group"}
					template.FounderResources.Slots[index].ImageCompartmentOCID = "foundation:GRU:control_compartment"
				}
				template.ManagedMaterial = &bootstrap.ManagedMaterialDomain{Namespace: identity.StorageDomain.Namespace, Bucket: "managed-material", KMSKeyOCID: "foundation:GRU:key", MemberCompartmentOCID: "foundation:GRU:workload_compartment", MemberSubnetOCID: "foundation:GRU:subnet", MemberSubnetCIDR: config.SubnetCIDR,
					RecipientSignerPublicKey: base64.StdEncoding.EncodeToString(root.Public().(ed25519.PublicKey)), NativeVerifierSHA256: strings.Repeat("c", 64)}
				var sidecar oci.RegionConfig
				if err := json.Unmarshal(template.ControllerFiles[1].Bytes, &sidecar); err != nil {
					t.Fatal(err)
				}
				sidecar.CompartmentID, sidecar.ImageCompartmentID, sidecar.SubnetID = "foundation:GRU:control_compartment", "foundation:GRU:control_compartment", "foundation:GRU:subnet"
				sidecar.NetworkSecurityGroupIDs = []string{"foundation:GRU:network_security_group"}
				template.ControllerFiles[1].Bytes = boundStartupJSON(t, sidecar)
				template.ControllerFiles[1].SHA256 = digestWire(template.ControllerFiles[1].Bytes)
			}
			if err := template.ValidateFoundation("GRU"); err != nil {
				t.Fatal(err)
			}
			originalTemplateWire := boundStartupJSON(t, template)
			configWire := boundStartupJSON(t, config)
			installation := entityid.New()
			identity.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
			registration := bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: identity.DeploymentID, Environment: identity.Environment, ClusterID: identity.ClusterID, Cell: identity.Cell, Generation: 1, PlanSHA256: digestWire(configWire), SeedSlot: template.SeedSlot,
				ControllerSlots: identity.ControllerSlots, StorageDomain: identity.StorageDomain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
			pins := map[string]any{}
			if soleFounderReference {
				for role, id := range ids {
					pins[role] = id
				}
			}
			grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 2, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration"}
			intent := region.FoundationIntent{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": config.Region, "tenancy_id": grant.TenancyID, "parent_compartment_id": grant.ParentCompartmentID, "shared_compartment_id": grant.SharedCompartmentID, "network_cidr": "10.251.0.0/16", "subnet_cidr": config.SubnetCIDR, "resource_ids": pins},
				BootstrapMaterial: &region.BootstrapMaterialIntent{InstallationID: installation, PlanSHA256: registration.PlanSHA256, Config: config, SourceVaultTarget: bootstrapmaterial.VaultTarget{CompartmentOCID: ids["control_compartment"], VaultOCID: ids["vault"], KMSKeyOCID: ids["key"]}, Startup: &template, SourceRegistration: &registration}}
			grant.Regions = []region.FoundationIntent{intent}
			scope := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: identity.DeploymentID, Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: identity.ClusterID}
			signGrant := func(value region.FoundationGrant) []byte {
				t.Helper()
				payload, err := trust.EncodePayload(value)
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(30*time.Minute), root)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := trust.EncodeEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
				return wire
			}
			wire := signGrant(grant)
			identity.LedgerDelegationWire = nil
			identity.InitialSourceRegistration = &registration
			identity.FoundationScope = &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID, TenancyID: grant.TenancyID, OCIRegion: config.Region, StorageDomain: identity.StorageDomain, GrantGeneration: 1, GrantSHA256: digestWire(wire)}
			anchorEnvelope, err := bootstrap.SignBootstrapAnchor(identity, now.Add(-time.Minute), now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, now, bootstrap.BootstrapAnchorTrustPolicy())
			if err != nil {
				t.Fatal(err)
			}
			protocol := &materialProtocol{directory: t.TempDir()}
			var observationMu sync.Mutex
			reads := map[string]int{}
			live := map[string]map[string]any{}
			for _, role := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
				live["/20160918/compartments/"+ids[role]] = map[string]any{"id": ids[role], "compartmentId": grant.ParentCompartmentID, "lifecycleState": "ACTIVE"}
			}
			live["/20160918/vcns/"+ids["vcn"]] = map[string]any{"id": ids["vcn"], "compartmentId": ids["network_compartment"], "cidrBlock": "10.251.0.0/16", "lifecycleState": "AVAILABLE"}
			live["/20160918/subnets/"+ids["subnet"]] = map[string]any{"id": ids["subnet"], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "cidrBlock": config.SubnetCIDR, "prohibitPublicIpOnVnic": true, "lifecycleState": "AVAILABLE"}
			live["/20160918/networkSecurityGroups/"+ids["network_security_group"]] = map[string]any{"id": ids["network_security_group"], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "lifecycleState": "AVAILABLE"}
			live["/20180608/vaults/"+ids["vault"]] = map[string]any{"id": ids["vault"], "compartmentId": ids["control_compartment"], "lifecycleState": "ACTIVE", "vaultType": "DEFAULT", "managementEndpoint": "https://fixture-management.kms." + config.Region + ".oraclecloud.com"}
			live["/20180608/keys/"+ids["key"]] = map[string]any{"id": ids["key"], "compartmentId": ids["control_compartment"], "vaultId": ids["vault"], "lifecycleState": "ENABLED", "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}}
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || !strings.Contains(r.Host, config.Region) {
					t.Errorf("request escaped signed regional SDK boundary: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				observationMu.Lock()
				if r.Method == http.MethodGet {
					reads[r.URL.Path]++
				}
				row := live[r.URL.Path]
				if row != nil {
					w.Header().Set("Content-Type", "application/json")
					if err := json.MarshalWrite(w, row); err != nil {
						t.Error(err)
					}
				}
				observationMu.Unlock()
				if row == nil {
					protocol.ServeHTTP(w, r)
				}
			}))
			t.Cleanup(endpoint.Close)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			originalTransport := http.DefaultTransport
			transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: endpoint.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(endpoint.URL, "https://"))
			}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider := common.NewRawConfigurationProvider(grant.TenancyID, "ocid1.user.oc1..test", config.Region, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
			factory, err := ociclient.New(provider, ociclient.Options{Region: config.Region, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
			if err != nil {
				t.Fatal(err)
			}
			objects, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			store, err := region.NewObjectFoundationStore(&objects, identity.StorageDomain.Namespace, identity.StorageDomain.HeadBucket)
			if err != nil {
				t.Fatal(err)
			}
			intentDigest, err := region.FoundationIntentDigest(intent)
			if err != nil {
				t.Fatal(err)
			}
			record := region.FoundationRecord{SchemaVersion: 1, GrantSHA256: digestWire(wire), Cell: "GRU", OCIRegion: config.Region, TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1, IntentDigest: intentDigest,
				OperationID: entityid.Derive("regional-foundation", grant.TenancyID, "GRU", "1"), Epoch: 1, Stage: "reconciled", StartedAt: now.Add(-time.Minute), UpdatedAt: now, CompletedAt: now, ResourceIDs: ids, ResourceProvenance: map[string]region.FoundationResourceProvenance{}}
			for role, id := range ids {
				record.ResourceProvenance[role] = region.FoundationResourceProvenance{ResourceID: id, Generation: 1, GrantSHA256: record.GrantSHA256,
					Create: region.PendingFoundationCreate{OperationID: record.OperationID, IntentDigest: intentDigest, FirstAttemptAt: record.StartedAt.Add(time.Second), Request: foundation.CreateIdentity{Key: role, Region: config.Region, RequestDigest: strings.Repeat("a", 64), RetryToken: strings.Repeat("b", 64)}}}
			}
			if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CompareAndSwap(t.Context(), record, ""); !errors.Is(err, region.ErrFoundationConflict) {
				t.Fatalf("duplicate create did not cross CAS conflict: %v", err)
			}
			grantPath := "/n/" + identity.StorageDomain.Namespace + "/b/" + identity.StorageDomain.HeadBucket + "/o/" + identity.StorageDomain.Prefix + "/foundation-scope-v1.json"
			publishCurrent := func(value []byte) {
				t.Helper()
				protocol.mu.Lock()
				defer protocol.mu.Unlock()
				if err := protocol.put(grantPath, value); err != nil {
					t.Fatal(err)
				}
			}
			publishCurrent(wire)
			verified, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, wire, roots, anchor, now)
			if err != nil {
				t.Fatal(err)
			}
			projected := verified.Template()
			if !verified.IsVerified() || verified.TemplateDigest() != digestWire(originalTemplateWire) || verified.TemplateDigest() == digestWire(boundStartupJSON(t, projected)) || !bytes.Equal(verified.GrantWire(), wire) {
				t.Fatal("bound startup lost its original signed template or grant identity")
			}
			if err := projected.Validate(); err != nil {
				t.Fatal(err)
			}
			for index, profile := range projected.Profiles {
				if profile.CompartmentOCID != ids["control_compartment"] || profile.SubnetOCID != ids["subnet"] || len(profile.NetworkSecurityGroupOCIDs) != 1 || profile.NetworkSecurityGroupOCIDs[0] != ids["network_security_group"] || projected.FounderResources.Slots[index].ImageCompartmentOCID != ids["control_compartment"] {
					t.Fatal("profile or founder resource projection differs from owned resources")
				}
			}
			var sidecar oci.RegionConfig
			if err := json.Unmarshal(projected.ControllerFiles[1].Bytes, &sidecar); err != nil {
				t.Fatal(err)
			}
			if sidecar.CompartmentID != ids["control_compartment"] || sidecar.ImageCompartmentID != ids["control_compartment"] || sidecar.SubnetID != ids["subnet"] || len(sidecar.NetworkSecurityGroupIDs) != 1 || sidecar.NetworkSecurityGroupIDs[0] != ids["network_security_group"] || projected.ControllerFiles[1].SHA256 != digestWire(projected.ControllerFiles[1].Bytes) {
				t.Fatal("OCI sidecar projection lost concrete IDs or content digest")
			}
			if !soleFounderReference && (projected.ManagedMaterial.KMSKeyOCID != ids["key"] || projected.ManagedMaterial.MemberCompartmentOCID != ids["workload_compartment"] || projected.ManagedMaterial.MemberSubnetOCID != ids["subnet"]) {
				t.Fatal("managed material projection differs from owned resources")
			}
			observationMu.Lock()
			before := maps.Clone(reads)
			observationMu.Unlock()
			if err := verified.VerifyCurrentContext(t.Context(), now); err != nil {
				t.Fatal(err)
			}
			observationMu.Lock()
			for path, count := range before {
				if reads[path] != count*2 {
					t.Errorf("startup revalidation did not reread %s: before %d, after %d", path, count, reads[path])
				}
			}
			observationMu.Unlock()
			if _, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, wire, trust.Keyring{}, anchor, now); err == nil {
				t.Fatal("startup accepted revoked roots")
			}
			changed := grant
			changed.CleanupOwner = "tampered signed scope"
			if _, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, signGrant(changed), roots, anchor, now); err == nil {
				t.Fatal("startup accepted a signed grant outside its exact anchor pin")
			}
			tampered := bytes.Replace(wire, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			if bytes.Equal(tampered, wire) {
				t.Fatal("signature tamper did not change the wire")
			}
			if _, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, tampered, roots, anchor, now); err == nil {
				t.Fatal("startup accepted signature tampering")
			}
			publishCurrent(signGrant(changed))
			if err := verified.VerifyCurrentContext(t.Context(), now); err == nil {
				t.Fatal("startup revalidation accepted current grant revocation")
			}
			if _, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, wire, roots, anchor, now); err == nil {
				t.Fatal("new startup accepted a revoked protected grant")
			}
		})
	}
}

func boundStartupJSON(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
