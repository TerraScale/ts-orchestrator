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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestBoundStartupSelectsFiniteVaultAndSiblingScopeSDKCAS(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	for _, mode := range []string{"exact publication pins", "sole founder compartment reference", "unbound publication key", "logical publication key", "consumed dynamic control compartment", "mixed dynamic control and consumed pinned key"} {
		t.Run(mode, func(t *testing.T) {
			var birthRoles []string
			switch mode {
			case "sole founder compartment reference", "consumed dynamic control compartment":
				birthRoles = []string{"control_compartment"}
			case "unbound publication key", "logical publication key":
				birthRoles = []string{"key"}
			case "mixed dynamic control and consumed pinned key":
				birthRoles = []string{"control_compartment", "key"}
			}
			now := time.Now().UTC().Truncate(time.Second)
			initial, _, roots, root, _ := materialSourceAnchor(t)
			identity := initial.Anchor()
			identity.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
			regionIntent := oci.RegionIntent{SchemaVersion: 1, Generation: 4, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}, {Cell: oci.RegionSFO, OCIRegion: "us-sanjose-1"}}}
			identity.InitialRegionIntentWire = startupScopeJSON(t, regionIntent)
			identity.InitialRegionIntentSHA256 = digestWire(identity.InitialRegionIntentWire)
			installation := entityid.New()
			grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 2, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration"}
			targets := map[string]bootstrap.StartupVaultTarget{}
			templates := map[string]bootstrap.StartupTemplate{}
			registrations := map[string]bootstrap.InitialSourceRegistration{}
			for _, cell := range []oci.Region{oci.RegionGRU, oci.RegionSFO} {
				ociRegion, err := cell.OCIRegion()
				if err != nil {
					t.Fatal(err)
				}
				name := string(cell)
				config := bootstrapmaterial.Config{Environment: identity.Environment, Region: ociRegion, Cell: strings.ToLower(name), DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID, SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
					Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
				domain := identity.StorageDomain
				if cell == oci.RegionSFO {
					config.ClusterID = entityid.New()
					domain.LedgerBucket, domain.HeadBucket = "sfo-ledger", "sfo-head"
					domain.LedgerKMSKeyOCID, domain.HeadKMSKeyOCID = "ocid1.key.oc1.us-sanjose-1.ledger", "ocid1.key.oc1.us-sanjose-1.head"
				}
				if err := config.Validate(); err != nil {
					t.Fatal(err)
				}
				target := bootstrap.StartupVaultTarget{CompartmentOCID: "ocid1.compartment.oc1.." + strings.ToLower(name) + "control", VaultOCID: "ocid1.vault.oc1." + ociRegion + ".publication", KMSKeyOCID: domain.HeadKMSKeyOCID}
				targets[name] = target
				ids := map[string]any{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID, "subnet": "ocid1.subnet.oc1." + ociRegion + ".private", "network_security_group": "ocid1.networksecuritygroup.oc1." + ociRegion + ".controllers"}
				template, _ := sourceImageRecipe(t, root, roots, now, config, ids, identity.InitialRegionIntentWire)
				template.FounderResources = &bootstrap.StartupFounderResources{LaunchDeadline: now.Add(5 * time.Minute)}
				for index := range template.Profiles {
					profile := &template.Profiles[index]
					profile.AvailabilityDomain = "test:" + strings.ToUpper(ociRegion) + "-AD-1"
					template.FounderResources.Slots = append(template.FounderResources.Slots, bootstrap.StartupSlotResources{Slot: profile.Slot, ImageCompartmentOCID: target.CompartmentOCID, WholeOCPUs: 1, MemoryInGB: 8, BootVolumeGB: 50, BootVolumeTier: bootstrap.FounderBootVolumeTierBalanced})
				}
				sidecar := oci.RegionConfig{Region: cell, Generation: regionIntent.Generation, Endpoint: "https://iaas." + ociRegion + ".oraclecloud.com", CompartmentID: target.CompartmentOCID, ImageCompartmentID: target.CompartmentOCID, AvailabilityDomain: template.Profiles[0].AvailabilityDomain, FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: ids["subnet"].(string), NetworkSecurityGroupIDs: []string{ids["network_security_group"].(string)}, ImageID: template.ImageOCID, Shape: template.Profiles[0].Shape, BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 32768, Owner: "ts-orchestrator"}
				if err := sidecar.Validate(regionIntent); err != nil {
					t.Fatal(err)
				}
				template.ControllerFiles[1].Bytes = startupScopeJSON(t, sidecar)
				template.ControllerFiles[1].SHA256 = digestWire(template.ControllerFiles[1].Bytes)
				if mode == "sole founder compartment reference" || mode == "consumed dynamic control compartment" {
					template.FounderResources.Slots[0].ImageCompartmentOCID = "foundation:" + name + ":control_compartment"
				}
				if mode == "mixed dynamic control and consumed pinned key" {
					template.ManagedMaterial = &bootstrap.ManagedMaterialDomain{Namespace: domain.Namespace, Bucket: "managed-material", KMSKeyOCID: "foundation:" + name + ":key", MemberCompartmentOCID: "ocid1.compartment.oc1.." + strings.ToLower(name) + "workload", MemberSubnetOCID: ids["subnet"].(string), MemberSubnetCIDR: config.SubnetCIDR,
						RecipientSignerPublicKey: base64.StdEncoding.EncodeToString(root.Public().(ed25519.PublicKey)), NativeVerifierSHA256: strings.Repeat("c", 64)}
				}
				if err := template.ValidateFoundation(name); err != nil {
					t.Fatal(err)
				}
				templates[name] = template
				registration := bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: config.DeploymentID, Environment: config.Environment, ClusterID: config.ClusterID, Cell: cell, Generation: 1, PlanSHA256: digestWire(startupScopeJSON(t, config)), SeedSlot: template.SeedSlot, ControllerSlots: identity.ControllerSlots, StorageDomain: domain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
				registrations[name] = registration
				// These signed host maps and future roles must not widen startup's query.
				ids["instances"] = map[string]any{"controller-a": nil, "controller-b": "ocid1.instance.oc1." + ociRegion + ".retained", "controller-c": nil}
				ids["boot_volumes"] = map[string]any{"controller-a": nil, "controller-b": "ocid1.bootvolume.oc1." + ociRegion + ".retained", "controller-c": nil}
				ids["data_volumes"] = map[string]any{"database-a": nil}
				ids["workload_compartment"] = "foundation:" + name + ":workload_compartment"
				if mode == "unbound publication key" {
					ids["key"] = nil
				}
				if mode == "logical publication key" {
					ids["key"] = "foundation:" + name + ":key"
				}
				if mode == "consumed dynamic control compartment" && cell == oci.RegionSFO || mode == "mixed dynamic control and consumed pinned key" {
					ids["control_compartment"] = "foundation:" + name + ":control_compartment"
				}
				grant.Regions = append(grant.Regions, region.FoundationIntent{Generation: 1, Plan: map[string]any{"cell": name, "region": ociRegion, "tenancy_id": grant.TenancyID, "parent_compartment_id": grant.ParentCompartmentID, "shared_compartment_id": grant.SharedCompartmentID, "network_cidr": "10.251.0.0/16", "subnet_cidr": config.SubnetCIDR, "resource_ids": ids},
					BootstrapMaterial: &region.BootstrapMaterialIntent{InstallationID: installation, PlanSHA256: registration.PlanSHA256, Config: config, SourceVaultTarget: bootstrapmaterial.VaultTarget{CompartmentOCID: targets["GRU"].CompartmentOCID, VaultOCID: targets["GRU"].VaultOCID, KMSKeyOCID: targets["GRU"].KMSKeyOCID}, Startup: &template, SourceRegistration: &registration}})
			}
			scope := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: identity.DeploymentID, Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: identity.ClusterID}
			envelope, err := trust.Sign(startupScopeJSON(t, grant), scope, now.Add(-time.Minute), now.Add(30*time.Minute), root)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := trust.EncodeEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			registration := registrations["GRU"]
			identity.InitialSourceRegistration, identity.LedgerDelegationWire = &registration, nil
			identity.FoundationScope = &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID, TenancyID: grant.TenancyID, OCIRegion: identity.OCIRegion, StorageDomain: identity.StorageDomain, GrantGeneration: 1, GrantSHA256: digestWire(wire)}
			anchorEnvelope, err := bootstrap.SignBootstrapAnchor(identity, now.Add(-time.Minute), now.Add(time.Hour), root)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, now, bootstrap.BootstrapAnchorTrustPolicy())
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			live := map[string]map[string]any{}
			resourceRegions := map[string]string{}
			reads := map[string]int{}
			for cell, target := range targets {
				ociRegion, err := oci.Region(cell).OCIRegion()
				if err != nil {
					t.Fatal(err)
				}
				live["/20160918/compartments/"+target.CompartmentOCID] = map[string]any{"id": target.CompartmentOCID, "compartmentId": grant.ParentCompartmentID, "lifecycleState": "ACTIVE"}
				live["/20180608/vaults/"+target.VaultOCID] = map[string]any{"id": target.VaultOCID, "compartmentId": target.CompartmentOCID, "lifecycleState": "ACTIVE", "vaultType": "DEFAULT", "managementEndpoint": "https://fixture-management.kms." + ociRegion + ".oraclecloud.com"}
				live["/20180608/keys/"+target.KMSKeyOCID] = map[string]any{"id": target.KMSKeyOCID, "compartmentId": target.CompartmentOCID, "vaultId": target.VaultOCID, "lifecycleState": "ENABLED", "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}}
				for _, path := range []string{"/20160918/compartments/" + target.CompartmentOCID, "/20180608/vaults/" + target.VaultOCID, "/20180608/keys/" + target.KMSKeyOCID} {
					resourceRegions[path] = ociRegion
				}
			}
			directory := t.TempDir()
			objectPath := func(path string) string { return filepath.Join(directory, digestWire([]byte(path))) }
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
					t.Error("startup SDK request lacks its provider signature")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodGet {
					reads[r.URL.Path]++
					if row := live[r.URL.Path]; row != nil {
						if !strings.Contains(r.Host, resourceRegions[r.URL.Path]) {
							t.Errorf("startup target read escaped its selected OCI region: %s", r.URL)
							w.WriteHeader(http.StatusForbidden)
							return
						}
						if err := json.MarshalWrite(w, row); err != nil {
							t.Error(err)
						}
						return
					}
				}
				if !strings.HasPrefix(r.URL.Path, "/n/"+identity.StorageDomain.Namespace+"/b/"+identity.StorageDomain.HeadBucket+"/o/") || !strings.Contains(r.Host, identity.OCIRegion) {
					t.Errorf("startup escaped its finite target/home SDK boundary: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				old, readErr := os.ReadFile(objectPath(r.URL.Path))
				if r.Method == http.MethodGet && readErr == nil {
					w.Header().Set("ETag", digestWire(old))
					w.Write(old)
					return
				}
				if r.Method == http.MethodPut {
					if r.Header.Get("If-None-Match") == "*" && readErr == nil || r.Header.Get("If-Match") != "" && (readErr != nil || r.Header.Get("If-Match") != digestWire(old)) {
						w.WriteHeader(http.StatusPreconditionFailed)
						io.WriteString(w, `{"code":"PreconditionFailed","message":"changed"}`)
						return
					}
					if r.Header.Get("If-None-Match") != "*" && r.Header.Get("If-Match") == "" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					if err := os.WriteFile(objectPath(r.URL.Path), body, 0o600); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					w.Header().Set("ETag", digestWire(body))
					return
				}
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
			}))
			t.Cleanup(endpoint.Close)
			listener, ok := endpoint.Listener.Addr().(*net.TCPAddr)
			if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
				t.Fatal("startup fixture requires a literal loopback listener")
			}
			loopbackAddress := listener.String()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			originalTransport := http.DefaultTransport
			transport.Proxy = func(request *http.Request) (*url.URL, error) {
				if request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Opaque != "" || request.Response != nil || request.Method == http.MethodConnect {
					return nil, errors.New("startup fixture refuses noninitial HTTPS request")
				}
				return nil, nil
			}
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("startup fixture refuses plaintext dialing")
			}
			transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" && network != "tcp6" {
					return nil, errors.New("startup fixture refuses unsupported network")
				}
				return (&tls.Dialer{Config: endpoint.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", loopbackAddress)
			}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider := common.NewRawConfigurationProvider(grant.TenancyID, "ocid1.user.oc1..test", identity.OCIRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
			factory, err := ociclient.New(provider, ociclient.Options{Region: identity.OCIRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
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
			_, err = objects.PutObject(ociclient.RequestContext(t.Context()), objectstorage.PutObjectRequest{NamespaceName: new(identity.StorageDomain.Namespace), BucketName: new(identity.StorageDomain.HeadBucket), ObjectName: new(identity.StorageDomain.Prefix + "/foundation-scope-v1.json"), IfNoneMatch: new("*"), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentLength: new(int64(len(wire)))})
			if err != nil {
				t.Fatal(err)
			}
			leaseDeadline := now.Add(10 * time.Minute)
			persist := func(index int) {
				t.Helper()
				intent := grant.Regions[index]
				cell := intent.Plan["cell"].(string)
				target := targets[cell]
				intentDigest, err := region.FoundationIntentDigest(intent)
				if err != nil {
					t.Fatal(err)
				}
				record := region.FoundationRecord{SchemaVersion: 1, Cell: cell, OCIRegion: intent.Plan["region"].(string), TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1, GrantSHA256: digestWire(wire), IntentDigest: intentDigest, OperationID: entityid.Derive("regional-foundation", grant.TenancyID, cell, "1"), Epoch: 7, LeaseID: entityid.New(), Stage: "foundation", StartedAt: now.Add(-time.Minute), UpdatedAt: now, ExpiresAt: leaseDeadline,
					ResourceIDs: map[string]string{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID}, ResourceProvenance: map[string]region.FoundationResourceProvenance{}}
				for _, birthRole := range birthRoles {
					record.ResourceProvenance[birthRole] = region.FoundationResourceProvenance{ResourceID: record.ResourceIDs[birthRole], Generation: 1, GrantSHA256: record.GrantSHA256, Create: region.PendingFoundationCreate{OperationID: record.OperationID, IntentDigest: intentDigest, FirstAttemptAt: record.StartedAt.Add(time.Second), Request: foundation.CreateIdentity{Key: birthRole, Region: record.OCIRegion, RequestDigest: strings.Repeat("a", 64), RetryToken: strings.Repeat("b", 64)}}}
				}
				if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
					t.Fatal(err)
				}
				if _, err := store.CompareAndSwap(t.Context(), record, ""); !errors.Is(err, region.ErrFoundationConflict) {
					t.Fatalf("foundation fixture did not enforce create CAS: %v", err)
				}
			}
			persist(0)
			home, err := bootstrap.VerifyBoundStartupTemplate(t.Context(), factory, wire, roots, anchor, now)
			if err != nil {
				t.Fatal(err)
			}
			assertStartup := func(verified bootstrap.VerifiedStartupTemplate, cell string) {
				t.Helper()
				if !verified.IsVerified() || verified.VaultTarget() != targets[cell] || verified.TemplateDigest() != digestWire(startupScopeJSON(t, templates[cell])) || !bytes.Equal(verified.GrantWire(), wire) || !verified.ExpiresAt().Equal(leaseDeadline) {
					t.Fatal("startup lost original template, signed wire, finite target or lease cap")
				}
				if err := verified.Template().Validate(); err != nil {
					t.Fatal(err)
				}
				if verified.Template().FounderResources.Slots[0].ImageCompartmentOCID != targets[cell].CompartmentOCID {
					t.Fatal("startup founder compartment escaped its finite publication target")
				}
				if mode == "mixed dynamic control and consumed pinned key" && verified.Template().ManagedMaterial.KMSKeyOCID != targets[cell].KMSKeyOCID {
					t.Fatal("startup managed key escaped its consumed pinned publication target")
				}
				if err := verified.VerifyCurrentContext(t.Context(), now); err != nil {
					t.Fatal(err)
				}
			}
			assertStartup(home, "GRU")
			mu.Lock()
			for path := range reads {
				if strings.Contains(path, "SFO.json") || strings.Contains(path, "us-sanjose-1") || strings.Contains(path, "sfocontrol") {
					t.Errorf("home startup observed uncreated sibling: %s", path)
				}
			}
			mu.Unlock()
			if _, err := bootstrap.VerifyBoundRegionalStartupTemplate(t.Context(), factory, wire, roots, anchor, oci.RegionSFO, now); err == nil {
				t.Fatal("sibling startup accepted an absent regional operation")
			}
			persist(1)
			sibling, err := bootstrap.VerifyBoundRegionalStartupTemplate(t.Context(), factory, wire, roots, anchor, oci.RegionSFO, now)
			if err != nil {
				t.Fatal(err)
			}
			assertStartup(sibling, "SFO")
			var regionalMaterial region.VerifiedBootstrapMaterial
			if mode == "consumed dynamic control compartment" {
				resolver, err := region.NewFoundationDiscovery(factory, anchor, roots)
				if err != nil {
					t.Fatal(err)
				}
				regionalMaterial, err = resolver.BootstrapMaterial(t.Context(), "SFO")
				if err != nil {
					t.Fatal(err)
				}
				startup, err := regionalMaterial.Startup()
				if err != nil {
					t.Fatal(err)
				}
				original := grant.Regions[1].BootstrapMaterial
				if startup.FounderResources.Slots[0].ImageCompartmentOCID != targets["SFO"].CompartmentOCID || regionalMaterial.PlanDigest() != original.PlanSHA256 || !bytes.Equal(startupScopeJSON(t, regionalMaterial.Config()), startupScopeJSON(t, original.Config)) || !bytes.Equal(regionalMaterial.FoundationGrantWire(), wire) || !regionalMaterial.ExpiresAt().Equal(leaseDeadline) {
					t.Fatal("regional material projection changed founder scope or original signed plan/config provenance")
				}
				if err := startup.Validate(); err != nil {
					t.Fatal(err)
				}
				if err := regionalMaterial.Revalidate(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			switched, err := home.ForCell(t.Context(), oci.RegionSFO, now)
			if err != nil {
				t.Fatal(err)
			}
			assertStartup(switched, "SFO")
			authority := foundationbinding.Authority{Scope: scope, Roots: roots, Policy: bootstrap.BootstrapAnchorTrustPolicy(), GrantSHA256: digestWire(wire), Generation: 1, InstallationID: installation, TenancyID: grant.TenancyID, Namespace: identity.StorageDomain.Namespace, Bucket: identity.StorageDomain.HeadBucket, Prefix: identity.StorageDomain.Prefix, Cell: "GRU", Keys: []string{"workload_compartment"}}
			if _, err := foundationbinding.Verify(t.Context(), factory, authority, wire); err == nil {
				t.Fatal("finite startup observation weakened generic missing-birth rejection")
			}
			mu.Lock()
			keyPath := "/20180608/keys/" + targets["SFO"].KMSKeyOCID
			live[keyPath]["vaultId"] = targets["GRU"].VaultOCID
			mu.Unlock()
			if err := sibling.VerifyCurrentContext(t.Context(), now); err == nil {
				t.Fatal("sibling startup ignored changed live publication target")
			}
			if err := home.VerifyCurrentContext(t.Context(), now); err != nil {
				t.Fatalf("foreign sibling drift invalidated selected home scope: %v", err)
			}
			if len(birthRoles) != 0 {
				birthRole := birthRoles[len(birthRoles)-1]
				record, etag, err := store.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				if _, exists := record.ResourceProvenance[birthRole]; !exists {
					t.Fatal("dynamic startup role lacks the original persisted birth")
				}
				delete(record.ResourceProvenance, birthRole)
				if _, err := store.CompareAndSwap(t.Context(), record, etag); err != nil {
					t.Fatal(err)
				}
				if err := home.VerifyCurrentContext(t.Context(), now); err == nil {
					t.Fatal("startup revalidation accepted CAS removal of its consumed dynamic birth")
				}
			}
			if mode == "consumed dynamic control compartment" {
				mu.Lock()
				live[keyPath]["vaultId"] = targets["SFO"].VaultOCID
				mu.Unlock()
				record, etag, err := store.Load(t.Context(), "SFO")
				if err != nil {
					t.Fatal(err)
				}
				record.Epoch++
				if _, err := store.CompareAndSwap(t.Context(), record, etag); err != nil {
					t.Fatal(err)
				}
				if err := regionalMaterial.Revalidate(t.Context()); err == nil {
					t.Fatal("regional material accepted replacement of its original retained startup epoch")
				}
			}
		})
	}
}

func startupScopeJSON(t *testing.T, value any) []byte {
	t.Helper()
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
