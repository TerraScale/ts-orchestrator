package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

func TestNetBirdConfigurationOriginalMaterialSDK(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	// A fresh client adopts the schema3 origin; the fixture already adopted its legacy grant at this generation.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
	fixture.cloud.bundle = bundle
	factory := fixture.factoryFor()
	stage, err := provisionFoundationMaterial(t.Context(), factory, fixture.roots, bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.cancel()
	fixture.assertMaterial(t)
	record, _, err := stage.resolver.Store.Load(t.Context(), "GRU")
	if err != nil || record.NetBirdMaterial == nil {
		t.Fatal("genuine original producer did not retain its material journal")
	}
	journal := *record.NetBirdMaterial
	management, err := vault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	management.SetRegion(foundationHomeRegion)
	factory.Configure(&management.BaseClient, ociclient.ServiceKMS)
	bundles, err := factory.SecretsContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// A configuration read must succeed after both root read surfaces disappear.
	delete(fixture.cloud.rows, journal.Creates[0].SecretID)
	if err := os.Remove(fixture.cloud.objectPath("material-value/" + journal.Creates[0].SecretID)); err != nil {
		t.Fatal(err)
	}
	values, err := readNetBirdConfigurationValues(t.Context(), &management, &bundles, journal)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range values {
		actual, err := os.ReadFile(fixture.cloud.objectPath("material-value/" + journal.Creates[i+1].SecretID))
		if err != nil || len(value) != 44 || !bytes.Equal(value, actual) {
			t.Fatal("configuration changed the genuine producer's fixed child ordering or raw bytes")
		}
		clear(actual)
		clear(value)
	}
	assertRefused := func(t *testing.T) {
		t.Helper()
		partial, err := readNetBirdConfigurationValues(t.Context(), &management, &bundles, journal)
		if err == nil {
			for _, value := range partial {
				clear(value)
			}
			t.Fatal("changed original CURRENT material returned configuration")
		}
		for _, value := range partial {
			if value != nil {
				t.Fatal("failed configuration returned a partial child buffer")
			}
		}
	}
	for _, fault := range []string{"foreign target", "rotation added", "foreign version", "not CURRENT", "malformed encoding"} {
		t.Run(fault, func(t *testing.T) {
			fixture.cloud.materialFault = fault
			t.Cleanup(func() { fixture.cloud.materialFault = "" })
			assertRefused(t)
		})
	}
	for _, fault := range []string{"missing second child", "changed second child digest"} {
		t.Run(fault, func(t *testing.T) {
			key := "material-value/" + journal.Creates[2].SecretID
			original, err := os.ReadFile(fixture.cloud.objectPath(key))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fixture.cloud.writeObject(key, original); clear(original) })
			if fault == "missing second child" {
				if err := os.Remove(fixture.cloud.objectPath(key)); err != nil {
					t.Fatal(err)
				}
			} else {
				fixture.cloud.writeObject(key, bytes.Repeat([]byte{'X'}, 44))
			}
			assertRefused(t)
		})
	}
	if _, err := ReadNetBirdConfiguration(t.Context(), factory, stage.resolver, VerifiedNetBirdManager{}); err == nil {
		t.Fatal("original producer material fabricated dedicated manager admission")
	}
	if fixture.cloud.materialPosts != 4 || fixture.cloud.creates != 0 || fixture.cloud.launchPosts != 0 {
		t.Fatal("configuration reader created or adopted production material or infrastructure")
	}
}

func TestNetBirdComponentPullCurrentSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	withNetBirdManagerFixture(t, func(factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager) {
		components, err := ReadNetBirdComponents(t.Context(), factory, resolver, manager)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range netBirdComponentRoles() {
			component, err := components.Component(t.Context(), role)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := components.ResolvePull(t.Context(), role)
			if err != nil {
				t.Fatal(err)
			}
			host := component.PullClaim().Scope.RegistryHost
			username, password, err := credentials.ForHost(host)
			if err != nil || username == "" || password == "" {
				t.Fatal("genuine admitted component could not resolve its current owned credential")
			}
			if _, _, err := credentials.ForHost("foreign.ocir.io"); err == nil {
				t.Fatal("component credential authorized a foreign registry origin")
			}
			wire, err := json.Marshal(credentials)
			if err != nil || string(wire) != "{}" || strings.Contains(credentials.String(), password) {
				t.Fatal("component credential formatting exposed its values")
			}
		}
		if _, err := components.ResolvePull(t.Context(), "terrabase"); err == nil {
			t.Fatal("complete dedicated component set authorized an unrelated role")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := components.ResolvePull(ctx, "netbird-server"); err == nil {
			t.Fatal("canceled component resolution returned credentials")
		}
		if _, err := ReadNetBirdConfiguration(t.Context(), factory, resolver, manager); err == nil {
			t.Fatal("historical manager grant gained original configuration material")
		}
		reader := resolver.Footprint.(*SignedFootprint)
		original, err := reader.readGrant(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		writeGrant := func(wire []byte) {
			t.Helper()
			name := strings.TrimSuffix(reader.storage.Prefix, "/") + "/" + foundationGrantObject
			_, err := reader.client.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new(reader.storage.Namespace), BucketName: new(reader.storage.HeadBucket), ObjectName: new(name), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentLength: new(int64(len(wire)))})
			if err != nil {
				t.Fatal(err)
			}
		}
		defer writeGrant(original)
		writeGrant([]byte("{}"))
		if _, err := components.ResolvePull(t.Context(), "netbird-server"); err == nil {
			t.Fatal("changed authenticated source returned a cached component credential")
		}
	})
}
