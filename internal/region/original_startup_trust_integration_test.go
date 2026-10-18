package region

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Explicit genesis qualifies the signed SDK primitive. It does not qualify the
// production DiscoveryGenesis constructor or admit a local original actor.
func originalStartupTrustFixture(t *testing.T, rotated bool) (*originalMaterialIAMSDKFixture, bootstrap.VerifiedBootstrapAnchor) {
	t.Helper()
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if rotated {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity := trust.ChainIdentity{DeploymentID: f.prepared.Anchor.DeploymentID, Cell: "gru", Environment: "production"}
		verified, err := trust.VerifyRootChain(f.roots, identity, trust.RootChain{Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		rotation, err := trust.NextRotation(verified, f.root.Public().(ed25519.PublicKey), public)
		if err != nil {
			t.Fatal(err)
		}
		signed := trust.SignedRotation{}
		for _, key := range []ed25519.PrivateKey{f.root, private} {
			envelope, err := trust.SignRotation(rotation, identity, f.now.Add(-time.Minute), f.now.Add(time.Hour), key)
			if err != nil {
				t.Fatal(err)
			}
			signed.Signatures = append(signed.Signatures, envelope)
		}
		wire, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}})
		if err != nil {
			t.Fatal(err)
		}
		f.bundle.RootChainWire = wire
		f.cloud.bundle.RootChainWire = bytes.Clone(wire)
	}
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatalf("retain genuine original producer and IAM: %v", err)
	}
	f.assertMaterialIAM(t)
	// Fixture genesis publishes the already-signed genuine HOME anchor only after
	// asserting that producer completion itself has not published startup authority.
	f.cloud.writeObject("gru-1-head/"+foundationDiscoveryObject, f.bundle.AnchorWire)
	anchor, err := verifyDiscoveryAnchor(f.bundle.AnchorWire, f.roots, f.approval.TenancyID, f.bundle.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	return f, anchor
}

func originalStartupTemplate(t *testing.T, f *originalMaterialIAMSDKFixture, anchor bootstrap.VerifiedBootstrapAnchor, cell oci.Region) bootstrap.VerifiedStartupTemplate {
	t.Helper()
	template, err := bootstrap.VerifyBoundOriginalStartupTemplate(t.Context(), f.factoryFor(), f.bundle.GrantWire, f.roots, anchor, cell, f.now)
	if err != nil || !template.IsVerified() {
		t.Fatalf("bind actual original %s: %v", cell, err)
	}
	return template
}

func TestOriginalStartupTrustSDKAllRegions(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		name := "genesis"
		if rotated {
			name = "rotated-lowercase-home-chain"
		}
		t.Run(name, func(t *testing.T) {
			f, anchor := originalStartupTrustFixture(t, rotated)
			var sdkRequests atomic.Int64
			originalStartupLedgerSDK(t, f, func(*http.Request) { sdkRequests.Add(1) })
			home := originalStartupTemplate(t, f, anchor, oci.RegionGRU)
			record := f.record(t)
			for _, cell := range []oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA} {
				t.Run(string(cell), func(t *testing.T) {
					template := originalStartupTemplate(t, f, anchor, cell)
					selected, err := home.ForCell(t.Context(), cell, f.now)
					if err != nil || !selected.IsVerified() {
						t.Fatalf("select regional template: %v", err)
					}
					if selected.StartupIdentity().Cell != cell || selected.StartupIdentity().DeploymentID != template.StartupIdentity().DeploymentID {
						t.Fatal("ForCell lost the regional signed identity")
					}
					if !bytes.Equal(selected.OriginAnchor().Wire(), anchor.Wire()) || selected.OriginAnchor().Anchor().Cell != oci.RegionGRU {
						t.Fatal("ForCell synthesized a regional origin anchor")
					}
					loaded, err := bootstrap.LoadBoundOriginalStartupTemplate(t.Context(), f.factoryFor(), f.roots, cell, digestSource(f.bundle.GrantWire), digestSource(f.bundle.AnchorWire), f.now)
					if err != nil || !loaded.IsVerified() || loaded.StartupIdentity().Cell != cell || loaded.StartupIdentity().DeploymentID != template.StartupIdentity().DeploymentID {
						t.Fatalf("fixed loader regional identity: %v", err)
					}
					launch, err := template.OriginalLaunch()
					if err != nil {
						t.Fatal(err)
					}
					for _, regional := range record.OriginalFoundationCompartments.Regions {
						if regional.Cell == string(cell) && (launch.InstanceOCID != regional.Actor.Provenance.ResourceID || launch.Create != regional.Actor.Pending.Request) {
							t.Fatal("original launch differs from protected provider receipt")
						}
					}
					request, err := template.OriginalLaunchRequest()
					if err != nil || request.DisplayName == nil {
						t.Fatalf("original request unavailable: %v", err)
					}
					if err := template.VerifyCurrentContext(t.Context(), f.now); err != nil {
						t.Fatalf("current genuine template: %v", err)
					}
					factory := f.factoryFor()
					before := sdkRequests.Load()
					if before == 0 {
						t.Fatal("genuine template did not cross the recorded SDK boundary")
					}
					founder, err := bootstrapstart.VerifySourceFounder(t.Context(), factory, template)
					if !errors.Is(err, bootstrapstart.ErrSourceFounder) || founder.IsVerified() {
						t.Fatalf("genuine original template became an ordinary source founder: %v", err)
					}
					if after := sdkRequests.Load(); after != before {
						t.Fatalf("ordinary founder refusal dispatched %d additional SDK requests", after-before)
					}
				})
			}
		})
	}
}

func TestOriginalStartupTrustSDKMutationsHold(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *originalMaterialIAMSDKFixture)
	}{
		{"retained-birth", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.replaceRecord(t, func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Actor.Provenance.ResourceID = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
			})
		}},
		{"retained-create", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.replaceRecord(t, func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Actor.Pending.Request.RequestDigest = digestSource([]byte("different launch"))
			})
		}},
		{"retained-evidence", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.replaceRecord(t, func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Actor.ReadbackSHA256 = digestSource([]byte("different readback"))
			})
		}},
		{"policy", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			for _, row := range f.rows {
				row["statements"] = []string{"Allow any-user to manage all-resources in tenancy"}
				break
			}
		}},
		{"dynamic-group", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			for _, row := range f.groupRows {
				row["matchingRule"] = "ALL {instance.compartment.id='ocid1.compartment.oc1..foreign'}"
				break
			}
		}},
		{"policy-etag", func(t *testing.T, f *originalMaterialIAMSDKFixture) { f.fault = "readback ETag changed" }},
		{"group-etag", func(t *testing.T, f *originalMaterialIAMSDKFixture) { f.fault = "group ETag changed" }},
		{"home-anchor", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.cloud.writeObject("gru-1-head/"+foundationDiscoveryObject, []byte("{}"))
		}},
		{"home-chain", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.cloud.writeObject("gru-1-head/"+foundationRootChainObject, []byte("{}"))
		}},
		{"home-grant", func(t *testing.T, f *originalMaterialIAMSDKFixture) {
			f.cloud.writeObject("gru-1-head/"+f.approval.HomeStorageDomain.Prefix+"/"+foundationGrantObject, []byte("{}"))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f, anchor := originalStartupTrustFixture(t, false)
			template := originalStartupTemplate(t, f, anchor, oci.RegionGRU)
			test.mutate(t, f)
			if err := template.VerifyCurrentContext(t.Context(), f.now); err == nil {
				t.Fatal("changed live producer/IAM/identity retained startup authority")
			}
			loaded, err := bootstrap.LoadBoundOriginalStartupTemplate(t.Context(), f.factoryFor(), f.roots, oci.RegionGRU, digestSource(f.bundle.GrantWire), digestSource(f.bundle.AnchorWire), f.now)
			if err == nil || loaded.IsVerified() {
				t.Fatal("fixed loader accepted changed live original evidence")
			}
		})
	}
}

func TestOriginalStartupTrustSDKRejectsWrongTrustAndExpiry(t *testing.T) {
	f, anchor := originalStartupTrustFixture(t, false)
	productionRoots, err := trust.DiscoveryGenesis()
	if err != nil {
		t.Fatal(err)
	}
	for _, roots := range []trust.Keyring{nil, productionRoots} {
		template, err := bootstrap.VerifyBoundOriginalStartupTemplate(t.Context(), f.factoryFor(), f.bundle.GrantWire, roots, anchor, oci.RegionGRU, f.now)
		if err == nil || template.IsVerified() {
			t.Fatal("unrelated production/genesis roots accepted fixture original authority")
		}
	}
	template := originalStartupTemplate(t, f, anchor, oci.RegionGRU)
	if err := template.VerifyCurrentContext(t.Context(), template.ExpiresAt().Add(time.Second)); err == nil {
		t.Fatal("expired original template stayed current")
	}
}
