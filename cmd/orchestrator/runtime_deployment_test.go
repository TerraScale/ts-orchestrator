package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentityrotation"
)

func TestProductionDeploymentBindsCloudflareAndEstate(t *testing.T) {
	const cloudflareAccountID = "0123456789abcdef0123456789abcdef"

	valid := func() productionDeploymentFile {
		return productionDeploymentFile{
			Delivery: productionDeliveryFile{MembershipFile: "/etc/terrascale/hosts.json", Cloudflare: productionDeliveryCloudflareFile{AccountID: cloudflareAccountID, ZoneID: "zone", SnippetServices: map[string]string{"ts-proxy": "gate"}}},
			Global: &productionGlobalFile{
				ServiceIdentity: serviceidentityrotation.FileConfig{Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..fixture", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.fixture", KeyID: "ocid1.key.oc1.sa-saopaulo-1.fixture", CloudflareAccountID: cloudflareAccountID, CloudflareTokenFile: "/etc/terrascale/cloudflare-token", DashboardScript: "dashboard", CertificateFile: "/etc/terrascale/identity-cert", PrivateKeyFile: "/etc/terrascale/identity-key", TrustBundleFile: "/etc/terrascale/identity-trust", Members: []serviceidentityrotation.RemoteMemberEndpoint{{NodeID: "node-gru-1", URL: "https://10.0.0.1:9443"}}, PeriodSeconds: 86400, OverlapSeconds: 300},
				Database:        productionDatabaseFileConfig{DeletionClaim: databaseDeletionClaimConfig{Endpoint: "https://app.terrascale.tech/api/internal/lifecycle/claim-delete", ServiceKeyFile: "/etc/terrascale/secrets/lifecycle-service-key"}},
				WriteBudget:     productionWriteBudgetFile{PolicyFile: "/etc/terrascale/billing/write-budget.json", StateKey: "billing-write-budget", Placement: "database-placement"},
				Compute: productionGlobalComputeFile{
					Enrollment:        &productionEnrollmentFile{BrokerIDs: []string{"broker-gru", "broker-sfo", "broker-fra"}, SignerFile: "/etc/terrascale/enrollment.key", PublicKeyFile: "/etc/terrascale/enrollment.pub", Templates: map[string]enrollment.Template{"gru": enrollment.Template{}, "sfo": enrollment.Template{}, "fra": enrollment.Template{}}},
					EstateFiles:       map[string]string{"gru": "/etc/terrascale/gru.estate", "sfo": "/etc/terrascale/sfo.estate", "fra": "/etc/terrascale/fra.estate"},
					KeyID:             "oci-key",
					PrivateKeyFile:    "/etc/terrascale/oci.key",
					ImageID:           "ocid1.image.oc1.primary",
					FallbackImageID:   "ocid1.image.oc1.fallback",
					MutationJournalKV: "PROVIDER_MUTATIONS",
					ReleaseVersion:    "v1.2.3", ArtifactURL: "https://releases.example/ts-node", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleasePublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HostFiles: map[string]string{"/etc/terrascale/ts-node.json": "{}", "/var/lib/terrascale/ts-node/manifest.json": "{}"}, Artifacts: map[string]productionComputeArtifactFile{"arm64": {Version: "v1", URL: "https://releases.example/arm", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "amd64": {Version: "v1", URL: "https://releases.example/amd", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", PublicKey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
				},
				HealthFile: "/etc/terrascale/hosts.json",
				KV:         productionKVFile{AccountID: cloudflareAccountID, ZoneID: "zone"},
				Rotation:   productionRotationFile{Regions: []string{"fra", "gru", "sfo"}, Edge: productionRotationEdgeFile{AccountID: cloudflareAccountID, ZoneID: "zone", TemplateService: "ts-proxy", SnippetName: "gate"}},
			},
		}
	}
	if err := valid().validateGlobalRelationships(estate.Default()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*productionDeploymentFile){
		"missing deletion claim endpoint": func(f *productionDeploymentFile) { f.Global.Database.DeletionClaim.Endpoint = "" },
		"missing deletion claim key":      func(f *productionDeploymentFile) { f.Global.Database.DeletionClaim.ServiceKeyFile = "" },
		"other account":                   func(f *productionDeploymentFile) { f.Global.Rotation.Edge.AccountID = "foreign" },
		"other service identity account": func(f *productionDeploymentFile) {
			f.Global.ServiceIdentity.CloudflareAccountID = "fedcba9876543210fedcba9876543210"
		},
		"other route zone":          func(f *productionDeploymentFile) { f.Global.KV.ZoneID = "foreign" },
		"other snippet":             func(f *productionDeploymentFile) { f.Global.Rotation.Edge.SnippetName = "foreign" },
		"missing region":            func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "sfo"} },
		"duplicate region":          func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "gru", "sfo"} },
		"other membership":          func(f *productionDeploymentFile) { f.Global.HealthFile = "/etc/foreign.json" },
		"missing service identity":  func(f *productionDeploymentFile) { f.Global.ServiceIdentity = serviceidentityrotation.FileConfig{} },
		"invalid service identity":  func(f *productionDeploymentFile) { f.Global.ServiceIdentity.PeriodSeconds = 0 },
		"missing enrollment":        func(f *productionDeploymentFile) { f.Global.Compute.Enrollment = nil },
		"missing enrollment region": func(f *productionDeploymentFile) { delete(f.Global.Compute.Enrollment.Templates, "fra") },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid()
			mutate(&config)
			if err := config.validateGlobalRelationships(estate.Default()); err == nil {
				t.Fatal("inconsistent deployment accepted")
			}
		})
	}
}
