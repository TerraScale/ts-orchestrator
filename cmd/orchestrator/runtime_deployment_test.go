package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func TestProductionDeploymentBindsCloudflareAndEstate(t *testing.T) {
	valid := func() productionDeploymentFile {
		return productionDeploymentFile{
			Delivery: productionDeliveryFile{MembershipFile: "/etc/terrascale/hosts.json", Cloudflare: productionDeliveryCloudflareFile{AccountID: "account", ZoneID: "zone", SnippetServices: map[string]string{"ts-proxy": "gate"}}},
			Global: &productionGlobalFile{
				Database:    productionDatabaseFileConfig{DeletionClaim: databaseDeletionClaimConfig{Endpoint: "https://app.terrascale.tech/api/internal/lifecycle/claim-delete", ServiceKeyFile: "/etc/terrascale/secrets/lifecycle-service-key"}},
				WriteBudget: productionWriteBudgetFile{PolicyFile: "/etc/terrascale/billing/write-budget.json", StateKey: "billing-write-budget", Placement: "database-placement"},
				Compute: productionGlobalComputeFile{
					Enrollment: &productionEnrollmentFile{BrokerIDs: []string{"broker-gru", "broker-sfo", "broker-fra"}, SignerFile: "/etc/terrascale/enrollment.key", PublicKeyFile: "/etc/terrascale/enrollment.pub", Templates: map[string]enrollment.Template{"gru": enrollment.Template{}, "sfo": enrollment.Template{}, "fra": enrollment.Template{}},
					EstateFiles:       map[string]string{"gru": "/etc/terrascale/gru.estate", "sfo": "/etc/terrascale/sfo.estate", "fra": "/etc/terrascale/fra.estate"},
					KeyID:             "oci-key",
					PrivateKeyFile:    "/etc/terrascale/oci.key",
					ImageID:           "ocid1.image.oc1.primary",
					FallbackImageID:   "ocid1.image.oc1.fallback",
					MutationJournalKV: "PROVIDER_MUTATIONS",
					ReleaseVersion:    "v1.2.3", ArtifactURL: "https://releases.example/ts-node", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleasePublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HostFiles: map[string]string{"/etc/terrascale/ts-node.json": "{}", "/var/lib/terrascale/ts-node/manifest.json": "{}"}, Artifacts: map[string]productionComputeArtifactFile{"arm64": {Version: "v1", URL: "https://releases.example/arm", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "amd64": {Version: "v1", URL: "https://releases.example/amd", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", PublicKey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
				},
				HealthFile: "/etc/terrascale/hosts.json",
				KV:         productionKVFile{AccountID: "account", ZoneID: "zone"},
				Rotation:   productionRotationFile{Regions: []string{"fra", "gru", "sfo"}, Edge: productionRotationEdgeFile{AccountID: "account", ZoneID: "zone", TemplateService: "ts-proxy", SnippetName: "gate"}},
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
		"other route zone":                func(f *productionDeploymentFile) { f.Global.KV.ZoneID = "foreign" },
		"other snippet":                   func(f *productionDeploymentFile) { f.Global.Rotation.Edge.SnippetName = "foreign" },
		"missing region":                  func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "sfo"} },
		"duplicate region":                func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "gru", "sfo"} },
		"other membership":                func(f *productionDeploymentFile) { f.Global.HealthFile = "/etc/foreign.json" },
		"missing enrollment":               func(f *productionDeploymentFile) { f.Global.Compute.Enrollment = nil },
		"missing enrollment region":        func(f *productionDeploymentFile) { delete(f.Global.Compute.Enrollment.Templates, "fra") },
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
