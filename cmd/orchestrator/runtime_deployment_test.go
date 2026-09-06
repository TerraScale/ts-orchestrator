package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func TestProductionDeploymentBindsCloudflareAndEstate(t *testing.T) {
	valid := func() productionDeploymentFile {
		return productionDeploymentFile{
			Delivery: productionDeliveryFile{MembershipFile: "/etc/terrascale/hosts.json", Cloudflare: productionDeliveryCloudflareFile{AccountID: "account", ZoneID: "zone", SnippetServices: map[string]string{"ts-proxy": "gate"}}},
			Global: &productionGlobalFile{
				Compute: productionGlobalComputeFile{
					EstateFiles:       map[string]string{"gru": "/etc/terrascale/gru.estate", "sfo": "/etc/terrascale/sfo.estate", "fra": "/etc/terrascale/fra.estate"},
					KeyID:             "oci-key",
					PrivateKeyFile:    "/etc/terrascale/oci.key",
					ImageID:           "ocid1.image.oc1.primary",
					FallbackImageID:   "ocid1.image.oc1.fallback",
					MutationJournalKV: "PROVIDER_MUTATIONS",
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
		"other account":    func(f *productionDeploymentFile) { f.Global.Rotation.Edge.AccountID = "foreign" },
		"other route zone": func(f *productionDeploymentFile) { f.Global.KV.ZoneID = "foreign" },
		"other snippet":    func(f *productionDeploymentFile) { f.Global.Rotation.Edge.SnippetName = "foreign" },
		"missing region":   func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "sfo"} },
		"duplicate region": func(f *productionDeploymentFile) { f.Global.Rotation.Regions = []string{"gru", "gru", "sfo"} },
		"other membership": func(f *productionDeploymentFile) { f.Global.HealthFile = "/etc/foreign.json" },
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
