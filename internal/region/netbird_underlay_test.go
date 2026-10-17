package region

import (
	"maps"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func TestNetBirdJournalUnderlayRecipePinsOriginalSeed(t *testing.T) {
	plan := map[string]any{"cell": "GRU", "region": foundationHomeRegion, "network_cidr": "10.251.0.0/24", "subnet_cidr": "10.251.0.0/25"}
	manager := NetBirdManagerProfile{NetworkCIDR: "10.251.1.0/24", PrivateIP: "10.251.1.10"}
	writer := BootstrapMaterialIntent{Config: bootstrapmaterial.Config{Environment: "production", Cell: "gru", Region: foundationHomeRegion, SubnetCIDR: "10.251.0.0/25",
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.10"}, {Name: "controller-b", PrivateIP: "10.251.0.11"}}}, Startup: &bootstrap.StartupTemplate{SeedSlot: "controller-a"}}
	recipe, err := NetBirdJournalUnderlayRecipe(plan, manager, writer)
	if err != nil {
		t.Fatal(err)
	}
	if recipe.WriterPrivateIP != "10.251.0.10" || recipe.ManagerPrivateIP != manager.PrivateIP || recipe.Protocol != "6" || recipe.Port != 443 ||
		recipe.WriterGatewayKey != "netbird_writer_local_peering_gateway" || recipe.ManagerGatewayKey != "netbird_manager_local_peering_gateway" ||
		recipe.WriterRouteTableKey != "route_table" || recipe.ManagerRouteTableKey != "netbird_manager_route" {
		t.Fatalf("recipe differs from exact original GRU endpoints and logical network roles: %+v", recipe)
	}
	for _, name := range []string{"overlap", "outside manager", "reserved manager", "noncanonical manager", "outside writer", "reserved writer", "duplicate seed", "missing seed", "other seed", "other region", "writer subnet drift"} {
		t.Run(name, func(t *testing.T) {
			badPlan, badManager, badWriter := maps.Clone(plan), manager, writer
			startup := *writer.Startup
			badWriter.Startup = &startup
			badWriter.Config.Slots = slices.Clone(writer.Config.Slots)
			switch name {
			case "overlap":
				badManager.NetworkCIDR, badManager.PrivateIP = "10.251.0.0/24", "10.251.0.20"
			case "outside manager":
				badManager.PrivateIP = "10.251.2.10"
			case "reserved manager":
				badManager.PrivateIP = "10.251.1.1"
			case "noncanonical manager":
				badManager.NetworkCIDR = "10.251.1.10/24"
			case "outside writer":
				badWriter.Config.Slots[0].PrivateIP = "10.251.0.130"
			case "reserved writer":
				badWriter.Config.Slots[0].PrivateIP = "10.251.0.127"
			case "duplicate seed":
				badWriter.Config.Slots = append(badWriter.Config.Slots, badWriter.Config.Slots[0])
			case "missing seed":
				badWriter.Config.Slots = badWriter.Config.Slots[1:]
			case "other seed":
				badWriter.Startup.SeedSlot = "controller-b"
			case "other region":
				badPlan["region"] = "us-ashburn-1"
			case "writer subnet drift":
				badWriter.Config.SubnetCIDR = "10.251.0.128/25"
			}
			if _, err := NetBirdJournalUnderlayRecipe(badPlan, badManager, badWriter); err == nil {
				t.Fatal("underlay recipe admitted a substituted endpoint or network")
			}
		})
	}
}
